use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use arti_client::DataStream;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use tor_hsservice::RunningOnionService;
use zeroize::Zeroizing;

use lycta_core::group::{self, SenderKey};
use lycta_core::handshake::{self, SessionId};
use lycta_core::hybrid::x25519_pair;
use lycta_core::identity::Identity;
use lycta_core::identity::{short_fingerprint, IdentityPublic, Invite};
use lycta_core::primitives::random_bytes;
use lycta_core::ratchet::RatchetMessage;
use lycta_core::vault::{
    self, deposit_id, set_reaction, Attachment, AttachmentKind, Direction, Group, HistoryEntry,
    HostedMailbox, IncomingFile, MyMailbox, OpEffect, Origin, OutboxItem, PeerMailbox, Session,
    SlotKind, State, StoredFile, VaultKey, MAX_HOSTED_FRAMES, MAX_STORED_BYTES,
};
use lycta_core::wire::{
    check_frame_len, decode_content, decode_frame, decode_op, decode_raw_frame, encode_content,
    encode_frame, encode_op, Content, DeviceMsg, Frame, MsgOp, FILE_CHUNK, MAX_BATCH, MAX_FILE,
    MAX_GROUP_MEMBERS,
};

fn sanitize_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .take(lycta_core::wire::MAX_FILE_NAME)
        .collect();
    let clean = clean.trim_start_matches('.').trim().to_string();
    if clean.is_empty() {
        "file".into()
    } else {
        clean
    }
}

use crate::tor::{self, Client, Incoming};

const IO_TIMEOUT: Duration = Duration::from_secs(120);

const MAILBOX_FETCH_MEAN_SECS: f64 = 90.0;

#[derive(Debug, Clone)]
pub enum Event {
    Message {
        contact: u32,
        text: String,
        accepted: bool,
    },
    NewContact {
        contact: u32,
        fingerprint: String,
    },
    Delivered {
        contact: u32,
    },
    Deposited {
        contact: u32,
    },
    FileReceived {
        contact: u32,
        file: u32,
        name: String,
        size: usize,
    },
    GroupMessage {
        group: u32,
        author: String,
        text: String,
    },

    Changed {
        contact: u32,
    },
    GroupChanged {
        group: u32,
    },

    MirrorMessage {
        mirror: u32,
        text: String,
    },
    MirrorChanged {
        mirror: u32,
    },
    Info(String),
    Error(String),
}

#[derive(Serialize, Deserialize)]
struct ReturnAddr {
    onion_key: [u8; 32],
    auth_secret: [u8; 32],
}

enum Followup {
    Discovery([u8; 32], [u8; 32]),
    Send(u32, Content),
    SendToAll(Content),
    StopSlot(u32),

    DeviceDo(u32, MsgOp),
}

struct Inner {
    state: State,
    vk: VaultKey,
    path: PathBuf,
}

impl Inner {
    fn persist(&self) -> Result<()> {
        vault::save(&self.path, &self.state, &self.vk)?;
        Ok(())
    }
}

pub struct Node {
    inner: Mutex<Inner>,
    client: Client,
    events: UnboundedSender<Event>,
    services: Mutex<HashMap<u32, Arc<RunningOnionService>>>,
    cover_tasks: Mutex<HashSet<u32>>,

    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    stopped: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Node")
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn poisson_delay(mean: f64) -> Duration {
    let u: f64 = rand::thread_rng().gen_range(f64::EPSILON..1.0);
    Duration::from_secs_f64((-mean * u.ln()).clamp(1.0, mean * 8.0))
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, f: &Frame) -> Result<()> {
    let b = encode_frame(f)?;
    write_raw(s, &b).await
}

async fn write_raw<S: AsyncWrite + Unpin>(s: &mut S, bytes: &[u8]) -> Result<()> {
    timeout(IO_TIMEOUT, async {
        s.write_all(bytes).await?;
        s.flush().await
    })
    .await??;
    Ok(())
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Result<Option<(Frame, Vec<u8>)>> {
    let mut len = [0u8; 4];
    match timeout(IO_TIMEOUT, s.read_exact(&mut len)).await? {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = check_frame_len(u32::from_be_bytes(len))?;
    let mut buf = vec![0u8; n];
    timeout(IO_TIMEOUT, s.read_exact(&mut buf)).await??;
    let frame = decode_frame(&buf)?;
    let mut raw = len.to_vec();
    raw.extend_from_slice(&buf);
    Ok(Some((frame, raw)))
}

async fn expect_frame<S: AsyncRead + Unpin>(s: &mut S) -> Result<Frame> {
    read_frame(s)
        .await?
        .map(|(f, _)| f)
        .ok_or_else(|| anyhow!("connection closed by peer"))
}

impl Node {
    pub fn new(
        state: State,
        vk: VaultKey,
        path: PathBuf,
        client: Client,
        events: UnboundedSender<Event>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner { state, vk, path }),
            client,
            events,
            services: Mutex::new(HashMap::new()),
            cover_tasks: Mutex::new(HashSet::new()),
            tasks: Mutex::new(Vec::new()),
            stopped: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn spawn_bg<F>(&self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if self.stopped.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let handle = tokio::spawn(fut).abort_handle();
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        tasks.retain(|t| !t.is_finished());
        tasks.push(handle);
    }

    pub fn shutdown(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.save();
        for t in self
            .tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
        {
            t.abort();
        }
        self.services
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        self.cover_tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    pub fn my_public(&self) -> IdentityPublic {
        self.with(|i| i.state.identity.public())
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn data_dir(&self) -> PathBuf {
        self.with(|i| i.path.parent().map(PathBuf::from).unwrap_or_default())
    }

    pub fn state<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        self.with(|i| f(&mut i.state))
    }

    pub fn save(&self) -> Result<()> {
        self.with(|i| i.persist())
    }

    pub fn start(self: &Arc<Self>) -> Result<()> {
        let (slots, discovery, contacts) = self.with(|i| {
            let slots: Vec<u32> = i.state.slots.iter().map(|s| s.id).collect();
            let mut disc = Vec::new();
            for c in &i.state.contacts {
                if let (Some(o), Some(a)) = (c.peer_onion, c.peer_auth) {
                    disc.push((o, a));
                }
                if let Some(m) = &c.mailbox {
                    disc.push((m.onion_key, m.auth_secret));
                }
            }
            if let Some(m) = &i.state.my_mailbox {
                disc.push((m.onion_key, m.auth_secret));
            }
            let contacts: Vec<u32> = i.state.contacts.iter().map(|c| c.local_id).collect();
            (slots, disc, contacts)
        });
        for (o, a) in discovery {
            let _ = tor::add_discovery_key(&self.client, &o, &a);
        }
        for s in slots {
            if let Err(e) = self.launch_slot(s) {
                self.emit(Event::Error(format!("onion service {s}: {e}")));
            }
        }
        for c in contacts {
            self.ensure_cover_task(c);
        }
        self.spawn_bg(Arc::clone(self).retry_loop());
        self.spawn_bg(Arc::clone(self).mailbox_fetch_loop());
        self.spawn_bg(Arc::clone(self).expiry_loop());
        Ok(())
    }

    fn launch_slot(self: &Arc<Self>, slot_id: u32) -> Result<[u8; 32]> {
        let (seed, auth) = self
            .with(|i| {
                i.state
                    .slot(slot_id)
                    .map(|s| (Zeroizing::new(s.hs_seed), s.authorized_client))
            })
            .ok_or_else(|| anyhow!("unknown service"))?;
        let (svc, onion_key, incoming) = tor::launch_slot(&self.client, slot_id, &seed, &auth)?;
        self.with(|i| -> Result<()> {
            if let Some(s) = i.state.slot(slot_id) {
                s.onion_key = Some(onion_key);
            }
            i.persist()
        })?;
        self.services
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(slot_id, svc);
        self.spawn_bg(Arc::clone(self).accept_loop(slot_id, incoming));
        Ok(onion_key)
    }

    fn stop_slot(&self, slot_id: u32) {
        self.services
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&slot_id);
    }

    async fn accept_loop(self: Arc<Self>, slot_id: u32, mut incoming: Incoming) {
        while let Some(req) = incoming.next().await {
            if !self
                .services
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(&slot_id)
            {
                break;
            }
            let me = Arc::clone(&self);
            self.spawn_bg(async move {
                if let Ok(mut s) = tor::accept(req).await {
                    let _ = me.serve(slot_id, &mut s).await;
                }
            });
        }
    }

    async fn serve(self: &Arc<Self>, slot_id: u32, s: &mut DataStream) -> Result<()> {
        let kind = self
            .with(|i| i.state.slot(slot_id).map(|s| s.kind))
            .ok_or_else(|| anyhow!("unknown service"))?;
        while let Some((frame, raw)) = read_frame(s).await? {
            let reply = match (kind, frame) {
                (SlotKind::Mailbox(_), Frame::Deposit { deposit_id, frame }) => self
                    .on_deposit(slot_id, &deposit_id, frame)
                    .unwrap_or(Frame::Nack),
                (SlotKind::Mailbox(_), Frame::Fetch { fetch_key }) => {
                    self.on_fetch(slot_id, &fetch_key).unwrap_or(Frame::Nack)
                }
                (SlotKind::Mailbox(_), _) => Frame::Nack,
                (_, Frame::GetBundle) => Frame::Bundle(self.my_public().to_bytes()),
                (_, Frame::Hs1(m)) => match self.on_hs1(slot_id, &m) {
                    Ok((f, follow)) => {
                        write_frame(s, &f).await?;
                        self.run_followups(follow).await;
                        continue;
                    }
                    Err(_) => Frame::Nack,
                },
                (_, Frame::Msg { session_id, msg }) => {
                    match self.on_msg(Some(slot_id), &session_id, &msg, &raw) {
                        Ok(follow) => {
                            write_frame(s, &Frame::Ack).await?;
                            self.run_followups(follow).await;
                            continue;
                        }
                        Err(_) => Frame::Nack,
                    }
                }
                _ => break,
            };
            write_frame(s, &reply).await?;
        }
        Ok(())
    }

    fn on_hs1(
        self: &Arc<Self>,
        slot_id: u32,
        m: &handshake::Hs1,
    ) -> Result<(Frame, Vec<Followup>)> {
        let identity = self.with(|i| i.state.identity.clone());
        let (hs2, est) = handshake::respond(&identity, m)?;
        let fp = est.peer.fingerprint();
        let ret: Option<ReturnAddr> = bincode::deserialize(&est.peer_extra).ok();
        let peer = est.peer.clone();
        let mut follow = Vec::new();

        let (id, is_new) = self.with(|i| -> Result<(u32, bool)> {
            let kind = i
                .state
                .slot(slot_id)
                .map(|s| s.kind)
                .ok_or_else(|| anyhow!("service"))?;
            let existing = i
                .state
                .contacts
                .iter()
                .find(|c| c.public.fingerprint() == fp)
                .map(|c| c.local_id);
            let id = match (kind, existing) {
                (SlotKind::Invite, None) => i.state.add_contact(peer, Origin::Request),
                (SlotKind::Invite, Some(_)) => bail!("already known"),

                (SlotKind::Contact(c), Some(e)) if c == e => e,
                _ => bail!("refused"),
            };
            let c = i.state.contact_by_local(id).expect("present");
            if c.blocked {
                bail!("blocked");
            }
            c.session = Some(Session {
                id: est.session_id,
                ratchet: est.ratchet.clone(),
            });
            c.my_slot = Some(slot_id);
            if let Some(r) = &ret {
                c.peer_onion = Some(r.onion_key);
                c.peer_auth = Some(r.auth_secret);
                follow.push(Followup::Discovery(r.onion_key, r.auth_secret));
            }
            if let Some(s) = i.state.slot(slot_id) {
                s.kind = SlotKind::Contact(id);
                s.invite_auth_secret = None;
            }
            i.persist()?;
            Ok((id, kind == SlotKind::Invite))
        })?;
        if is_new {
            self.emit(Event::NewContact {
                contact: id,
                fingerprint: short_fingerprint(&fp),
            });
            self.ensure_cover_task(id);
            if let Some(info) = self.mailbox_info_content() {
                follow.push(Followup::Send(id, info));
            }
        }
        Ok((Frame::Hs2(hs2), follow))
    }

    fn on_msg(
        &self,
        via_slot: Option<u32>,
        sid: &SessionId,
        msg: &RatchetMessage,
        raw: &[u8],
    ) -> Result<Vec<Followup>> {
        let (ev, follow) = self.with(|i| -> Result<(Option<Event>, Vec<Followup>)> {
            if i.state.is_seen(raw) {
                return Ok((None, Vec::new()));
            }
            let keep = i.state.keep_history;
            let pending_host = i.state.mailbox_pending_host;
            let c = i
                .state
                .contact_by_session(sid)
                .ok_or_else(|| anyhow!("unknown"))?;
            if let (Some(v), Some(mine)) = (via_slot, c.my_slot) {
                if v != mine {
                    bail!("wrong service");
                }
            }
            let session = c.session.as_mut().expect("found by session");
            let pt = session.ratchet.decrypt(msg, sid)?;
            let content = decode_content(&pt)?;
            let (blocked, accepted, local) = (c.blocked, c.accepted, c.local_id);
            let mut follow = Vec::new();
            let mut ev = None;
            if !blocked {
                match content {
                    Content::Hello | Content::Cover => {}
                    Content::Text(text) => {
                        if keep {
                            let expires_at = c.timer.map(|t| now_secs() + t as u64);
                            c.push_history(HistoryEntry::new(
                                Direction::In,
                                text.clone(),
                                true,
                                expires_at,
                            ));
                        }
                        ev = Some(Event::Message {
                            contact: local,
                            text,
                            accepted,
                        });
                    }
                    Content::Op(op) => {
                        let effect = c.apply_peer_op(&op, keep);
                        let (is_device, fp, ttl) =
                            (c.own_device, c.public.fingerprint(), c.timer.unwrap_or(0));

                        if effect != OpEffect::Ignored && !is_device {
                            for d in i.state.devices() {
                                follow.push(Followup::Send(
                                    d,
                                    Content::Device(DeviceMsg::Sync {
                                        fp,
                                        out: false,
                                        ttl,
                                        op: op.clone(),
                                    }),
                                ));
                            }
                        }
                        match (effect, op) {
                            (OpEffect::Added, MsgOp::Message { text, .. }) => {
                                ev = Some(Event::Message {
                                    contact: local,
                                    text,
                                    accepted,
                                });
                            }
                            (OpEffect::Changed, _) => ev = Some(Event::Changed { contact: local }),
                            _ => {}
                        }
                    }
                    Content::Device(msg) => {
                        let is_device = c.own_device;
                        match msg {
                            DeviceMsg::Link => {
                                if !is_device && !i.state.device_requests.contains(&local) {
                                    i.state.device_requests.push(local);
                                }
                                ev = Some(Event::Info(format!(
                                    "#{local} asks to be linked as one of your devices"
                                )));
                            }
                            DeviceMsg::Accept => {
                                if i.state.primary_pending == Some(local) {
                                    i.state.primary_pending = None;
                                    i.state.primary = Some(local);
                                    ev = Some(Event::Info(format!(
                                        "This device is now linked to #{local}"
                                    )));
                                }
                            }
                            DeviceMsg::Unlink => {
                                if is_device || i.state.primary == Some(local) {
                                    i.state.unlink_device(local);
                                    ev = Some(Event::Info(format!(
                                        "#{local} ended the device link"
                                    )));
                                }
                            }
                            DeviceMsg::Peer { fp, note } => {
                                if i.state.primary == Some(local) {
                                    let m = i.state.mirror_for(&fp);
                                    m.note = note;
                                    ev = Some(Event::MirrorChanged { mirror: m.local_id });
                                }
                            }
                            DeviceMsg::Sync { fp, out, ttl, op } => {
                                if i.state.primary == Some(local) {
                                    let m = i.state.mirror_for(&fp);
                                    let mirror = m.local_id;
                                    ev = match (m.apply(out, &op, ttl, keep), op) {
                                        (OpEffect::Ignored, _) => None,
                                        (OpEffect::Added, MsgOp::Message { text, .. }) if !out => {
                                            Some(Event::MirrorMessage { mirror, text })
                                        }
                                        _ => Some(Event::MirrorChanged { mirror }),
                                    };
                                }
                            }
                            DeviceMsg::Send { fp, op } => {
                                if is_device {
                                    let target = i
                                        .state
                                        .contacts
                                        .iter()
                                        .find(|x| {
                                            x.public.fingerprint() == fp
                                                && !x.own_device
                                                && !x.blocked
                                        })
                                        .map(|x| x.local_id);
                                    if let Some(t) = target {
                                        follow.push(Followup::DeviceDo(t, op));
                                    }
                                }
                            }
                        }
                    }
                    Content::Timer(t) => {
                        c.timer = (t > 0).then_some(t);
                        ev = Some(Event::Info(match c.timer {
                            Some(t) => format!("#{local} turned on disappearing messages ({t} s)"),
                            None => format!("#{local} turned off disappearing messages"),
                        }));
                    }
                    Content::MailboxInfo {
                        onion_key,
                        auth_secret,
                        deposit_id,
                    } => {
                        c.mailbox = Some(PeerMailbox {
                            onion_key,
                            auth_secret,
                            deposit_id,
                        });
                        follow.push(Followup::Discovery(onion_key, auth_secret));

                        if let Some(h) = i.state.hosted.iter_mut().find(|h| h.owner == local) {
                            h.deposit_id = Some(deposit_id);
                        }
                    }
                    Content::MailboxRevoke => {
                        c.mailbox = None;
                        let slots: Vec<u32> = i
                            .state
                            .hosted
                            .iter()
                            .filter(|h| h.owner == local)
                            .map(|h| h.slot)
                            .collect();
                        i.state.hosted.retain(|h| h.owner != local);
                        i.state.slots.retain(|s| !slots.contains(&s.id));
                        follow.extend(slots.into_iter().map(Followup::StopSlot));
                    }
                    Content::MailboxRequest => {
                        if !i.state.mailbox_requests.contains(&local) {
                            i.state.mailbox_requests.push(local);
                        }
                        ev = Some(Event::Info(format!(
                            "#{local} asks you to host their mailbox"
                        )));
                    }
                    Content::FileStart {
                        file_id,
                        name,
                        size,
                        chunks,
                        hash,
                    } => {
                        let expected = (size as usize).div_ceil(FILE_CHUNK) as u32;
                        if size as usize <= MAX_FILE
                            && chunks == expected
                            && i.state.stored_bytes() + size as usize <= MAX_STORED_BYTES
                        {
                            let name: String = sanitize_name(&name);
                            i.state
                                .incoming_files
                                .retain(|f| !(f.contact == local && f.file_id == file_id));
                            i.state.incoming_files.push(IncomingFile {
                                contact: local,
                                file_id,
                                name: name.clone(),
                                size,
                                hash,
                                chunks: vec![None; chunks as usize],
                            });
                            ev = Some(Event::Info(format!("#{local} is sending {name}")));
                        }
                    }
                    Content::FileChunk {
                        file_id,
                        index,
                        data,
                    } => {
                        if let Some(pos) = i
                            .state
                            .incoming_files
                            .iter()
                            .position(|f| f.contact == local && f.file_id == file_id)
                        {
                            let f = &mut i.state.incoming_files[pos];
                            if let Some(slot) = f.chunks.get_mut(index as usize) {
                                *slot = Some(data);
                            }
                            if f.received() == f.chunks.len() {
                                let f = i.state.incoming_files.remove(pos);
                                let data: Vec<u8> =
                                    f.chunks.iter().flatten().flatten().copied().collect();
                                let ok = data.len() as u64 == f.size
                                    && lycta_core::primitives::sha3_256(&[
                                        b"LyctaCrypt/file",
                                        &data,
                                    ]) == f.hash;
                                if ok {
                                    let id = i.state.next_file_id;
                                    i.state.next_file_id += 1;
                                    let size = data.len();
                                    i.state.files.push(StoredFile {
                                        local_id: id,
                                        contact: local,
                                        name: f.name.clone(),
                                        data,
                                    });
                                    if keep {
                                        if let Some(c) = i.state.contact_by_local(local) {
                                            let expires_at = c.timer.map(|t| now_secs() + t as u64);
                                            let mut e = HistoryEntry::new(
                                                Direction::In,
                                                format!("[file] {}", f.name),
                                                true,
                                                expires_at,
                                            );
                                            e.id = random_bytes();
                                            e.attachment = Some(Attachment {
                                                file: id,
                                                name: f.name.clone(),
                                                kind: AttachmentKind::from_name(&f.name),
                                            });
                                            c.push_history(e);
                                        }
                                    }
                                    ev = Some(Event::FileReceived {
                                        contact: local,
                                        file: id,
                                        name: f.name.clone(),
                                        size,
                                    });
                                } else {
                                    ev = Some(Event::Error(format!(
                                        "Corrupted file from #{local} rejected"
                                    )));
                                }
                            }
                        }
                    }
                    Content::GroupCreate { group_id, members } => {
                        let hub_public = c.public.clone();
                        if let Some(g) = i.state.group_by_gid(&group_id) {
                            if g.hub == Some(local) {
                                g.set_members(members);
                                g.set_member_key(&hub_public);
                            }
                        } else {
                            let id = i.state.next_group_id;
                            i.state.next_group_id += 1;
                            let n = members.len();
                            let mut g = Group::new(id, group_id, Some(local));
                            g.member_fps = members;
                            g.set_member_key(&hub_public);
                            i.state.groups.push(g);
                            ev = Some(Event::Info(format!(
                                "#{local} added you to group G{id} ({n} members)"
                            )));
                        }
                    }
                    Content::GroupMember { group_id, identity } => {
                        if let (Some(g), Ok(public)) = (
                            i.state.group_by_gid(&group_id),
                            IdentityPublic::from_bytes(&identity),
                        ) {
                            if g.hub == Some(local) {
                                g.set_member_key(&public);
                            }
                        }
                    }
                    Content::GroupKey {
                        group_id,
                        author,
                        to,
                        sealed,
                    } => {
                        let sender_fp = c.public.fingerprint();
                        let identity = i.state.identity.clone();
                        let my_fp = identity.public().fingerprint();
                        let by_fp: Option<u32> = i
                            .state
                            .contacts
                            .iter()
                            .find(|x| x.public.fingerprint() == to)
                            .map(|x| x.local_id);
                        if let Some(g) = i.state.group_by_gid(&group_id) {
                            let is_hub_here = g.hub.is_none() && g.members.contains(&local);
                            let from_hub = g.hub == Some(local);
                            if (is_hub_here && author == sender_fp) || from_hub {
                                if to == my_fp {
                                    let key = g.member_public(&author).and_then(|p| {
                                        let pt = group::open_from(
                                            &identity,
                                            &p,
                                            &group::key_ad(&group_id),
                                            &sealed,
                                        )
                                        .ok()?;
                                        let a = group::SenderAnnounce::from_bytes(&pt).ok()?;
                                        group::PeerSender::new(author, &a).ok()
                                    });
                                    if let Some(key) = key {
                                        g.senders.retain(|s| s.author != author);
                                        g.senders.push(key);
                                    }
                                } else if is_hub_here {
                                    if let Some(m) = by_fp.filter(|m| g.members.contains(m)) {
                                        follow.push(Followup::Send(
                                            m,
                                            Content::GroupKey {
                                                group_id,
                                                author,
                                                to,
                                                sealed,
                                            },
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    Content::GroupSealed {
                        group_id,
                        author,
                        key_id,
                        n,
                        ct,
                        sig,
                    } => {
                        let sender_fp = c.public.fingerprint();
                        if let Some(g) = i.state.group_by_gid(&group_id) {
                            let is_hub_here = g.hub.is_none() && g.members.contains(&local);
                            let from_hub = g.hub == Some(local);
                            if (is_hub_here && author == sender_fp) || from_hub {
                                let gl = g.local_id;
                                let sealed = group::Sealed { key_id, n, ct, sig };
                                if is_hub_here {
                                    for &m in g.members.iter().filter(|&&m| m != local) {
                                        follow.push(Followup::Send(
                                            m,
                                            Content::GroupSealed {
                                                group_id,
                                                author,
                                                key_id,
                                                n,
                                                ct: sealed.ct.clone(),
                                                sig: sealed.sig.clone(),
                                            },
                                        ));
                                    }
                                }
                                let op = g
                                    .senders
                                    .iter_mut()
                                    .find(|s| s.author == author)
                                    .and_then(|s| s.decrypt(&group_id, &sealed).ok())
                                    .and_then(|pt| decode_op(&pt).ok());
                                ev = match op {
                                    None => Some(Event::Error(format!(
                                        "A message in G{gl} could not be decrypted"
                                    ))),
                                    Some(op) => match (g.apply_op(author, false, &op, keep), op) {
                                        (OpEffect::Added, MsgOp::Message { text, .. }) => {
                                            Some(Event::GroupMessage {
                                                group: gl,
                                                author: short_fingerprint(&author),
                                                text,
                                            })
                                        }
                                        (OpEffect::Changed, _) => {
                                            Some(Event::GroupChanged { group: gl })
                                        }
                                        _ => None,
                                    },
                                };
                            }
                        }
                    }

                    Content::GroupText { .. } | Content::GroupOp { .. } => {}
                    Content::GroupLeave { group_id } => {
                        let leaver_fp = c.public.fingerprint();
                        if let Some(g) = i.state.group_by_gid(&group_id) {
                            let gl = g.local_id;
                            if g.hub == Some(local) {
                                i.state.groups.retain(|g| g.group_id != group_id);
                                ev = Some(Event::Info(format!("Group G{gl} was deleted")));
                            } else if g.hub.is_none() && g.members.contains(&local) {
                                g.members.retain(|&m| m != local);

                                let fps: Vec<[u8; 32]> = g
                                    .member_fps
                                    .iter()
                                    .copied()
                                    .filter(|f| *f != leaver_fp)
                                    .collect();
                                g.set_members(fps.clone());
                                for &m in &g.members {
                                    follow.push(Followup::Send(
                                        m,
                                        Content::GroupCreate {
                                            group_id,
                                            members: fps.clone(),
                                        },
                                    ));
                                }
                                ev = Some(Event::Info(format!("#{local} left group G{gl}")));
                            }
                        }
                    }
                    Content::Rotate { identity } => {
                        if let Ok(new_pub) = IdentityPublic::from_bytes(&identity) {
                            let fp = short_fingerprint(&new_pub.fingerprint());
                            c.public = new_pub;
                            ev = Some(Event::Info(format!(
                                "#{local} changed identity key. \
                                 New fingerprint: {fp}"
                            )));
                        }
                    }
                    Content::MailboxGrant {
                        onion_key,
                        auth_secret,
                    } => {
                        if pending_host == Some(local) {
                            let fetch_key: [u8; 32] = random_bytes();
                            let mb = MyMailbox {
                                host_contact: local,
                                onion_key,
                                auth_secret,
                                fetch_key,
                            };
                            let info = Content::MailboxInfo {
                                onion_key,
                                auth_secret,
                                deposit_id: mb.deposit_id(),
                            };
                            i.state.my_mailbox = Some(mb);
                            i.state.mailbox_pending_host = None;
                            follow.push(Followup::Discovery(onion_key, auth_secret));
                            follow.push(Followup::SendToAll(info));
                            ev = Some(Event::Info(format!("Mailbox active at #{local}")));
                        }
                    }
                }
            }
            i.state.check_and_mark_seen(raw);
            i.persist()?;
            Ok((ev, follow))
        })?;
        if let Some(e) = ev {
            self.emit(e);
        }
        Ok(follow)
    }

    fn on_deposit(&self, slot_id: u32, did: &[u8; 32], frame: Vec<u8>) -> Result<Frame> {
        decode_raw_frame(&frame)?;
        self.with(|i| -> Result<Frame> {
            let h = i
                .state
                .hosted
                .iter_mut()
                .find(|h| h.slot == slot_id)
                .ok_or_else(|| anyhow!("mailbox"))?;
            if h.deposit_id.as_ref() != Some(did) || h.frames.len() >= MAX_HOSTED_FRAMES {
                bail!("refused");
            }
            h.frames.push(frame);
            i.persist()?;
            Ok(Frame::Ack)
        })
    }

    fn on_fetch(&self, slot_id: u32, fetch_key: &[u8; 32]) -> Result<Frame> {
        let did = deposit_id(fetch_key);
        self.with(|i| -> Result<Frame> {
            let h = i
                .state
                .hosted
                .iter_mut()
                .find(|h| h.slot == slot_id)
                .ok_or_else(|| anyhow!("mailbox"))?;
            if h.deposit_id != Some(did) {
                bail!("refused");
            }
            let n = h.frames.len().min(MAX_BATCH);
            let batch: Vec<Vec<u8>> = h.frames.drain(..n).collect();
            i.persist()?;
            Ok(Frame::Batch(batch))
        })
    }

    async fn run_followups(self: &Arc<Self>, follow: Vec<Followup>) {
        for f in follow {
            match f {
                Followup::Discovery(o, a) => {
                    let _ = tor::add_discovery_key(&self.client, &o, &a);
                }
                Followup::Send(c, content) => {
                    let _ = self.queue(c, content, None).await;
                }
                Followup::SendToAll(content) => {
                    let ids: Vec<u32> = self.with(|i| {
                        i.state
                            .contacts
                            .iter()
                            .filter(|c| c.accepted && !c.blocked && c.session.is_some())
                            .map(|c| c.local_id)
                            .collect()
                    });
                    for c in ids {
                        let _ = self.queue(c, content.clone(), None).await;
                    }
                }
                Followup::StopSlot(s) => self.stop_slot(s),
                Followup::DeviceDo(c, op) => {
                    let _ = match op {
                        MsgOp::Message { id, text, reply_to } => {
                            self.send_message_id(c, id, text, reply_to).await
                        }
                        other => self.message_op(c, other).await,
                    };
                }
            }
        }
    }

    pub fn create_invite(self: &Arc<Self>) -> Result<String> {
        let (secret, public) = x25519_pair();
        let slot = self.with(|i| {
            let id = i.state.new_slot(public, SlotKind::Invite);
            if let Some(s) = i.state.slot(id) {
                s.invite_auth_secret = Some(*secret);
            }
            id
        });
        let onion_key = self.launch_slot(slot)?;
        let fp = self.my_public().fingerprint();
        Ok(Invite {
            onion_key,
            auth_secret: *secret,
            fingerprint: fp,
        }
        .encode())
    }

    pub fn pending_invites(&self) -> Vec<String> {
        let fp = self.my_public().fingerprint();
        self.with(|i| {
            i.state
                .slots
                .iter()
                .filter(|s| s.kind == SlotKind::Invite)
                .filter_map(|s| {
                    Some(
                        Invite {
                            onion_key: s.onion_key?,
                            auth_secret: s.invite_auth_secret?,
                            fingerprint: fp,
                        }
                        .encode(),
                    )
                })
                .collect()
        })
    }

    pub fn revoke_invites(&self) -> Result<usize> {
        let ids: Vec<u32> = self.with(|i| {
            i.state
                .slots
                .iter()
                .filter(|s| s.kind == SlotKind::Invite)
                .map(|s| s.id)
                .collect()
        });
        for &id in &ids {
            self.stop_slot(id);
        }
        self.with(|i| -> Result<()> {
            i.state.slots.retain(|s| s.kind != SlotKind::Invite);
            i.persist()
        })?;
        Ok(ids.len())
    }

    pub async fn add_contact(self: &Arc<Self>, invite: &str) -> Result<u32> {
        let inv = Invite::decode(invite)?;
        let own = self.with(|i| {
            i.state
                .slots
                .iter()
                .any(|s| s.onion_key == Some(inv.onion_key))
        });
        if own {
            bail!("this is your own invite");
        }
        tor::add_discovery_key(&self.client, &inv.onion_key, &inv.auth_secret)?;
        let mut s = tor::connect(&self.client, &inv.onion_key).await?;
        write_frame(&mut s, &Frame::GetBundle).await?;
        let bundle = match expect_frame(&mut s).await? {
            Frame::Bundle(b) => IdentityPublic::from_bytes(&b)?,
            _ => bail!("invite already used or revoked"),
        };
        inv.verify(&bundle)?;
        if bundle == self.my_public() {
            bail!("this is your own invite");
        }

        let (their_secret, their_public) = x25519_pair();
        let (id, slot) = self.with(|i| -> Result<(u32, u32)> {
            let id = i.state.add_contact(bundle, Origin::Invite);
            let slot = i.state.new_slot(their_public, SlotKind::Contact(id));
            let c = i.state.contact_by_local(id).expect("just added");
            c.accepted = true;
            c.peer_onion = Some(inv.onion_key);
            c.peer_auth = Some(inv.auth_secret);
            c.my_slot = Some(slot);
            i.persist()?;
            Ok((id, slot))
        })?;
        let my_onion = self.launch_slot(slot)?;
        let extra = Zeroizing::new(bincode::serialize(&ReturnAddr {
            onion_key: my_onion,
            auth_secret: *their_secret,
        })?);
        self.handshake(id, Some(s), &extra).await?;
        self.ensure_cover_task(id);
        if let Some(info) = self.mailbox_info_content() {
            let _ = self.queue(id, info, None).await;
        }
        Ok(id)
    }

    fn mailbox_info_content(&self) -> Option<Content> {
        self.with(|i| {
            i.state.my_mailbox.as_ref().map(|m| Content::MailboxInfo {
                onion_key: m.onion_key,
                auth_secret: m.auth_secret,
                deposit_id: m.deposit_id(),
            })
        })
    }

    async fn handshake(
        &self,
        contact: u32,
        stream: Option<DataStream>,
        extra: &[u8],
    ) -> Result<()> {
        let (identity, peer, onion) = self.with(|i| {
            let identity = i.state.identity.clone();
            let c = i.state.contact_by_local(contact);
            (
                identity,
                c.as_ref().map(|c| c.public.clone()),
                c.and_then(|c| c.peer_onion),
            )
        });
        let peer = peer.ok_or_else(|| anyhow!("unknown contact"))?;
        let mut s = match stream {
            Some(s) => s,
            None => {
                let onion = onion.ok_or_else(|| anyhow!("unknown contact address"))?;
                tor::connect(&self.client, &onion).await?
            }
        };

        let (hs1, st) = handshake::initiate(&identity, &peer, extra)?;
        write_frame(&mut s, &Frame::Hs1(hs1)).await?;
        let hs2 = match expect_frame(&mut s).await? {
            Frame::Hs2(m) => m,
            _ => bail!("peer refused the session"),
        };
        let mut est = handshake::finish(&identity, st, &hs2)?;

        let hello = encode_content(&Content::Hello)?;
        let msg = est.ratchet.encrypt(&hello, &est.session_id)?;
        let frame = Frame::Msg {
            session_id: est.session_id,
            msg,
        };

        self.with(|i| -> Result<()> {
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("unknown contact"))?;
            c.session = Some(Session {
                id: est.session_id,
                ratchet: est.ratchet.clone(),
            });
            i.persist()
        })?;

        write_frame(&mut s, &frame).await?;
        let _ = expect_frame(&mut s).await;
        Ok(())
    }

    pub async fn send_text(self: &Arc<Self>, contact: u32, text: String) -> Result<()> {
        self.send_reply(contact, text, None).await
    }

    pub async fn send_reply(
        self: &Arc<Self>,
        contact: u32,
        text: String,
        reply_to: Option<[u8; 16]>,
    ) -> Result<()> {
        self.send_message_id(contact, random_bytes(), text, reply_to)
            .await
    }

    async fn send_message_id(
        self: &Arc<Self>,
        contact: u32,
        id: [u8; 16],
        text: String,
        reply_to: Option<[u8; 16]>,
    ) -> Result<()> {
        self.with(|i| -> Result<()> {
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("unknown contact"))?;
            if c.blocked {
                bail!("contact is blocked");
            }
            c.accepted = true;
            Ok(())
        })?;
        let mut entry = HistoryEntry::new(Direction::Out, text.clone(), false, None);
        entry.id = id;
        entry.reply_to = reply_to;
        let op = MsgOp::Message { id, text, reply_to };
        self.queue_many(contact, vec![Content::Op(op.clone())], Some(entry))
            .await?;
        self.sync_devices(contact, op).await;
        Ok(())
    }

    async fn sync_devices(self: &Arc<Self>, contact: u32, op: MsgOp) {
        let targets = self.with(|i| {
            let devices = i.state.devices();
            let c = i.state.contact_by_local(contact)?;
            if c.own_device || devices.is_empty() {
                return None;
            }
            Some((c.public.fingerprint(), c.timer.unwrap_or(0), devices))
        });
        if let Some((fp, ttl, devices)) = targets {
            for d in devices {
                let sync = DeviceMsg::Sync {
                    fp,
                    out: true,
                    ttl,
                    op: op.clone(),
                };
                let _ = self.queue(d, Content::Device(sync), None).await;
            }
        }
    }

    pub async fn request_device_link(self: &Arc<Self>, primary: u32) -> Result<()> {
        self.with(|i| -> Result<()> {
            if i.state.contact_by_local(primary).is_none() {
                bail!("unknown contact");
            }
            if !i.state.devices().is_empty() {
                bail!("this device already has companions: it cannot be one itself");
            }
            i.state.primary_pending = Some(primary);
            i.persist()
        })?;
        self.queue(primary, Content::Device(DeviceMsg::Link), None)
            .await
    }

    pub async fn accept_device(self: &Arc<Self>, contact: u32) -> Result<()> {
        let now = now_secs();
        let contents = self.with(|i| -> Result<Vec<Content>> {
            if !i.state.device_requests.contains(&contact) {
                bail!("this contact did not ask to be linked");
            }
            if i.state.primary.is_some() || i.state.primary_pending.is_some() {
                bail!("this device is itself a companion: it cannot have companions");
            }
            i.state.device_requests.retain(|&r| r != contact);
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("unknown contact"))?;
            c.own_device = true;
            c.accepted = true;
            let mut contents = vec![Content::Device(DeviceMsg::Accept)];

            for c in i.state.contacts.iter() {
                if c.own_device || c.blocked || !c.accepted {
                    continue;
                }
                let fp = c.public.fingerprint();
                contents.push(Content::Device(DeviceMsg::Peer {
                    fp,
                    note: c.note.clone(),
                }));
                let start = c.history.len().saturating_sub(30);
                for h in c.history[start..].iter().filter(|h| !h.deleted) {
                    let ttl = match h.expires_at {
                        Some(t) if t <= now => continue,
                        Some(t) => (t - now).min(u32::MAX as u64) as u32,
                        None => 0,
                    };
                    contents.push(Content::Device(DeviceMsg::Sync {
                        fp,
                        out: h.dir == Direction::Out,
                        ttl,
                        op: MsgOp::Message {
                            id: if h.id == [0; 16] {
                                random_bytes()
                            } else {
                                h.id
                            },
                            text: h.text.clone(),
                            reply_to: h.reply_to,
                        },
                    }));
                }
            }
            i.persist()?;
            Ok(contents)
        })?;
        self.queue_many(contact, contents, None).await
    }

    pub async fn unlink_device(self: &Arc<Self>, contact: u32) -> Result<()> {
        let _ = self
            .queue(contact, Content::Device(DeviceMsg::Unlink), None)
            .await;
        self.with(|i| {
            i.state.unlink_device(contact);
            i.persist()
        })
    }

    pub async fn mirror_op(self: &Arc<Self>, mirror: u32, op: MsgOp) -> Result<()> {
        let (primary, fp) = self.with(|i| -> Result<(u32, [u8; 32])> {
            let primary = i
                .state
                .primary
                .ok_or_else(|| anyhow!("this device is not linked"))?;
            let keep = i.state.keep_history;
            let m = i
                .state
                .mirror_by_local(mirror)
                .ok_or_else(|| anyhow!("unknown conversation"))?;

            if let (true, MsgOp::Message { id, text, reply_to }) = (keep, &op) {
                let mut e = HistoryEntry::new(Direction::Out, text.clone(), false, None);
                e.id = *id;
                e.reply_to = *reply_to;
                m.history.push(e);
            }
            let fp = m.fp;
            i.persist()?;
            Ok((primary, fp))
        })?;
        self.queue(primary, Content::Device(DeviceMsg::Send { fp, op }), None)
            .await
    }

    pub async fn message_op(self: &Arc<Self>, contact: u32, op: MsgOp) -> Result<()> {
        let send = self.with(|i| -> Result<bool> {
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("unknown contact"))?;
            let send = match &op {
                MsgOp::Message { .. } => bail!("use send_reply"),
                MsgOp::React { target, emoji } => {
                    let e = c
                        .entry_mut(target)
                        .ok_or_else(|| anyhow!("unknown message"))?;
                    set_reaction(&mut e.reactions, None, emoji);
                    true
                }
                MsgOp::Edit { target, text } => {
                    let e = c
                        .entry_mut(target)
                        .ok_or_else(|| anyhow!("unknown message"))?;
                    if e.dir != Direction::Out || e.deleted {
                        bail!("you can only edit your own messages");
                    }
                    e.text = text.clone();
                    e.edited = true;
                    true
                }
                MsgOp::Delete { target } => {
                    let pos = c
                        .history
                        .iter()
                        .rposition(|e| e.id == *target && *target != [0; 16])
                        .ok_or_else(|| anyhow!("unknown message"))?;
                    if c.history[pos].dir == Direction::Out {
                        let e = &mut c.history[pos];
                        e.text.clear();
                        e.reactions.clear();
                        e.deleted = true;
                        true
                    } else {
                        c.history.remove(pos);
                        false
                    }
                }
            };
            i.persist()?;
            Ok(send)
        })?;
        if send {
            self.queue(contact, Content::Op(op.clone()), None).await?;
            self.sync_devices(contact, op).await;
        }
        Ok(())
    }

    pub async fn set_timer(self: &Arc<Self>, contact: u32, secs: u32) -> Result<()> {
        self.with(|i| -> Result<()> {
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("unknown contact"))?;
            c.timer = (secs > 0).then_some(secs);
            Ok(())
        })?;
        self.queue(contact, Content::Timer(secs), None).await
    }

    async fn queue(
        self: &Arc<Self>,
        contact: u32,
        content: Content,
        history: Option<HistoryEntry>,
    ) -> Result<()> {
        self.queue_many(contact, vec![content], history).await
    }

    async fn queue_many(
        self: &Arc<Self>,
        contact: u32,
        contents: Vec<Content>,
        history: Option<HistoryEntry>,
    ) -> Result<()> {
        let need_hs = self.with(|i| {
            i.state
                .contact_by_local(contact)
                .map(|c| c.session.as_ref().is_none_or(|s| !s.ratchet.can_send()))
        });
        match need_hs {
            None => bail!("unknown contact"),
            Some(true) => self
                .handshake(contact, None, &[])
                .await
                .map_err(|e| anyhow!("peer unreachable: {e}"))?,
            Some(false) => {}
        }

        let encoded: Vec<Zeroizing<Vec<u8>>> = contents
            .iter()
            .map(encode_content)
            .collect::<lycta_core::Result<_>>()?;
        let immediate = self.with(|i| -> Result<bool> {
            let keep = i.state.keep_history;
            let immediate = i.state.cover.mean_interval_secs().is_none();
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("unknown contact"))?;
            let timer = c.timer;
            let session = c.session.as_mut().ok_or_else(|| anyhow!("no session"))?;
            let sid = session.id;
            let mut frames = Vec::with_capacity(encoded.len());
            for e in &encoded {
                let msg = session.ratchet.encrypt(e, &sid)?;
                frames.push(encode_frame(&Frame::Msg {
                    session_id: sid,
                    msg,
                })?);
            }
            let (history_index, history_id) = match history {
                Some(mut e) if keep => {
                    e.delivered = false;
                    e.expires_at = timer.map(|t| now_secs() + t as u64);
                    let id = (e.id != [0; 16]).then_some(e.id);
                    (Some(c.push_history(e)), id)
                }
                _ => (None, None),
            };
            let last = frames.len().saturating_sub(1);
            for (k, frame) in frames.into_iter().enumerate() {
                let (hidx, hid) = if k == last {
                    (history_index, history_id)
                } else {
                    (None, None)
                };
                i.state.outbox.push(OutboxItem {
                    contact,
                    frame,
                    history_index: hidx,
                    history_id: hid,
                    deposited: false,
                });
            }
            i.persist()?;
            Ok(immediate)
        })?;

        if immediate {
            let me = Arc::clone(self);
            self.spawn_bg(async move {
                let _ = me.flush(contact).await;
            });
        }
        Ok(())
    }

    pub async fn flush(&self, contact: u32) -> Result<()> {
        let (frames, onion, mailbox) = self.with(|i| {
            let frames: Vec<Vec<u8>> = i
                .state
                .outbox
                .iter()
                .filter(|o| o.contact == contact)
                .map(|o| o.frame.clone())
                .collect();
            let c = i.state.contact_by_local(contact);
            let onion = c.as_ref().and_then(|c| c.peer_onion);
            let mb = c.and_then(|c| c.mailbox.as_ref().map(|m| (m.onion_key, m.deposit_id)));
            (frames, onion, mb)
        });
        if frames.is_empty() {
            return Ok(());
        }
        let onion = onion.ok_or_else(|| anyhow!("unknown contact address"))?;
        match tor::connect(&self.client, &onion).await {
            Ok(mut s) => self.flush_direct(contact, &mut s, frames).await,
            Err(e) => match mailbox {
                Some((mb_onion, did)) => self.flush_mailbox(contact, &mb_onion, &did, frames).await,
                None => Err(e),
            },
        }
    }

    async fn flush_direct(
        &self,
        contact: u32,
        s: &mut DataStream,
        frames: Vec<Vec<u8>>,
    ) -> Result<()> {
        let r = self.flush_direct_inner(contact, s, frames).await;
        self.save()?;
        r
    }

    async fn flush_direct_inner(
        &self,
        contact: u32,
        s: &mut DataStream,
        frames: Vec<Vec<u8>>,
    ) -> Result<()> {
        let mut since_save = 0;
        for f in frames {
            write_raw(s, &f).await?;
            match expect_frame(s).await? {
                Frame::Ack => {
                    let marked = self.remove_outbox(&f, true, false)?;
                    since_save += 1;
                    if since_save >= 32 {
                        self.save()?;
                        since_save = 0;
                    }
                    if marked {
                        self.emit(Event::Delivered { contact });
                    }
                }
                _ => {
                    self.with(|i| -> Result<()> {
                        i.state.outbox.retain(|o| o.contact != contact);
                        if let Some(c) = i.state.contact_by_local(contact) {
                            c.session = None;
                        }
                        i.persist()
                    })?;
                    self.emit(Event::Error(format!(
                        "#{contact} rejected the session. \
                         Resend your messages."
                    )));
                    break;
                }
            }
        }
        Ok(())
    }

    async fn flush_mailbox(
        &self,
        contact: u32,
        mb_onion: &[u8; 32],
        did: &[u8; 32],
        frames: Vec<Vec<u8>>,
    ) -> Result<()> {
        let pending: Vec<Vec<u8>> = self.with(|i| {
            i.state
                .outbox
                .iter()
                .filter(|o| o.contact == contact && !o.deposited && frames.contains(&o.frame))
                .map(|o| o.frame.clone())
                .collect()
        });
        if pending.is_empty() {
            return Ok(());
        }
        let mut s = tor::connect(&self.client, mb_onion).await?;
        for f in pending {
            write_frame(
                &mut s,
                &Frame::Deposit {
                    deposit_id: *did,
                    frame: f.clone(),
                },
            )
            .await?;
            if let Frame::Ack = expect_frame(&mut s).await? {
                if self.remove_outbox(&f, true, true)? {
                    self.emit(Event::Deposited { contact });
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    fn remove_outbox(&self, frame: &[u8], delivered: bool, persist: bool) -> Result<bool> {
        self.with(|i| -> Result<bool> {
            let mut marked = false;
            if let Some(pos) = i.state.outbox.iter().position(|o| o.frame == frame) {
                let contact = i.state.outbox[pos].contact;
                let hidx = i.state.outbox[pos].history_index;
                let hid = i.state.outbox[pos].history_id;
                i.state.outbox.remove(pos);
                if let Some(c) = i.state.contact_by_local(contact) {
                    let e = match hid {
                        Some(id) => c.entry_mut(&id),
                        None => hidx.and_then(|h| c.history.get_mut(h)),
                    };
                    if let Some(e) = e {
                        e.delivered = delivered;
                        marked = true;
                    }
                }
            }
            if persist {
                i.persist()?;
            }
            Ok(marked)
        })
    }

    pub async fn send_file(self: &Arc<Self>, contact: u32, path: &std::path::Path) -> Result<()> {
        let size = std::fs::metadata(path)?.len();
        if size > MAX_FILE as u64 {
            bail!("file too large ({size} bytes, max {MAX_FILE})");
        }
        let data = std::fs::read(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.send_file_bytes(contact, &name, data).await
    }

    pub async fn send_file_bytes(
        self: &Arc<Self>,
        contact: u32,
        name: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let data = Zeroizing::new(data);
        if data.is_empty() {
            bail!("empty file");
        }
        if data.len() > MAX_FILE {
            bail!("file too large ({} bytes, max {MAX_FILE})", data.len());
        }
        let name = sanitize_name(name);
        let file_id: [u8; 16] = random_bytes();
        let hash = lycta_core::primitives::sha3_256(&[b"LyctaCrypt/file", &data]);
        let chunks: Vec<&[u8]> = data.chunks(FILE_CHUNK).collect();
        let mut contents = Vec::with_capacity(chunks.len() + 1);
        contents.push(Content::FileStart {
            file_id,
            name: name.clone(),
            size: data.len() as u64,
            chunks: chunks.len() as u32,
            hash,
        });
        for (k, ch) in chunks.iter().enumerate() {
            contents.push(Content::FileChunk {
                file_id,
                index: k as u32,
                data: ch.to_vec(),
            });
        }
        let mut entry = HistoryEntry::new(Direction::Out, format!("[file] {name}"), false, None);
        entry.id = random_bytes();

        let kind = AttachmentKind::from_name(&name);
        if kind != AttachmentKind::Other {
            entry.attachment = self.with(|i| {
                if !i.state.keep_history || i.state.stored_bytes() + data.len() > MAX_STORED_BYTES {
                    return None;
                }
                let id = i.state.next_file_id;
                i.state.next_file_id += 1;
                i.state.files.push(StoredFile {
                    local_id: id,
                    contact,
                    name: name.clone(),
                    data: data.to_vec(),
                });
                Some(Attachment {
                    file: id,
                    name: name.clone(),
                    kind,
                })
            });
        }
        self.queue_many(contact, contents, Some(entry)).await
    }

    pub fn export_file(&self, file: u32, dest: &std::path::Path) -> Result<std::path::PathBuf> {
        let (name, data) = self
            .with(|i| {
                i.state
                    .files
                    .iter()
                    .find(|f| f.local_id == file)
                    .map(|f| (f.name.clone(), Zeroizing::new(f.data.clone())))
            })
            .ok_or_else(|| anyhow!("unknown file"))?;
        let target = if dest.is_dir() {
            dest.join(&name)
        } else {
            dest.to_path_buf()
        };
        std::fs::write(&target, &*data)?;
        self.with(|i| {
            i.state.files.retain(|f| f.local_id != file);
            i.persist()
        })?;
        Ok(target)
    }

    pub async fn create_group(self: &Arc<Self>, members: Vec<u32>) -> Result<u32> {
        if members.is_empty() || members.len() + 1 > MAX_GROUP_MEMBERS {
            bail!("between 1 and {} members", MAX_GROUP_MEMBERS - 1);
        }
        let my_fp = self.my_public().fingerprint();
        let my_public = self.my_public();
        type Created = (u32, [u8; 16], Vec<[u8; 32]>, Vec<(u32, Vec<u8>)>);
        let (local, gid, fps, bundles) = self.with(|i| -> Result<Created> {
            let mut fps = vec![my_fp];

            let mut bundles = vec![(0u32, my_public.to_bytes())];
            let gid: [u8; 16] = random_bytes();
            let local = i.state.next_group_id;
            let mut g = Group::new(local, gid, None);
            let mut publics = vec![my_public.clone()];
            for &m in &members {
                let c = i
                    .state
                    .contact_by_local(m)
                    .ok_or_else(|| anyhow!("unknown contact #{m}"))?;
                if c.blocked || !c.accepted {
                    bail!("contact #{m} not accepted or blocked");
                }
                fps.push(c.public.fingerprint());
                bundles.push((m, c.public.to_bytes()));
                publics.push(c.public.clone());
            }
            i.state.next_group_id += 1;
            g.members = members.clone();
            g.member_fps = fps.clone();
            for p in &publics {
                g.set_member_key(p);
            }
            i.state.groups.push(g);
            i.persist()?;
            Ok((local, gid, fps, bundles))
        })?;
        for &m in &members {
            let mut contents = vec![Content::GroupCreate {
                group_id: gid,
                members: fps.clone(),
            }];

            for (owner, identity) in &bundles {
                if *owner != m && *owner != 0 {
                    contents.push(Content::GroupMember {
                        group_id: gid,
                        identity: identity.clone(),
                    });
                }
            }
            let _ = self.queue_many(m, contents, None).await;
        }
        Ok(local)
    }

    pub async fn send_group(self: &Arc<Self>, group: u32, text: String) -> Result<()> {
        self.group_op(
            group,
            MsgOp::Message {
                id: random_bytes(),
                text,
                reply_to: None,
            },
        )
        .await
    }

    pub async fn group_op(self: &Arc<Self>, group: u32, op: MsgOp) -> Result<()> {
        let me = self.my_public().fingerprint();
        let sends = self.with(|i| -> Result<Vec<(u32, Content)>> {
            let keep = i.state.keep_history;
            let identity = i.state.identity.clone();
            let by_fp: Vec<([u8; 32], u32)> = i
                .state
                .contacts
                .iter()
                .map(|c| (c.public.fingerprint(), c.local_id))
                .collect();
            let g = i
                .state
                .group_by_local(group)
                .ok_or_else(|| anyhow!("unknown group"))?;
            if let MsgOp::Edit { target, .. } | MsgOp::Delete { target } = &op {
                if !g.entry_mut(target).is_some_and(|e| e.author == me) {
                    bail!("you can only change your own messages");
                }
            }
            let gid = g.group_id;
            let mut sends = Vec::new();

            let mut sender = g.my_sender.take().unwrap_or_else(SenderKey::generate);
            let announce = sender.announce().to_bytes();
            for mk in &g.member_keys {
                if mk.fp == me || sender.given_to.contains(&mk.fp) {
                    continue;
                }
                let Ok(public) = IdentityPublic::from_bytes(&mk.public) else {
                    continue;
                };
                let sealed = group::seal_to(&identity, &public, &group::key_ad(&gid), &announce)?;
                let content = Content::GroupKey {
                    group_id: gid,
                    author: me,
                    to: mk.fp,
                    sealed,
                };
                let via = match g.hub {
                    Some(h) => Some(h),
                    None => by_fp
                        .iter()
                        .find(|(f, l)| *f == mk.fp && g.members.contains(l))
                        .map(|(_, l)| *l),
                };
                if let Some(t) = via {
                    sends.push((t, content));
                    sender.given_to.push(mk.fp);
                }
            }

            let s = sender.encrypt(&gid, &me, &encode_op(&op)?);
            g.my_sender = Some(sender);
            g.apply_op(me, true, &op, keep);
            let targets = match g.hub {
                None => g.members.clone(),
                Some(h) => vec![h],
            };
            for t in targets {
                sends.push((
                    t,
                    Content::GroupSealed {
                        group_id: gid,
                        author: me,
                        key_id: s.key_id,
                        n: s.n,
                        ct: s.ct.clone(),
                        sig: s.sig.clone(),
                    },
                ));
            }
            i.persist()?;
            Ok(sends)
        })?;
        for (t, content) in sends {
            self.queue(t, content, None).await?;
        }
        Ok(())
    }

    pub async fn leave_group(self: &Arc<Self>, group: u32) -> Result<()> {
        let (gid, targets) = self
            .with(|i| {
                i.state.group_by_local(group).map(|g| {
                    (
                        g.group_id,
                        match g.hub {
                            None => g.members.clone(),
                            Some(h) => vec![h],
                        },
                    )
                })
            })
            .ok_or_else(|| anyhow!("unknown group"))?;
        for t in targets {
            let _ = self
                .queue(t, Content::GroupLeave { group_id: gid }, None)
                .await;
        }
        self.with(|i| {
            i.state.groups.retain(|g| g.local_id != group);
            i.persist()
        })
    }

    pub async fn rotate_identity(self: &Arc<Self>) -> Result<Vec<u32>> {
        let new_id = Identity::generate();
        let announce = Content::Rotate {
            identity: new_id.public().to_bytes(),
        };
        let ids: Vec<u32> = self.with(|i| {
            i.state
                .contacts
                .iter()
                .filter(|c| !c.blocked)
                .map(|c| c.local_id)
                .collect()
        });
        let mut missed = Vec::new();
        for c in ids {
            if self.queue(c, announce.clone(), None).await.is_err() {
                missed.push(c);
            }
        }
        self.with(|i| {
            i.state.identity = new_id;
            i.persist()
        })?;
        Ok(missed)
    }

    pub fn create_decoy(&self, pass: &[u8], contacts: usize, conversations: bool) -> Result<()> {
        if pass.len() < 12 {
            bail!("passphrase too short (12 characters minimum)");
        }
        let slots = self.with(|i| i.vk.slots_snapshot());
        if slots.len() >= vault::MAX_SLOTS {
            bail!("maximum number of vaults reached");
        }

        if !vault::check_pass_unused(&slots, pass)? {
            bail!("this passphrase already opens a vault");
        }
        let decoy = lycta_core::decoy::populate(contacts, conversations);
        let slot = vault::seal_new_slot(&decoy, pass)?;
        self.with(|i| -> Result<()> {
            i.vk.insert_slot(slot)?;
            i.persist()
        })
    }

    pub fn backup(&self, path: &std::path::Path, pass: &[u8]) -> Result<()> {
        self.with(|i| vault::backup(path, &i.state, pass))?;
        Ok(())
    }

    fn ensure_cover_task(self: &Arc<Self>, contact: u32) {
        let new = self
            .cover_tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(contact);
        if new {
            self.spawn_bg(Arc::clone(self).cover_loop(contact));
        }
    }

    async fn cover_loop(self: Arc<Self>, contact: u32) {
        loop {
            let (mean, exists) = self.with(|i| {
                let mean = i.state.cover.mean_interval_secs();
                let exists = i
                    .state
                    .contacts
                    .iter()
                    .any(|c| c.local_id == contact && !c.blocked);
                (mean, exists)
            });
            if !exists {
                break;
            }
            let Some(mean) = mean else {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            };
            tokio::time::sleep(poisson_delay(mean)).await;
            let has_pending = self.with(|i| i.state.outbox.iter().any(|o| o.contact == contact));
            let _ = if has_pending {
                self.flush(contact).await
            } else {
                self.send_cover(contact).await
            };
        }
        self.cover_tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&contact);
    }

    async fn send_cover(&self, contact: u32) -> Result<()> {
        let onion = self.with(|i| {
            i.state.contact_by_local(contact).and_then(|c| {
                let ready = c.session.as_ref().is_some_and(|s| s.ratchet.can_send());
                if ready {
                    c.peer_onion
                } else {
                    None
                }
            })
        });
        let Some(onion) = onion else { return Ok(()) };

        let mut s = tor::connect(&self.client, &onion).await?;
        let encoded = encode_content(&Content::Cover)?;
        let frame = self.with(|i| -> Result<Vec<u8>> {
            let c = i
                .state
                .contact_by_local(contact)
                .ok_or_else(|| anyhow!("contact"))?;
            let session = c.session.as_mut().ok_or_else(|| anyhow!("session"))?;
            let sid = session.id;
            let msg = session.ratchet.encrypt(&encoded, &sid)?;
            let f = encode_frame(&Frame::Msg {
                session_id: sid,
                msg,
            })?;
            i.persist()?;
            Ok(f)
        })?;
        write_raw(&mut s, &frame).await?;
        let _ = expect_frame(&mut s).await;
        Ok(())
    }

    pub async fn request_mailbox(self: &Arc<Self>, host: u32) -> Result<()> {
        self.with(|i| i.state.mailbox_pending_host = Some(host));
        self.queue(host, Content::MailboxRequest, None).await
    }

    pub async fn accept_mailbox(self: &Arc<Self>, owner: u32) -> Result<()> {
        let asked = self.with(|i| i.state.mailbox_requests.contains(&owner));
        if !asked {
            bail!("#{owner} didn't ask you to host a mailbox");
        }
        let (secret, public) = x25519_pair();
        let slot = self.with(|i| {
            i.state.mailbox_requests.retain(|&r| r != owner);
            let slot = i.state.new_slot(public, SlotKind::Mailbox(owner));
            i.state.hosted.retain(|h| h.owner != owner);
            i.state.hosted.push(HostedMailbox {
                slot,
                owner,
                deposit_id: None,
                frames: Vec::new(),
            });
            slot
        });
        let onion_key = self.launch_slot(slot)?;
        self.queue(
            owner,
            Content::MailboxGrant {
                onion_key,
                auth_secret: *secret,
            },
            None,
        )
        .await
    }

    pub async fn revoke_mailbox(self: &Arc<Self>) -> Result<()> {
        let had = self.with(|i| i.state.my_mailbox.take().is_some());
        if had {
            self.run_followups(vec![Followup::SendToAll(Content::MailboxRevoke)])
                .await;
        }
        self.save()
    }

    async fn mailbox_fetch_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(poisson_delay(MAILBOX_FETCH_MEAN_SECS)).await;
            let _ = self.fetch_mailbox().await;
        }
    }

    async fn fetch_mailbox(self: &Arc<Self>) -> Result<()> {
        let Some((onion, fetch_key)) = self.with(|i| {
            i.state
                .my_mailbox
                .as_ref()
                .map(|m| (m.onion_key, Zeroizing::new(m.fetch_key)))
        }) else {
            return Ok(());
        };
        let mut s = tor::connect(&self.client, &onion).await?;
        loop {
            write_frame(
                &mut s,
                &Frame::Fetch {
                    fetch_key: *fetch_key,
                },
            )
            .await?;
            let Frame::Batch(frames) = expect_frame(&mut s).await? else {
                break;
            };
            let n = frames.len();
            for raw in frames {
                if let Ok(Frame::Msg { session_id, msg }) = decode_raw_frame(&raw) {
                    if let Ok(follow) = self.on_msg(None, &session_id, &msg, &raw) {
                        self.run_followups(follow).await;
                    }
                }
            }
            if n < MAX_BATCH {
                break;
            }
        }
        Ok(())
    }

    async fn retry_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(poisson_delay(90.0)).await;
            let pending: Vec<u32> = self.with(|i| {
                if i.state.cover.mean_interval_secs().is_some() {
                    return Vec::new();
                }
                let mut v: Vec<u32> = i.state.outbox.iter().map(|o| o.contact).collect();
                v.sort_unstable();
                v.dedup();
                v
            });
            for c in pending {
                let _ = self.flush(c).await;
            }
        }
    }

    async fn expiry_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let _ = self.with(|i| -> Result<()> {
                if i.state.expire_history(now_secs()) > 0 {
                    i.persist()?;
                }
                Ok(())
            });
        }
    }

    pub fn forget_contact(&self, contact: u32) -> Result<()> {
        let slots: Vec<u32> = self.with(|i| {
            i.state
                .slots
                .iter()
                .filter(|s| {
                    s.kind == SlotKind::Contact(contact) || s.kind == SlotKind::Mailbox(contact)
                })
                .map(|s| s.id)
                .collect()
        });
        for s in slots {
            self.stop_slot(s);
        }
        self.with(|i| {
            i.state.remove_contact(contact);
            i.persist()
        })
    }
}
