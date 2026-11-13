use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use argon2::{Algorithm, Argon2, Params, Version};

use crate::group::{PeerSender, SenderKey};
use crate::handshake::SessionId;
use crate::identity::{Identity, IdentityPublic};
use crate::primitives::{open, random_bytes, seal, sha3_256};
use crate::ratchet::Ratchet;
use crate::wire::MsgOp;

const CBOR_TAG: u8 = 0xCB;

fn encode_state(state: &State) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(vec![CBOR_TAG]);
    ciborium::into_writer(state, &mut *out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

pub(crate) fn decode_state(pt: &[u8]) -> Result<State> {
    if pt.first() == Some(&CBOR_TAG) {
        if let Ok(st) = ciborium::from_reader::<State, _>(&pt[1..]) {
            return Ok(st);
        }
    }

    let legacy: crate::legacy::LegacyState = bincode::deserialize(pt)?;
    Ok(legacy.into())
}
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"LYCTA\x00v2";
const SALT_LEN: usize = 16;
const ARGON_M_KIB: u32 = 64 * 1024;
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 1;
const MAX_SEEN: usize = 4096;
const MAX_HISTORY: usize = 2000;

pub const MAX_HOSTED_FRAMES: usize = 500;

macro_rules! redacted_debug {
    ($($t:ty),*) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )*};
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Zeroize)]
pub enum Origin {
    Invite,

    Request,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Zeroize)]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Zeroize)]
pub enum CoverMode {
    Off,

    Low,

    High,
}

impl CoverMode {
    pub fn mean_interval_secs(self) -> Option<f64> {
        match self {
            CoverMode::Off => None,
            CoverMode::Low => Some(120.0),
            CoverMode::High => Some(20.0),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Zeroize)]
pub enum SlotKind {
    Invite,

    Contact(u32),

    Mailbox(u32),
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Slot {
    pub id: u32,

    pub hs_seed: [u8; 32],

    pub onion_key: Option<[u8; 32]>,

    pub authorized_client: [u8; 32],

    pub invite_auth_secret: Option<[u8; 32]>,
    pub kind: SlotKind,
}
redacted_debug!(Slot);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HistoryEntry {
    pub dir: Direction,
    pub text: String,

    pub delivered: bool,

    pub expires_at: Option<u64>,

    #[serde(default)]
    pub id: [u8; 16],
    #[serde(default)]
    pub reply_to: Option<[u8; 16]>,
    #[serde(default)]
    pub reactions: Vec<Reaction>,
    #[serde(default)]
    pub edited: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub attachment: Option<Attachment>,
}

impl HistoryEntry {
    pub fn new(dir: Direction, text: String, delivered: bool, expires_at: Option<u64>) -> Self {
        Self {
            dir,
            text,
            delivered,
            expires_at,
            id: [0; 16],
            reply_to: None,
            reactions: Vec::new(),
            edited: false,
            deleted: false,
            attachment: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, PartialEq)]
pub struct Reaction {
    pub from: Option<[u8; 32]>,
    pub emoji: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, PartialEq)]
pub struct Attachment {
    pub file: u32,
    pub name: String,
    pub kind: AttachmentKind,
}

redacted_debug!(Reaction, Attachment);

#[derive(Clone, Copy, Serialize, Deserialize, Zeroize, PartialEq, Eq, Debug)]
pub enum AttachmentKind {
    Image,
    Audio,
    Other,
}

impl AttachmentKind {
    pub fn from_name(name: &str) -> Self {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => AttachmentKind::Image,
            "wav" | "ogg" | "opus" | "mp3" | "m4a" | "flac" => AttachmentKind::Audio,
            _ => AttachmentKind::Other,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Session {
    pub id: SessionId,
    pub ratchet: Ratchet,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PeerMailbox {
    pub onion_key: [u8; 32],
    pub auth_secret: [u8; 32],
    pub deposit_id: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Contact {
    pub local_id: u32,
    pub public: IdentityPublic,
    pub origin: Origin,
    pub accepted: bool,
    pub blocked: bool,

    pub note: Option<String>,
    pub session: Option<Session>,

    pub my_slot: Option<u32>,

    pub peer_onion: Option<[u8; 32]>,
    pub peer_auth: Option<[u8; 32]>,

    pub timer: Option<u32>,
    pub mailbox: Option<PeerMailbox>,
    pub history: Vec<HistoryEntry>,

    #[serde(default)]
    pub own_device: bool,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Mirror {
    pub local_id: u32,
    pub fp: [u8; 32],
    pub note: Option<String>,
    pub history: Vec<HistoryEntry>,
}
redacted_debug!(Mirror);

impl Mirror {
    pub fn entry_mut(&mut self, id: &[u8; 16]) -> Option<&mut HistoryEntry> {
        if *id == [0; 16] {
            return None;
        }
        self.history.iter_mut().rev().find(|e| e.id == *id)
    }

    pub fn apply(&mut self, mine: bool, op: &MsgOp, ttl: u32, keep: bool) -> OpEffect {
        if let (true, MsgOp::Message { id, .. }) = (mine, op) {
            if let Some(e) = self.entry_mut(id) {
                e.delivered = true;
                return OpEffect::Changed;
            }
        }
        let expires_at = (ttl > 0).then(|| now_secs() + ttl as u64);
        let effect = apply_op_to(&mut self.history, mine, op, expires_at, keep);
        trim(&mut self.history);
        effect
    }
}

fn trim(history: &mut Vec<HistoryEntry>) {
    if history.len() > MAX_HISTORY {
        let excess = history.len() - MAX_HISTORY;
        history.drain(..excess);
    }
}

pub fn apply_op_to(
    history: &mut Vec<HistoryEntry>,
    mine: bool,
    op: &MsgOp,
    expires_at: Option<u64>,
    keep: bool,
) -> OpEffect {
    let side = if mine { Direction::Out } else { Direction::In };
    let find = |history: &mut Vec<HistoryEntry>, id: &[u8; 16]| -> Option<usize> {
        if *id == [0; 16] {
            return None;
        }
        history.iter().rposition(|e| e.id == *id)
    };
    match op {
        MsgOp::Message { id, text, reply_to } => {
            if !keep {
                return OpEffect::Added;
            }
            if find(history, id).is_some() {
                return OpEffect::Ignored;
            }
            let mut e = HistoryEntry::new(side, text.clone(), true, expires_at);
            e.id = *id;
            e.reply_to = *reply_to;
            history.push(e);
            OpEffect::Added
        }
        MsgOp::React { target, emoji } => match find(history, target) {
            Some(i) if !history[i].deleted => {
                let from = if mine { None } else { Some(PEER) };
                set_reaction(&mut history[i].reactions, from, emoji);
                OpEffect::Changed
            }
            _ => OpEffect::Ignored,
        },
        MsgOp::Edit { target, text } => match find(history, target) {
            Some(i) if history[i].dir == side && !history[i].deleted => {
                let e = &mut history[i];
                e.text.zeroize();
                e.text = text.clone();
                e.edited = true;
                OpEffect::Changed
            }
            _ => OpEffect::Ignored,
        },
        MsgOp::Delete { target } => match find(history, target) {
            Some(i) if history[i].dir == side => {
                let e = &mut history[i];
                erase_entry(&mut e.text, &mut e.reactions, &mut e.deleted);
                OpEffect::Changed
            }
            _ => OpEffect::Ignored,
        },
    }
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Contact(#{})", self.local_id)
    }
}

impl Contact {
    pub fn push_history(&mut self, e: HistoryEntry) -> usize {
        self.history.push(e);
        if self.history.len() > MAX_HISTORY {
            let excess = self.history.len() - MAX_HISTORY;
            self.history.drain(..excess);
        }
        self.history.len() - 1
    }

    pub fn entry_mut(&mut self, id: &[u8; 16]) -> Option<&mut HistoryEntry> {
        if *id == [0; 16] {
            return None;
        }
        self.history.iter_mut().rev().find(|e| e.id == *id)
    }

    pub fn apply_peer_op(&mut self, op: &MsgOp, keep: bool) -> OpEffect {
        let expires_at = self.timer.map(|t| now_secs() + t as u64);
        let effect = apply_op_to(&mut self.history, false, op, expires_at, keep);
        trim(&mut self.history);
        effect
    }
}

pub const PEER: [u8; 32] = [0; 32];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpEffect {
    Added,
    Changed,
    Ignored,
}

pub fn set_reaction(reactions: &mut Vec<Reaction>, from: Option<[u8; 32]>, emoji: &str) {
    reactions.retain(|r| r.from != from);
    if !emoji.is_empty() {
        reactions.push(Reaction {
            from,
            emoji: emoji.to_string(),
        });
    }
}

fn erase_entry(text: &mut String, reactions: &mut Vec<Reaction>, deleted: &mut bool) {
    text.zeroize();
    text.clear();
    reactions.zeroize();
    reactions.clear();
    *deleted = true;
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OutboxItem {
    pub contact: u32,

    #[serde(with = "serde_bytes")]
    pub frame: Vec<u8>,

    pub history_index: Option<usize>,

    #[serde(default)]
    pub history_id: Option<[u8; 16]>,

    pub deposited: bool,
}
redacted_debug!(HistoryEntry, Session, OutboxItem, PeerMailbox);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MyMailbox {
    pub host_contact: u32,
    pub onion_key: [u8; 32],
    pub auth_secret: [u8; 32],
    pub fetch_key: [u8; 32],
}

impl MyMailbox {
    pub fn deposit_id(&self) -> [u8; 32] {
        deposit_id(&self.fetch_key)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HostedMailbox {
    pub slot: u32,
    pub owner: u32,

    pub deposit_id: Option<[u8; 32]>,
    pub frames: Vec<Vec<u8>>,
}
redacted_debug!(MyMailbox, HostedMailbox);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IncomingFile {
    pub contact: u32,
    pub file_id: [u8; 16],
    pub name: String,
    pub size: u64,
    pub hash: [u8; 32],
    pub chunks: Vec<Option<Vec<u8>>>,
}

impl IncomingFile {
    pub fn received(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredFile {
    pub local_id: u32,
    pub contact: u32,
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Group {
    pub local_id: u32,
    pub group_id: [u8; 16],

    pub hub: Option<u32>,

    pub members: Vec<u32>,

    pub member_fps: Vec<[u8; 32]>,
    pub history: Vec<GroupEntry>,

    #[serde(default)]
    pub member_keys: Vec<MemberKey>,

    #[serde(default)]
    pub my_sender: Option<SenderKey>,

    #[serde(default)]
    pub senders: Vec<PeerSender>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct MemberKey {
    pub fp: [u8; 32],
    pub public: Vec<u8>,
}
redacted_debug!(MemberKey);

impl Group {
    pub fn new(local_id: u32, group_id: [u8; 16], hub: Option<u32>) -> Self {
        Self {
            local_id,
            group_id,
            hub,
            members: Vec::new(),
            member_fps: Vec::new(),
            history: Vec::new(),
            member_keys: Vec::new(),
            my_sender: None,
            senders: Vec::new(),
        }
    }

    pub fn set_member_key(&mut self, public: &IdentityPublic) -> bool {
        let fp = public.fingerprint();
        if public.validate().is_err() || !self.member_fps.contains(&fp) {
            return false;
        }
        self.member_keys.retain(|k| k.fp != fp);
        self.member_keys.push(MemberKey {
            fp,
            public: public.to_bytes(),
        });
        true
    }

    pub fn member_public(&self, fp: &[u8; 32]) -> Option<IdentityPublic> {
        let k = self.member_keys.iter().find(|k| k.fp == *fp)?;
        IdentityPublic::from_bytes(&k.public).ok()
    }

    pub fn set_members(&mut self, fps: Vec<[u8; 32]>) {
        let someone_left = self.member_fps.iter().any(|f| !fps.contains(f));
        self.member_fps = fps;
        if someone_left {
            let fps = &self.member_fps;
            self.member_keys.retain(|k| fps.contains(&k.fp));
            self.senders.retain(|s| fps.contains(&s.author));
            self.my_sender = None;
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupEntry {
    pub author: [u8; 32],
    pub text: String,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub id: [u8; 16],
    #[serde(default)]
    pub reply_to: Option<[u8; 16]>,
    #[serde(default)]
    pub reactions: Vec<Reaction>,
    #[serde(default)]
    pub edited: bool,
    #[serde(default)]
    pub deleted: bool,
}

impl GroupEntry {
    pub fn new(author: [u8; 32], text: String, expires_at: Option<u64>) -> Self {
        Self {
            author,
            text,
            expires_at,
            id: [0; 16],
            reply_to: None,
            reactions: Vec::new(),
            edited: false,
            deleted: false,
        }
    }
}

impl Group {
    pub fn entry_mut(&mut self, id: &[u8; 16]) -> Option<&mut GroupEntry> {
        if *id == [0; 16] {
            return None;
        }
        self.history.iter_mut().rev().find(|e| e.id == *id)
    }

    pub fn apply_op(&mut self, author: [u8; 32], mine: bool, op: &MsgOp, keep: bool) -> OpEffect {
        let from = if mine { None } else { Some(author) };
        match op {
            MsgOp::Message { id, text, reply_to } => {
                if !keep || (*id != [0; 16] && self.entry_mut(id).is_some()) {
                    return if keep {
                        OpEffect::Ignored
                    } else {
                        OpEffect::Added
                    };
                }
                let mut e = GroupEntry::new(author, text.clone(), None);
                e.id = *id;
                e.reply_to = *reply_to;
                self.history.push(e);
                if self.history.len() > MAX_HISTORY {
                    let excess = self.history.len() - MAX_HISTORY;
                    self.history.drain(..excess);
                }
                OpEffect::Added
            }
            MsgOp::React { target, emoji } => match self.entry_mut(target) {
                Some(e) if !e.deleted => {
                    set_reaction(&mut e.reactions, from, emoji);
                    OpEffect::Changed
                }
                _ => OpEffect::Ignored,
            },
            MsgOp::Edit { target, text } => match self.entry_mut(target) {
                Some(e) if e.author == author && !e.deleted => {
                    e.text.zeroize();
                    e.text = text.clone();
                    e.edited = true;
                    OpEffect::Changed
                }
                _ => OpEffect::Ignored,
            },
            MsgOp::Delete { target } => match self.entry_mut(target) {
                Some(e) if e.author == author => {
                    erase_entry(&mut e.text, &mut e.reactions, &mut e.deleted);
                    OpEffect::Changed
                }
                _ => OpEffect::Ignored,
            },
        }
    }
}
redacted_debug!(IncomingFile, StoredFile, Group, GroupEntry);

pub const MAX_STORED_BYTES: usize = 16 * 1024 * 1024;

pub fn deposit_id(fetch_key: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[b"LyctaCrypt/mailbox/deposit", fetch_key])
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct State {
    pub identity: Identity,
    pub contacts: Vec<Contact>,
    pub slots: Vec<Slot>,
    pub outbox: Vec<OutboxItem>,

    pub seen: Vec<[u8; 32]>,
    pub next_local_id: u32,
    pub next_slot_id: u32,

    pub keep_history: bool,
    pub cover: CoverMode,
    pub my_mailbox: Option<MyMailbox>,

    pub mailbox_pending_host: Option<u32>,
    pub hosted: Vec<HostedMailbox>,

    pub mailbox_requests: Vec<u32>,
    pub incoming_files: Vec<IncomingFile>,
    pub files: Vec<StoredFile>,
    pub next_file_id: u32,
    pub groups: Vec<Group>,
    pub next_group_id: u32,

    #[serde(default)]
    pub device_requests: Vec<u32>,

    #[serde(default)]
    pub primary: Option<u32>,

    #[serde(default)]
    pub primary_pending: Option<u32>,

    #[serde(default)]
    pub mirrors: Vec<Mirror>,
    #[serde(default)]
    pub next_mirror_id: u32,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State({} contacts)", self.contacts.len())
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            identity: Identity::generate(),
            contacts: Vec::new(),
            slots: Vec::new(),
            outbox: Vec::new(),
            seen: Vec::new(),
            next_local_id: 1,
            next_slot_id: 1,
            keep_history: true,
            cover: CoverMode::Low,
            my_mailbox: None,
            mailbox_pending_host: None,
            hosted: Vec::new(),
            mailbox_requests: Vec::new(),
            incoming_files: Vec::new(),
            files: Vec::new(),
            next_file_id: 1,
            groups: Vec::new(),
            next_group_id: 1,
            device_requests: Vec::new(),
            primary: None,
            primary_pending: None,
            mirrors: Vec::new(),
            next_mirror_id: 1,
        }
    }

    pub fn devices(&self) -> Vec<u32> {
        self.contacts
            .iter()
            .filter(|c| c.own_device && !c.blocked)
            .map(|c| c.local_id)
            .collect()
    }

    pub fn mirror_for(&mut self, fp: &[u8; 32]) -> &mut Mirror {
        if let Some(pos) = self.mirrors.iter().position(|m| m.fp == *fp) {
            return &mut self.mirrors[pos];
        }
        let local_id = self.next_mirror_id.max(1);
        self.next_mirror_id = local_id + 1;
        self.mirrors.push(Mirror {
            local_id,
            fp: *fp,
            note: None,
            history: Vec::new(),
        });
        self.mirrors.last_mut().expect("just pushed")
    }

    pub fn mirror_by_local(&mut self, id: u32) -> Option<&mut Mirror> {
        self.mirrors.iter_mut().find(|m| m.local_id == id)
    }

    pub fn unlink_device(&mut self, contact: u32) {
        if let Some(c) = self.contact_by_local(contact) {
            c.own_device = false;
        }
        self.device_requests.retain(|&r| r != contact);
        if self.primary_pending == Some(contact) {
            self.primary_pending = None;
        }
        if self.primary == Some(contact) {
            self.primary = None;
            self.mirrors.clear();
        }
    }

    pub fn stored_bytes(&self) -> usize {
        self.files.iter().map(|f| f.data.len()).sum::<usize>()
            + self
                .incoming_files
                .iter()
                .map(|f| f.size as usize)
                .sum::<usize>()
    }

    pub fn group_by_gid(&mut self, gid: &[u8; 16]) -> Option<&mut Group> {
        self.groups.iter_mut().find(|g| &g.group_id == gid)
    }

    pub fn group_by_local(&mut self, id: u32) -> Option<&mut Group> {
        self.groups.iter_mut().find(|g| g.local_id == id)
    }

    pub fn prepare_restore(&mut self) {
        for c in &mut self.contacts {
            c.session = None;
        }
        self.outbox.clear();
        self.seen.clear();
    }

    pub fn contact_by_fp(&mut self, fp: &[u8; 32]) -> Option<&mut Contact> {
        self.contacts
            .iter_mut()
            .find(|c| &c.public.fingerprint() == fp)
    }

    pub fn contact_by_local(&mut self, id: u32) -> Option<&mut Contact> {
        self.contacts.iter_mut().find(|c| c.local_id == id)
    }

    pub fn contact_by_session(&mut self, sid: &SessionId) -> Option<&mut Contact> {
        self.contacts
            .iter_mut()
            .find(|c| c.session.as_ref().is_some_and(|s| &s.id == sid))
    }

    pub fn slot(&mut self, id: u32) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|s| s.id == id)
    }

    pub fn new_slot(&mut self, authorized_client: [u8; 32], kind: SlotKind) -> u32 {
        let id = self.next_slot_id;
        self.next_slot_id += 1;
        self.slots.push(Slot {
            id,
            hs_seed: random_bytes(),
            onion_key: None,
            authorized_client,
            invite_auth_secret: None,
            kind,
        });
        id
    }

    pub fn add_contact(&mut self, public: IdentityPublic, origin: Origin) -> u32 {
        let fp = public.fingerprint();
        if let Some(c) = self.contact_by_fp(&fp) {
            return c.local_id;
        }
        let local_id = self.next_local_id;
        self.next_local_id += 1;
        self.contacts.push(Contact {
            local_id,
            public,
            origin,
            accepted: origin == Origin::Invite,
            blocked: false,
            note: None,
            session: None,
            my_slot: None,
            peer_onion: None,
            peer_auth: None,
            timer: None,
            mailbox: None,
            history: Vec::new(),
            own_device: false,
        });
        local_id
    }

    pub fn remove_contact(&mut self, id: u32) {
        self.contacts.retain(|c| c.local_id != id);
        self.outbox.retain(|o| o.contact != id);
        self.slots
            .retain(|s| s.kind != SlotKind::Contact(id) && s.kind != SlotKind::Mailbox(id));
        self.hosted.retain(|h| h.owner != id);
        self.mailbox_requests.retain(|&r| r != id);
        self.unlink_device(id);
        self.incoming_files.retain(|f| f.contact != id);
        self.groups.retain(|g| g.hub != Some(id));
        for g in &mut self.groups {
            g.members.retain(|&m| m != id);
        }
        if self
            .my_mailbox
            .as_ref()
            .is_some_and(|m| m.host_contact == id)
        {
            self.my_mailbox = None;
        }
    }

    pub fn is_seen(&self, frame_bytes: &[u8]) -> bool {
        self.seen
            .contains(&sha3_256(&[b"LyctaCrypt/seen", frame_bytes]))
    }

    pub fn check_and_mark_seen(&mut self, frame_bytes: &[u8]) -> bool {
        let h = sha3_256(&[b"LyctaCrypt/seen", frame_bytes]);
        if self.seen.contains(&h) {
            return true;
        }
        self.seen.push(h);
        if self.seen.len() > MAX_SEEN {
            self.seen.remove(0);
        }
        false
    }

    pub fn purge_history(&mut self) {
        for c in &mut self.contacts {
            c.history.clear();
        }
        for g in &mut self.groups {
            g.history.clear();
        }
        for m in &mut self.mirrors {
            m.history.clear();
        }
    }

    pub fn expire_history(&mut self, now: u64) -> usize {
        let mut n = 0;
        for c in &mut self.contacts {
            let before = c.history.len();
            c.history.retain(|h| h.expires_at.is_none_or(|t| t > now));
            n += before - c.history.len();
        }
        for g in &mut self.groups {
            let before = g.history.len();
            g.history.retain(|h| h.expires_at.is_none_or(|t| t > now));
            n += before - g.history.len();
        }
        for m in &mut self.mirrors {
            let before = m.history.len();
            m.history.retain(|h| h.expires_at.is_none_or(|t| t > now));
            n += before - m.history.len();
        }
        if n > 0 {
            for o in &mut self.outbox {
                o.history_index = None;
            }
        }
        n
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

fn derive_key(pass: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32)).map_err(|_| Error::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pass, salt, &mut *key)
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

const MAGIC_V3: &[u8; 8] = b"LYCTA\x00v3";

pub const MAX_SLOTS: usize = 6;

pub struct VaultKey {
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,

    index: usize,

    slots: Vec<Vec<u8>>,
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(<secret>)")
    }
}

fn random_index(n: usize) -> usize {
    use rand::Rng;
    rand::thread_rng().gen_range(0..n)
}

fn filler() -> Vec<u8> {
    use rand::{Rng, RngCore};
    let len = SALT_LEN + 24 + 16 + rand::thread_rng().gen_range(8 * 1024..96 * 1024);
    let mut v = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

impl VaultKey {
    pub fn create(pass: &[u8]) -> Result<Self> {
        let salt: [u8; SALT_LEN] = random_bytes();
        let key = derive_key(pass, &salt)?;
        let fillers = 1 + random_index(2);
        let mut slots: Vec<Vec<u8>> = (0..fillers).map(|_| filler()).collect();
        let index = random_index(fillers + 1);
        slots.insert(index, Vec::new());
        Ok(Self {
            salt,
            key,
            index,
            slots,
        })
    }

    pub fn slots_snapshot(&self) -> Vec<Vec<u8>> {
        self.slots.clone()
    }

    pub fn insert_slot(&mut self, slot: Vec<u8>) -> Result<()> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(Error::Malformed);
        }
        let pos = random_index(self.slots.len() + 1);
        self.slots.insert(pos, slot);
        if pos <= self.index {
            self.index += 1;
        }
        Ok(())
    }
}

fn seal_slot(state: &State, salt: &[u8; SALT_LEN], key: &[u8; 32]) -> Result<Vec<u8>> {
    let pt = encode_state(state)?;
    let mut out = Vec::with_capacity(SALT_LEN + pt.len() + 64);
    out.extend_from_slice(salt);
    out.extend_from_slice(&seal(key, MAGIC_V3, &pt));
    Ok(out)
}

fn encode_file(slots: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = slots.iter().map(|s| s.len() + 4).sum();
    let mut out = Vec::with_capacity(MAGIC_V3.len() + 1 + total);
    out.extend_from_slice(MAGIC_V3);
    out.push(slots.len() as u8);
    for s in slots {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }
    out
}

fn parse_file(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    if bytes.len() < MAGIC_V3.len() + 1 || &bytes[..MAGIC_V3.len()] != MAGIC_V3 {
        return Err(Error::VaultDecrypt);
    }
    let n = bytes[MAGIC_V3.len()] as usize;
    if n == 0 || n > MAX_SLOTS {
        return Err(Error::VaultDecrypt);
    }
    let mut pos = MAGIC_V3.len() + 1;
    let mut slots = Vec::with_capacity(n);
    for _ in 0..n {
        let len_bytes = bytes.get(pos..pos + 4).ok_or(Error::VaultDecrypt)?;
        let len = u32::from_be_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
        pos += 4;
        let s = bytes.get(pos..pos + len).ok_or(Error::VaultDecrypt)?;
        slots.push(s.to_vec());
        pos += len;
    }
    Ok(slots)
}

type Opened = (State, [u8; SALT_LEN], Zeroizing<[u8; 32]>);

type OpenedAt = (usize, State, [u8; SALT_LEN], Zeroizing<[u8; 32]>);

fn try_slots(slots: &[Vec<u8>], pass: &[u8]) -> Result<Option<OpenedAt>> {
    let results: Vec<Option<Opened>> = std::thread::scope(|s| {
        let handles: Vec<_> = slots
            .iter()
            .map(|slot| {
                s.spawn(move || {
                    if slot.len() < SALT_LEN + 24 + 16 {
                        return None;
                    }
                    let mut salt = [0u8; SALT_LEN];
                    salt.copy_from_slice(&slot[..SALT_LEN]);
                    let key = derive_key(pass, &salt).ok()?;
                    let pt = open(&key, MAGIC_V3, &slot[SALT_LEN..]).ok()?;
                    let state: State = decode_state(&pt).ok()?;
                    Some((state, salt, key))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().ok().flatten())
            .collect()
    });
    Ok(results
        .into_iter()
        .enumerate()
        .find_map(|(i, r)| r.map(|(st, salt, key)| (i, st, salt, key))))
}

fn open_v2(bytes: &[u8], pass: &[u8]) -> Result<(State, VaultKey)> {
    if bytes.len() < MAGIC.len() + SALT_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::VaultDecrypt);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    let key = derive_key(pass, &salt)?;
    let pt =
        open(&key, MAGIC, &bytes[MAGIC.len() + SALT_LEN..]).map_err(|_| Error::VaultDecrypt)?;
    let state = decode_state(&pt)?;

    let index = random_index(2);
    let mut slots = vec![filler()];
    slots.insert(index, Vec::new());
    Ok((
        state,
        VaultKey {
            salt,
            key,
            index,
            slots,
        },
    ))
}

pub fn seal_state(state: &State, vk: &VaultKey) -> Result<Vec<u8>> {
    let mine = seal_slot(state, &vk.salt, &vk.key)?;
    let mut slots = vk.slots.clone();
    slots[vk.index] = mine;
    Ok(encode_file(&slots))
}

pub fn open_state(bytes: &[u8], pass: &[u8]) -> Result<(State, VaultKey)> {
    if bytes.starts_with(MAGIC) {
        return open_v2(bytes, pass);
    }
    let slots = parse_file(bytes)?;
    match try_slots(&slots, pass)? {
        Some((index, state, salt, key)) => Ok((
            state,
            VaultKey {
                salt,
                key,
                index,
                slots,
            },
        )),
        None => Err(Error::VaultDecrypt),
    }
}

pub fn check_pass_unused(slots: &[Vec<u8>], pass: &[u8]) -> Result<bool> {
    Ok(try_slots(slots, pass)?.is_none())
}

pub fn seal_new_slot(state: &State, pass: &[u8]) -> Result<Vec<u8>> {
    let salt: [u8; SALT_LEN] = random_bytes();
    let key = derive_key(pass, &salt)?;
    seal_slot(state, &salt, &key)
}

pub fn save(path: &Path, state: &State, vk: &VaultKey) -> Result<()> {
    let data = seal_state(state, vk)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn backup(path: &Path, state: &State, backup_pass: &[u8]) -> Result<()> {
    let vk = VaultKey::create(backup_pass)?;
    save(path, state, &vk)
}

pub fn load(path: &Path, pass: &[u8]) -> Result<(State, VaultKey)> {
    let data = Zeroizing::new(fs::read(path)?);
    open_state(&data, pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip_and_wrong_pass() {
        let mut st = State::new();
        let slot = st.new_slot([5u8; 32], SlotKind::Invite);
        let vk = VaultKey::create(b"correct horse").unwrap();
        let sealed = seal_state(&st, &vk).unwrap();
        let (mut back, _) = open_state(&sealed, b"correct horse").unwrap();
        assert_eq!(back.slot(slot).unwrap().authorized_client, [5u8; 32]);
        assert!(open_state(&sealed, b"wrong").is_err());
    }

    #[test]
    fn decoy_slot_is_separate_and_never_overwrites() {
        let mut real = State::new();
        real.add_contact(Identity::generate().public(), Origin::Invite);
        let mut vk = VaultKey::create(b"vraie phrase de passe").unwrap();
        let file = seal_state(&real, &vk).unwrap();
        let n_before = parse_file(&file).unwrap().len();

        let slots = parse_file(&file).unwrap();
        assert!(!check_pass_unused(&slots, b"vraie phrase de passe").unwrap());
        assert!(check_pass_unused(&slots, b"decoy passphrase").unwrap());

        let decoy = crate::decoy::populate(3, true);
        let decoy_fp = decoy.identity.public().fingerprint();
        vk.insert_slot(seal_new_slot(&decoy, b"decoy passphrase").unwrap())
            .unwrap();
        let file = seal_state(&real, &vk).unwrap();
        assert_eq!(parse_file(&file).unwrap().len(), n_before + 1);

        let (r, _) = open_state(&file, b"vraie phrase de passe").unwrap();
        assert_eq!(r.identity.public(), real.identity.public());
        let (mut d, dvk) = open_state(&file, b"decoy passphrase").unwrap();
        assert_eq!(d.identity.public().fingerprint(), decoy_fp);
        assert_eq!(d.contacts.len(), 3);
        assert!(open_state(&file, b"mauvaise").is_err());

        d.purge_history();
        let file2 = seal_state(&d, &dvk).unwrap();
        let (r2, _) = open_state(&file2, b"vraie phrase de passe").unwrap();
        assert_eq!(r2.contacts.len(), 1);
        assert_eq!(r2.identity.public(), real.identity.public());
    }

    #[test]
    fn migrates_v2_vault() {
        let st = State::new();
        let salt: [u8; SALT_LEN] = random_bytes();
        let key = derive_key(b"old passphrase", &salt).unwrap();

        let pt = crate::legacy::sample_bytes(&st.identity);
        let mut v2 = MAGIC.to_vec();
        v2.extend_from_slice(&salt);
        v2.extend_from_slice(&seal(&key, MAGIC, &pt));

        let (back, vk) = open_state(&v2, b"old passphrase").unwrap();
        assert_eq!(back.contacts.len(), 1);

        let v3 = seal_state(&back, &vk).unwrap();
        assert!(v3.starts_with(MAGIC_V3));
        assert!(parse_file(&v3).unwrap().len() >= 2);
        let (again, _) = open_state(&v3, b"old passphrase").unwrap();
        assert_eq!(again.identity.public(), st.identity.public());
    }

    #[test]
    fn max_slots_enforced() {
        let mut vk = VaultKey::create(b"x").unwrap();
        while vk.slots.len() < MAX_SLOTS {
            vk.insert_slot(filler()).unwrap();
        }
        assert!(vk.insert_slot(filler()).is_err());
    }

    #[test]
    fn seen_dedup() {
        let mut st = State::new();
        assert!(!st.check_and_mark_seen(b"x"));
        assert!(st.check_and_mark_seen(b"x"));
    }

    #[test]
    fn expiry() {
        let mut st = State::new();
        let id = st.add_contact(Identity::generate().public(), Origin::Invite);
        let c = st.contact_by_local(id).unwrap();
        c.push_history(HistoryEntry::new(Direction::In, "a".into(), true, Some(10)));
        c.push_history(HistoryEntry::new(Direction::In, "b".into(), true, None));
        assert_eq!(st.expire_history(11), 1);
        assert_eq!(st.contact_by_local(id).unwrap().history.len(), 1);
    }

    #[test]
    fn peer_ops_only_touch_their_own_messages() {
        let mut st = State::new();
        let id = st.add_contact(Identity::generate().public(), Origin::Invite);
        let c = st.contact_by_local(id).unwrap();
        let mut mine = HistoryEntry::new(Direction::Out, "mine".into(), true, None);
        mine.id = [1; 16];
        c.push_history(mine);
        let msg = MsgOp::Message {
            id: [2; 16],
            text: "theirs".into(),
            reply_to: Some([1; 16]),
        };
        assert_eq!(c.apply_peer_op(&msg, true), OpEffect::Added);
        assert_eq!(
            c.apply_peer_op(&msg, true),
            OpEffect::Ignored,
            "no duplicates"
        );
        assert_eq!(c.history[1].reply_to, Some([1; 16]));

        assert_eq!(
            c.apply_peer_op(
                &MsgOp::Edit {
                    target: [1; 16],
                    text: "x".into()
                },
                true
            ),
            OpEffect::Ignored
        );
        assert_eq!(
            c.apply_peer_op(&MsgOp::Delete { target: [1; 16] }, true),
            OpEffect::Ignored
        );
        assert_eq!(c.history[0].text, "mine");

        c.apply_peer_op(
            &MsgOp::React {
                target: [1; 16],
                emoji: "👍".into(),
            },
            true,
        );
        c.apply_peer_op(
            &MsgOp::React {
                target: [1; 16],
                emoji: "❤".into(),
            },
            true,
        );
        assert_eq!(c.history[0].reactions.len(), 1);
        assert_eq!(c.history[0].reactions[0].emoji, "❤");
        c.apply_peer_op(
            &MsgOp::React {
                target: [1; 16],
                emoji: String::new(),
            },
            true,
        );
        assert!(c.history[0].reactions.is_empty());

        c.apply_peer_op(
            &MsgOp::Edit {
                target: [2; 16],
                text: "edited".into(),
            },
            true,
        );
        assert!(c.history[1].edited && c.history[1].text == "edited");
        c.apply_peer_op(&MsgOp::Delete { target: [2; 16] }, true);
        assert!(c.history[1].deleted && c.history[1].text.is_empty());
    }

    #[test]
    fn group_ops_check_the_author() {
        let mut g = Group::new(1, [0; 16], None);
        let (a, b) = ([1; 32], [2; 32]);
        g.apply_op(
            a,
            false,
            &MsgOp::Message {
                id: [5; 16],
                text: "a".into(),
                reply_to: None,
            },
            true,
        );
        assert_eq!(
            g.apply_op(b, false, &MsgOp::Delete { target: [5; 16] }, true),
            OpEffect::Ignored
        );
        assert_eq!(
            g.apply_op(a, false, &MsgOp::Delete { target: [5; 16] }, true),
            OpEffect::Changed
        );
        assert!(g.history[0].deleted);
    }

    #[test]
    fn backup_restore() {
        let dir =
            std::env::temp_dir().join(format!("lycta-test-{}", u64::from_le_bytes(random_bytes())));
        std::fs::create_dir_all(&dir).unwrap();
        let mut st = State::new();
        let id = st.add_contact(Identity::generate().public(), Origin::Invite);
        st.outbox.push(OutboxItem {
            contact: id,
            frame: vec![1],
            history_index: None,
            history_id: None,
            deposited: false,
        });
        let path = dir.join("backup.lycta");
        backup(&path, &st, b"autre phrase de passe").unwrap();
        let (mut back, _) = load(&path, b"autre phrase de passe").unwrap();
        back.prepare_restore();
        assert_eq!(back.contacts.len(), 1);
        assert!(back.outbox.is_empty());
        assert_eq!(back.identity.public(), st.identity.public());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_contact_drops_its_slots() {
        let mut st = State::new();
        let id = st.add_contact(Identity::generate().public(), Origin::Invite);
        st.new_slot([1; 32], SlotKind::Contact(id));
        st.new_slot([2; 32], SlotKind::Invite);
        st.remove_contact(id);
        assert_eq!(st.slots.len(), 1);
        assert!(st.contacts.is_empty());
    }
}
