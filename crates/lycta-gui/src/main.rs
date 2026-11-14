#![deny(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "demo")]
mod demo;
mod media;
mod scan;
mod system;
mod theme;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Vec2};
use tokio::sync::mpsc::UnboundedReceiver;
use zeroize::Zeroizing;

use lycta_core::identity::{safety_code, short_fingerprint};
use lycta_core::vault::{self, CoverMode, Direction, State, VaultKey};
use lycta_core::wire::MsgOp;
use lycta_node::node::{Event, Node};
use lycta_node::tor::{self, TorOptions};
use lycta_node::{bridges, hardening, qr, update};

use theme::{avatar, bubble, Palette};

fn main() -> eframe::Result<()> {
    let _ = hardening::apply();
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );
    let mut data_dir = dirs::data_local_dir()
        .map(|d| d.join("LyctaCrypt"))
        .unwrap_or_else(|| PathBuf::from("LyctaCrypt"));
    #[allow(unused_mut)]
    let mut demo: Option<(String, PathBuf, [f32; 2])> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => {
                if let Some(d) = args.next() {
                    data_dir = PathBuf::from(d);
                }
            }
            #[cfg(feature = "demo")]
            "--demo" => {
                let view = args.next().unwrap_or_else(|| "welcome".into());
                let out = PathBuf::from(args.next().unwrap_or_else(|| "capture.png".into()));
                let w: f32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1080.0);
                let h: f32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(720.0);
                demo = Some((view, out, [w, h]));
            }
            _ => {}
        }
    }
    let size = demo.as_ref().map(|d| d.2).unwrap_or([1080.0, 720.0]);
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("LyctaCrypt")
        .with_decorations(false)
        .with_inner_size(size)
        .with_min_inner_size([760.0, 500.0]);
    if let Some(icon) = theme::window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "LyctaCrypt",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            #[allow(unused_mut)]
            let mut app = App::new(rt, data_dir);
            #[cfg(feature = "demo")]
            if let Some((view, out, _)) = demo {
                app.setup_demo(&view, out);
            }
            #[cfg(not(feature = "demo"))]
            let _ = demo;
            app.init_system(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
}

enum Msg {
    Ready(Arc<Node>, UnboundedReceiver<Event>),
    Failed(String),
    DeviceProtectionUnavailable,
    UnlockRejected,
    Info(String),
    Silent,
    Invite(String),
    ContactAdded(u32),

    Update(Option<update::Manifest>),
    UpdateInstalled(String),
}

enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    Available(update::Manifest),
    Installing,
    Installed(String),
}

type MirrorRow = (u32, [u8; 32], Option<String>, Option<String>);

type ContactRow = (
    u32,
    [u8; 32],
    String,
    Option<String>,
    bool,
    bool,
    Option<String>,
);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Target {
    Contact(u32),
    Group(u32),

    Mirror(u32),
}

enum Screen {
    Unlock,
    Connecting(Instant),
    Main,
}

#[derive(PartialEq)]
enum Tone {
    Info,
    Ok,
    Warn,
}

struct Toast {
    text: String,
    tone: Tone,
    until: Instant,
}

#[derive(Clone)]
struct Compose {
    target: Target,
    id: [u8; 16],
    edit: bool,
    preview: String,
}

struct MsgRow {
    id: [u8; 16],
    out: bool,

    author: Option<[u8; 32]>,
    text: String,
    delivered: bool,
    quote: Option<String>,
    reactions: Vec<(String, usize, bool)>,
    edited: bool,
    deleted: bool,

    attachment: Option<(u32, vault::AttachmentKind)>,
}

const REACTIONS: &[&str] = &["👍", "❤", "🔥", "🎉", "💯", "👎"];

fn tally(reactions: &[vault::Reaction]) -> Vec<(String, usize, bool)> {
    let mut out: Vec<(String, usize, bool)> = Vec::new();
    for r in reactions {
        match out.iter_mut().find(|(e, _, _)| *e == r.emoji) {
            Some(t) => {
                t.1 += 1;
                t.2 |= r.from.is_none();
            }
            None => out.push((r.emoji.clone(), 1, r.from.is_none())),
        }
    }
    out
}

fn quote_of<'a>(
    mut find: impl FnMut(&[u8; 16]) -> Option<(&'a str, bool)>,
    id: Option<[u8; 16]>,
) -> Option<String> {
    let id = id?;
    Some(match find(&id) {
        Some((_, true)) => "Message deleted".into(),
        Some((t, false)) => t.to_string(),
        None => "Original message unavailable".into(),
    })
}

fn contact_rows(ct: &vault::Contact) -> Vec<MsgRow> {
    history_rows(&ct.history)
}

fn history_rows(history: &[vault::HistoryEntry]) -> Vec<MsgRow> {
    history
        .iter()
        .map(|h| MsgRow {
            id: h.id,
            out: h.dir == Direction::Out,
            author: None,
            attachment: h
                .attachment
                .as_ref()
                .filter(|_| !h.deleted)
                .map(|a| (a.file, a.kind)),
            text: match &h.attachment {
                Some(a) if a.kind == vault::AttachmentKind::Audio => "Voice note".into(),
                Some(a) => a.name.clone(),
                None => h.text.clone(),
            },
            delivered: h.delivered,
            quote: quote_of(
                |id| {
                    history
                        .iter()
                        .find(|e| e.id == *id)
                        .map(|e| (e.text.as_str(), e.deleted))
                },
                h.reply_to,
            ),
            reactions: tally(&h.reactions),
            edited: h.edited,
            deleted: h.deleted,
        })
        .collect()
}

fn group_rows(g: &vault::Group, me: &[u8; 32]) -> Vec<MsgRow> {
    g.history
        .iter()
        .map(|h| MsgRow {
            id: h.id,
            out: h.author == *me,
            author: (h.author != *me).then_some(h.author),
            attachment: None,
            text: h.text.clone(),
            delivered: true,
            quote: quote_of(
                |id| {
                    g.history
                        .iter()
                        .find(|e| e.id == *id)
                        .map(|e| (e.text.as_str(), e.deleted))
                },
                h.reply_to,
            ),
            reactions: tally(&h.reactions),
            edited: h.edited,
            deleted: h.deleted,
        })
        .collect()
}

struct Live {
    out: bool,
    text: String,
}

struct App {
    rt: Arc<tokio::runtime::Runtime>,
    data_dir: PathBuf,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    screen: Screen,
    node: Option<Arc<Node>>,
    events: Option<UnboundedReceiver<Event>>,

    pass: Zeroizing<String>,
    pass2: Zeroizing<String>,
    show_pass: bool,
    unlock_error: Option<String>,
    failed_unlocks: u32,
    unlock_allowed_at: Option<Instant>,

    target: Option<Target>,
    input: String,

    compose: Option<Compose>,
    update: UpdateState,
    bridges_open: bool,
    bridge_lines: String,
    bridge_program: Option<PathBuf>,

    #[cfg_attr(not(feature = "demo"), allow(dead_code))]
    demo_click: bool,
    search: String,
    toasts: Vec<Toast>,
    unread: HashMap<Target, usize>,

    textures: HashMap<u32, Option<egui::TextureHandle>>,
    scanner: Option<scan::Scanner>,
    scan_tex: Option<egui::TextureHandle>,

    verify_result: Option<bool>,
    recorder: Option<media::Recorder>,
    record_target: Option<u32>,
    player: Option<media::Player>,
    live: HashMap<Target, Vec<Live>>,
    invite: Option<String>,
    add_open: bool,
    add_field: String,
    verify: Option<u32>,
    group_sel: Vec<u32>,
    group_open: bool,
    settings_open: bool,
    backup_pass: Zeroizing<String>,
    timer_field: String,
    busy: usize,
    decoy_pass: Zeroizing<String>,
    decoy_pass2: Zeroizing<String>,
    decoy_contacts: usize,
    decoy_conversations: bool,

    decoy_scroll: bool,

    capture: Option<(PathBuf, u32)>,

    prefs: system::Prefs,
    last_activity: Instant,
    capture_applied: Option<bool>,
    tray: Option<system::Tray>,
    quitting: bool,
    was_minimized: bool,
    focused: bool,
    lock_requested: bool,
}

impl App {
    #[cfg(feature = "demo")]
    fn setup_demo(&mut self, view: &str, out: PathBuf) {
        self.capture = Some((out, 0));
        let dir = std::env::temp_dir().join(format!("lycta-demo-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        match view {
            "unlock" => {
                self.data_dir = dir;
                return;
            }
            "connecting" => {
                self.screen = Screen::Connecting(Instant::now() - Duration::from_secs(12));
                return;
            }
            _ => {}
        }
        let state = demo::state();
        let vk = VaultKey::create(b"demo-demo-demo").expect("key");
        let client = {
            let _g = self.rt.enter();
            tor::offline_client(&dir).expect("offline client")
        };
        let (etx, erx) = tokio::sync::mpsc::unbounded_channel();
        let node = Node::new(state, vk, dir.join(lycta_node::VAULT_FILE), client, etx);
        self.node = Some(node);
        self.events = Some(erx);
        self.screen = Screen::Main;
        self.unread.insert(Target::Contact(2), 3);
        match view {
            "chat" => self.target = Some(Target::Contact(1)),
            "menu" => {
                self.target = Some(Target::Contact(1));
                self.demo_click = true;
            }
            "reply" => {
                self.target = Some(Target::Contact(1));
                self.compose = Some(Compose {
                    target: Target::Contact(1),
                    id: [0; 16],
                    edit: false,
                    preview: "Perfect. I'm also sending Sam's voice note, it explains the route.".into(),
                });
            }
            "request" => self.target = Some(Target::Contact(3)),
            "group" => self.target = Some(Target::Group(1)),
            "settings" => {
                self.target = Some(Target::Contact(1));
                self.settings_open = true;
            }
            "invite" => self.invite = Some("lycta:ajacd3vowq7oj7glco56vz6zl5nd3krdvxp7qzeovikoixdcaokbwqxhejedyazppq7fxsvlbznxyavcjpzxha53xuqq2s7zt34o6tzqn44hqja7mxvojyvgqekhcydgm6pgz4qw4bnam4q4x3kr7tz72jfg26dvma".into()),
            "verify" => {
                self.target = Some(Target::Contact(1));
                self.verify = Some(1);
            }
            "add" => self.add_open = true,
            "bridges" => self.bridges_open = true,
            "lock" => {
                self.target = Some(Target::Contact(1));
                self.lock_requested = true;
            }
            "decoy" => {
                self.target = Some(Target::Contact(1));
                self.settings_open = true;
                self.decoy_scroll = true;
            }
            "toast" => {
                self.target = Some(Target::Contact(1));
                self.toast(Tone::Ok, "Contact #2 added");
                self.toast(Tone::Warn, "#4 rejected the session. Resend your messages.");
            }
            "empty" => {
                if let Some(n) = &self.node {
                    n.state(|st| {
                        st.contacts.clear();
                        st.groups.clear();
                        st.files.clear();
                    });
                }
                self.unread.clear();
            }
            _ => {}
        }
    }

    fn handle_capture(&mut self, ctx: &egui::Context) {
        let Some((out, frames)) = &mut self.capture else {
            return;
        };
        *frames += 1;
        if *frames == 20 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
        }
        #[cfg(feature = "demo")]
        {
            let shot = ctx.input(|i| {
                i.raw.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(img) = shot {
                let [w, h] = img.size;
                let _ = image::save_buffer(
                    out,
                    img.as_raw(),
                    w as u32,
                    h as u32,
                    image::ExtendedColorType::Rgba8,
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        let _ = out;
        ctx.request_repaint();
    }

    fn new(rt: Arc<tokio::runtime::Runtime>, data_dir: PathBuf) -> Self {
        let (tx, rx) = channel();
        Self {
            rt,
            data_dir,
            tx,
            rx,
            screen: Screen::Unlock,
            node: None,
            events: None,
            pass: Zeroizing::new(String::new()),
            pass2: Zeroizing::new(String::new()),
            show_pass: false,
            unlock_error: None,
            failed_unlocks: 0,
            unlock_allowed_at: None,
            target: None,
            input: String::new(),
            compose: None,
            update: UpdateState::Idle,
            bridges_open: false,
            bridge_lines: String::new(),
            bridge_program: None,
            demo_click: false,
            search: String::new(),
            toasts: Vec::new(),
            unread: HashMap::new(),
            textures: HashMap::new(),
            scanner: None,
            scan_tex: None,
            verify_result: None,
            recorder: None,
            record_target: None,
            player: None,
            live: HashMap::new(),
            invite: None,
            add_open: false,
            add_field: String::new(),
            verify: None,
            group_sel: Vec::new(),
            group_open: false,
            settings_open: false,
            backup_pass: Zeroizing::new(String::new()),
            timer_field: "1h".into(),
            busy: 0,
            decoy_pass: Zeroizing::new(String::new()),
            decoy_pass2: Zeroizing::new(String::new()),
            decoy_contacts: 4,
            decoy_conversations: true,
            decoy_scroll: false,
            capture: None,
            prefs: system::Prefs::default(),
            last_activity: Instant::now(),
            capture_applied: None,
            tray: None,
            quitting: false,
            was_minimized: false,
            focused: true,
            lock_requested: false,
        }
    }

    fn init_system(&mut self, ctx: &egui::Context) {
        self.prefs = system::Prefs::load(&self.data_dir);
        if self.capture.is_none() {
            if let Some((rgba, w, h)) = theme::logo_rgba() {
                self.tray = system::create_tray(ctx, rgba, w, h);
            }
        }
    }

    fn lock(&mut self) {
        if let Some(node) = self.node.take() {
            node.shutdown();
        }
        self.events = None;
        self.live.clear();
        self.textures.clear();
        self.stop_scanner();
        self.verify_result = None;
        self.recorder = None;
        self.record_target = None;
        self.player = None;
        self.compose = None;
        self.unread.clear();
        self.toasts.clear();
        self.input.clear();
        self.target = None;
        self.invite = None;
        self.verify = None;
        self.add_open = false;
        self.group_open = false;
        self.settings_open = false;
        self.busy = 0;
        self.pass = Zeroizing::new(String::new());
        self.pass2 = Zeroizing::new(String::new());
        self.unlock_error = None;
        self.screen = Screen::Unlock;
    }

    fn handle_system(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        let now = Instant::now();
        let (active, minimized, focused, close) = ctx.input(|i| {
            (
                !i.events.is_empty() || i.pointer.is_moving(),
                i.viewport().minimized.unwrap_or(false),
                i.viewport().focused.unwrap_or(true),
                i.viewport().close_requested(),
            )
        });
        self.focused = focused && !minimized;
        if active {
            self.last_activity = now;
        }
        if std::mem::take(&mut self.lock_requested) {
            self.lock();
        }
        let unlocked = matches!(self.screen, Screen::Main);
        if unlocked && self.prefs.lock_minutes > 0 {
            let idle = now.duration_since(self.last_activity);
            if idle >= Duration::from_secs(u64::from(self.prefs.lock_minutes) * 60) {
                self.lock();
            }
        }
        if unlocked && self.prefs.lock_on_minimize && minimized && !self.was_minimized {
            self.lock();
        }
        self.was_minimized = minimized;

        let (tray_lock, tray_quit) = match &self.tray {
            Some(tray) => (
                tray.flags
                    .lock
                    .swap(false, std::sync::atomic::Ordering::SeqCst),
                tray.flags.quit.load(std::sync::atomic::Ordering::SeqCst),
            ),
            None => (false, false),
        };
        if tray_lock {
            self.lock();
        }
        if tray_quit {
            self.quitting = true;
        }
        if close && self.prefs.close_to_tray && self.tray.is_some() && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        if self.capture_applied != Some(self.prefs.hide_from_capture) {
            system::set_capture_protection(frame, self.prefs.hide_from_capture);
            self.capture_applied = Some(self.prefs.hide_from_capture);
        }
    }

    fn vault_path(&self) -> PathBuf {
        lycta_node::vault_path(&self.data_dir)
    }

    fn toast(&mut self, tone: Tone, text: impl Into<String>) {
        let text = text.into();
        if text.is_empty() {
            return;
        }
        let secs = if tone == Tone::Warn { 7 } else { 3 };
        self.toasts.push(Toast {
            text,
            tone,
            until: Instant::now() + Duration::from_secs(secs),
        });
        if self.toasts.len() > 3 {
            self.toasts.remove(0);
        }
    }

    fn spawn<F, Fut>(&mut self, f: F)
    where
        F: FnOnce(Arc<Node>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Msg>> + Send + 'static,
    {
        let Some(node) = self.node.clone() else {
            return;
        };
        let tx = self.tx.clone();
        self.busy += 1;
        self.rt.spawn(async move {
            let m = match f(node).await {
                Ok(m) => m,
                Err(e) => Msg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(m);
        });
    }

    fn unlock(&mut self) {
        if self
            .unlock_allowed_at
            .is_some_and(|deadline| Instant::now() < deadline)
        {
            return;
        }
        let exists = self.vault_path().exists();
        if !exists {
            if *self.pass != *self.pass2 {
                self.unlock_error = Some("Passphrases don't match.".into());
                return;
            }
            if self.pass.chars().count() < 12 {
                self.unlock_error = Some("At least 12 characters.".into());
                return;
            }
        }
        self.unlock_error = None;
        self.screen = Screen::Connecting(Instant::now());
        let pass = Zeroizing::new(self.pass.as_bytes().to_vec());
        self.pass = Zeroizing::new(String::new());
        self.pass2 = Zeroizing::new(String::new());
        let dir = self.data_dir.clone();
        let path = self.vault_path();
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let r: anyhow::Result<Msg> = async {
                std::fs::create_dir_all(&dir)?;
                let p = path.clone();
                let (state, vk) =
                    tokio::task::spawn_blocking(move || -> anyhow::Result<(State, VaultKey)> {
                        if exists {
                            let (state, vk) = vault::load(&p, &pass)?;
                            let vk = {
                                let mut vk = vk;
                                vk.bind_to_device_with_fallback()?;
                                vk
                            };
                            Ok((state, vk))
                        } else {
                            let vk = VaultKey::create_with_device_fallback(&pass)?;
                            Ok((State::new(), vk))
                        }
                    })
                    .await??;
                vault::save(&path, &state, &vk)?;
                #[cfg(windows)]
                if !vk.is_device_bound() {
                    let _ = tx.send(Msg::DeviceProtectionUnavailable);
                }
                let client = tor::bootstrap(&dir, &TorOptions::load_files(&dir)?).await?;
                let (etx, erx) = tokio::sync::mpsc::unbounded_channel();
                let node = Node::new(state, vk, path, client, etx);
                node.start()?;
                Ok(Msg::Ready(node, erx))
            }
            .await;
            let msg = match r {
                Ok(msg) => msg,
                Err(e)
                    if e.downcast_ref::<lycta_core::Error>()
                        .is_some_and(|e| matches!(e, lycta_core::Error::VaultDecrypt)) =>
                {
                    Msg::UnlockRejected
                }
                Err(e) => Msg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
        });
    }

    fn keep_history(&self) -> bool {
        self.node
            .as_ref()
            .is_some_and(|n| n.state(|st| st.keep_history))
    }

    fn poll(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            if !matches!(m, Msg::Ready(..)) && matches!(self.screen, Screen::Main) {
                self.busy = self.busy.saturating_sub(1);
            }
            match m {
                Msg::Ready(node, events) => {
                    self.failed_unlocks = 0;
                    self.unlock_allowed_at = None;
                    self.node = Some(node);
                    self.events = Some(events);
                    self.screen = Screen::Main;
                }
                Msg::Failed(e) => {
                    if matches!(self.update, UpdateState::Checking | UpdateState::Installing) {
                        self.update = UpdateState::Idle;
                    }
                    if matches!(self.screen, Screen::Connecting(_)) {
                        self.screen = Screen::Unlock;
                        self.unlock_error = Some(e);
                    } else {
                        self.toast(Tone::Warn, e);
                    }
                }
                Msg::DeviceProtectionUnavailable => self.toast(
                    Tone::Warn,
                    "TPM unavailable: this vault is protected by its passphrase only.",
                ),
                Msg::UnlockRejected => {
                    self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                    let exponent = self.failed_unlocks.saturating_sub(1).min(6);
                    let delay = (1u64 << exponent).min(60);
                    self.unlock_allowed_at = Some(Instant::now() + Duration::from_secs(delay));
                    self.unlock_error = Some("Incorrect passphrase or damaged vault.".into());
                    self.screen = Screen::Unlock;
                }
                Msg::Info(s) => self.toast(Tone::Ok, s),
                Msg::Silent => {}
                Msg::Invite(s) => self.invite = Some(s),
                Msg::ContactAdded(id) => {
                    self.target = Some(Target::Contact(id));
                    self.toast(Tone::Ok, format!("Contact #{id} added"));
                }
                Msg::Update(None) => self.update = UpdateState::UpToDate,
                Msg::Update(Some(m)) => {
                    self.toast(Tone::Info, format!("Version {} is available", m.version));
                    self.update = UpdateState::Available(m);
                }
                Msg::UpdateInstalled(v) => self.update = UpdateState::Installed(v),
            }
        }
        let mut evs = Vec::new();
        if let Some(rx) = &mut self.events {
            while let Ok(ev) = rx.try_recv() {
                evs.push(ev);
            }
        }
        let keep = self.keep_history();
        let incoming = evs.iter().any(|e| {
            matches!(
                e,
                Event::Message { .. } | Event::GroupMessage { .. } | Event::MirrorMessage { .. }
            )
        });
        if incoming && self.prefs.notifications && !self.focused {
            system::notify_new_message();
        }
        for ev in evs {
            match ev {
                Event::Message { contact, text, .. } => {
                    let t = Target::Contact(contact);
                    if !keep {
                        self.live
                            .entry(t)
                            .or_default()
                            .push(Live { out: false, text });
                    }
                    if self.target != Some(t) {
                        *self.unread.entry(t).or_default() += 1;
                    }
                }
                Event::GroupMessage {
                    group,
                    author,
                    text,
                } => {
                    let t = Target::Group(group);
                    if !keep {
                        self.live.entry(t).or_default().push(Live {
                            out: false,
                            text: format!("{author}: {text}"),
                        });
                    }
                    if self.target != Some(t) {
                        *self.unread.entry(t).or_default() += 1;
                    }
                }
                Event::NewContact { contact, .. } => {
                    self.toast(Tone::Info, format!("New contact #{contact}"))
                }
                Event::MirrorMessage { mirror, text } => {
                    let t = Target::Mirror(mirror);
                    if !keep {
                        self.live
                            .entry(t)
                            .or_default()
                            .push(Live { out: false, text });
                    }
                    if self.target != Some(t) {
                        *self.unread.entry(t).or_default() += 1;
                    }
                }

                Event::MirrorChanged { .. }
                | Event::Delivered { .. }
                | Event::Deposited { .. }
                | Event::Changed { .. }
                | Event::GroupChanged { .. } => {}
                Event::FileReceived { contact, name, .. } => {
                    self.toast(Tone::Ok, format!("File from #{contact}: {name}"))
                }
                Event::Info(s) => self.toast(Tone::Info, s),
                Event::Error(s) => self.toast(Tone::Warn, s),
            }
        }
        let now = Instant::now();
        self.toasts.retain(|t| t.until > now);
    }

    fn ui_unlock(&mut self, ctx: &egui::Context) {
        let exists = self.vault_path().exists();
        let remaining = self
            .unlock_allowed_at
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .filter(|remaining| !remaining.is_zero());
        if remaining.is_some() {
            ctx.request_repaint_after(Duration::from_secs(1));
        } else {
            self.unlock_allowed_at = None;
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() * 0.2).max(20.0));
                theme::logo(ui, 64.0);
                ui.add_space(10.0);
                ui.label(RichText::new("LyctaCrypt").size(32.0).strong());
                ui.add_space(24.0);
                theme::card(ui, |ui| {
                    ui.set_width(340.0);
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut *self.pass)
                            .margin(egui::Margin::symmetric(10, 8))
                            .password(!self.show_pass)
                            .hint_text(if exists {
                                "Passphrase"
                            } else {
                                "New passphrase"
                            })
                            .desired_width(f32::INFINITY),
                    );
                    if !exists && !self.pass.is_empty() {
                        let (label, color, frac) = strength(&self.pass);
                        ui.add(egui::ProgressBar::new(frac).fill(color).desired_height(4.0));
                        ui.label(RichText::new(label).small().color(color));
                    }
                    let mut submit =
                        r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if !exists {
                        let r2 = ui.add(
                            egui::TextEdit::singleline(&mut *self.pass2)
                                .margin(egui::Margin::symmetric(10, 8))
                                .password(!self.show_pass)
                                .hint_text("Confirm passphrase")
                                .desired_width(f32::INFINITY),
                        );
                        submit = r2.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    }
                    ui.checkbox(&mut self.show_pass, "Show");
                    ui.add_space(4.0);
                    let label = if exists { "Unlock" } else { "Create vault" };
                    let unlock_button = ui
                        .add_enabled_ui(remaining.is_none(), |ui| theme::primary_button(ui, label))
                        .inner;
                    if unlock_button.clicked() || (submit && remaining.is_none()) {
                        self.unlock();
                    }
                    if let Some(remaining) = remaining {
                        ui.add_space(4.0);
                        ui.label(format!(
                            "Too many attempts. Try again in {} seconds.",
                            remaining
                                .as_secs()
                                .saturating_add(u64::from(remaining.subsec_nanos() > 0))
                        ));
                    }
                    if let Some(e) = &self.unlock_error {
                        ui.add_space(4.0);
                        ui.colored_label(Palette::DANGER, e);
                    }
                });
                ui.add_space(10.0);
                if ui
                    .link(RichText::new("Tor blocked here? Use a bridge").small())
                    .clicked()
                {
                    self.bridges_open = true;
                }
            });
        });
        self.ui_bridges(ctx);
    }

    fn ui_bridges(&mut self, ctx: &egui::Context) {
        if !self.bridges_open {
            return;
        }
        let dir = self.data_dir.clone();
        let mut open = true;
        let mut result: Option<anyhow::Result<String>> = None;
        theme::modal("Connection", &mut open).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.label(match bridges::current(&dir) {
                bridges::Current::Direct => "Now: direct connection to Tor".to_string(),
                bridges::Current::Bridges { protocol, count } => {
                    format!("Now: {count} {protocol} bridge(s)")
                }
            });
            ui.add_space(6.0);
            theme::section(ui, "ONE CLICK");
            let tb = bridges::find_tor_browser().is_some();
            ui.horizontal(|ui| {
                if ui.button("Direct").clicked() {
                    result = Some(bridges::clear(&dir).map(|_| "Direct connection".into()));
                }
                for (label, kind) in [
                    ("obfs4", bridges::Kind::Obfs4),
                    ("Snowflake", bridges::Kind::Snowflake),
                ] {
                    if ui
                        .add_enabled(tb, egui::Button::new(label))
                        .on_disabled_hover_text("Needs Tor Browser installed")
                        .clicked()
                    {
                        result = Some(
                            bridges::use_tor_browser(&dir, kind)
                                .map(|n| format!("{n} {label} bridge(s) from Tor Browser")),
                        );
                    }
                }
            });
            ui.label(
                RichText::new(if tb {
                    "Uses the transports and built-in bridges of your Tor Browser."
                } else {
                    "Install Tor Browser to enable obfs4 and Snowflake in one click. LyctaCrypt downloads nothing."
                })
                .small()
                .color(Palette::MUTED),
            );
            ui.add_space(6.0);
            theme::section(ui, "YOUR OWN BRIDGES");
            ui.add(
                egui::TextEdit::multiline(&mut self.bridge_lines)
                    .margin(egui::Margin::symmetric(8, 6))
                    .hint_text("Bridge lines from bridges.torproject.org, one per line")
                    .desired_rows(3)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal(|ui| {
                if ui.button("Transport program…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.bridge_program = Some(p);
                    }
                }
                ui.label(
                    RichText::new(match &self.bridge_program {
                        Some(p) => p
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        None => "none chosen".into(),
                    })
                    .small()
                    .color(Palette::MUTED),
                );
            });
            let lines = bridges::parse_lines(&self.bridge_lines);
            if ui
                .add_enabled(!lines.is_empty(), egui::Button::new("Use these bridges"))
                .clicked()
            {
                let program = self.bridge_program.clone().or_else(|| {
                    let d = bridges::find_tor_browser()?;
                    bridges::find_program(&d, bridges::Kind::Obfs4)
                });
                result = Some(
                    bridges::save(&dir, &lines, program.as_deref())
                        .map(|_| format!("{} bridge(s) saved", lines.len())),
                );
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new("Applies the next time you unlock.")
                    .small()
                    .color(Palette::MUTED),
            );
        });
        match result {
            Some(Ok(msg)) => {
                self.toast(Tone::Ok, msg);
                self.bridge_lines.clear();
            }
            Some(Err(e)) => self.toast(Tone::Warn, e.to_string()),
            None => {}
        }
        if !open {
            self.bridges_open = false;
        }
    }

    fn ui_connecting(&mut self, ctx: &egui::Context, since: Instant) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() * 0.35).max(20.0));
                ui.add(egui::Spinner::new().size(28.0));
                ui.add_space(10.0);
                ui.label(RichText::new("Connecting to Tor…").size(16.0));
                ui.label(
                    RichText::new(format!("{} s", since.elapsed().as_secs())).color(Palette::MUTED),
                );
            });
        });
    }

    fn handle_media(&mut self, ctx: &egui::Context) {
        if self.player.as_ref().is_some_and(|p| p.finished()) {
            self.player = None;
        }
        if self.player.is_some() || self.recorder.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        if self.recorder.as_ref().is_some_and(|r| r.full()) {
            self.finish_recording(true);
        }
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            match self.target {
                Some(Target::Contact(c)) => {
                    for p in dropped {
                        self.spawn(move |n| async move {
                            n.send_file(c, &p).await?;
                            Ok(Msg::Silent)
                        });
                    }
                }
                _ => self.toast(Tone::Warn, "Open a conversation to send files"),
            }
        }
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let rect = ctx.screen_rect();
            let p = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop-overlay"),
            ));
            p.rect_filled(rect, 0.0, Color32::from_rgba_unmultiplied(4, 34, 61, 150));
            p.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                if matches!(self.target, Some(Target::Contact(_))) {
                    "Drop to send (max 1 MB)"
                } else {
                    "Open a conversation first"
                },
                egui::FontId::proportional(24.0),
                Color32::WHITE,
            );
        }
    }

    fn stop_scanner(&mut self) {
        self.scanner = None;
        self.scan_tex = None;
    }

    fn ui_scanner(&mut self, ui: &mut egui::Ui) -> Option<String> {
        let mut result = None;
        if let Some(sc) = &self.scanner {
            if let Some(img) = sc.take_frame() {
                match &mut self.scan_tex {
                    Some(t) => t.set(img, egui::TextureOptions::LINEAR),
                    None => {
                        self.scan_tex = Some(ui.ctx().load_texture(
                            "scan",
                            img,
                            egui::TextureOptions::LINEAR,
                        ))
                    }
                }
            }
            let (found, error) = (sc.found(), sc.error());
            ui.vertical_centered(|ui| match &self.scan_tex {
                Some(t) => {
                    let s = t.size_vec2();
                    let w = ui.available_width().min(320.0);
                    ui.add(
                        egui::Image::new(t)
                            .fit_to_exact_size(Vec2::new(w, w * s.y / s.x))
                            .corner_radius(10),
                    );
                }
                None => {
                    ui.add_space(8.0);
                    ui.spinner();
                    ui.label(
                        RichText::new("Starting camera…")
                            .small()
                            .color(Palette::MUTED),
                    );
                }
            });
            if let Some(e) = error {
                self.toast(Tone::Warn, e);
                self.stop_scanner();
            } else if found.is_some() {
                result = found;
                self.stop_scanner();
            } else if ui.button("Stop camera").clicked() {
                self.stop_scanner();
            }
        } else {
            ui.horizontal(|ui| {
                if ui.button("📷 Scan with camera").clicked() {
                    self.scanner = Some(scan::Scanner::start(ui.ctx().clone()));
                }
                if ui.button("QR from image…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Images", &["png", "jpg", "jpeg", "webp", "bmp", "gif"])
                        .pick_file()
                    {
                        match scan::decode_file(&p) {
                            Ok(t) => result = Some(t),
                            Err(e) => self.toast(Tone::Warn, e.to_string()),
                        }
                    }
                }
            });
        }
        result
    }

    fn finish_recording(&mut self, send: bool) {
        let Some(rec) = self.recorder.take() else {
            return;
        };
        let target = self.record_target.take();
        if !send {
            return;
        }
        match (rec.finish(), target) {
            (Ok(wav), Some(c)) => self.spawn(move |n| async move {
                n.send_file_bytes(c, "voice-note.wav", wav).await?;
                Ok(Msg::Silent)
            }),
            (Err(e), _) => self.toast(Tone::Warn, e.to_string()),
            _ => {}
        }
    }

    fn preview(&mut self, ctx: &egui::Context, file: u32) -> Option<egui::TextureHandle> {
        if let Some(t) = self.textures.get(&file) {
            return t.clone();
        }
        let data = self.node.as_ref()?.state(|st| {
            st.files
                .iter()
                .find(|f| f.local_id == file)
                .map(|f| f.data.clone())
        });
        let tex = data
            .and_then(|d| media::decode_preview(&d))
            .map(|img| ctx.load_texture(format!("file-{file}"), img, egui::TextureOptions::LINEAR));
        self.textures.insert(file, tex.clone());
        tex
    }

    fn toggle_play(&mut self, file: u32) {
        if self.player.as_ref().is_some_and(|p| p.file == file) {
            self.player = None;
            return;
        }
        let data = self.node.as_ref().and_then(|n| {
            n.state(|st| {
                st.files
                    .iter()
                    .find(|f| f.local_id == file)
                    .map(|f| f.data.clone())
            })
        });
        match data.map(|d| media::Player::play(file, d)) {
            Some(Ok(p)) => self.player = Some(p),
            Some(Err(e)) => self.toast(Tone::Warn, e.to_string()),
            None => self.toast(Tone::Warn, "This file is no longer in the vault"),
        }
    }

    fn ui_main(&mut self, ctx: &egui::Context) {
        let Some(node) = self.node.clone() else {
            return;
        };
        self.handle_media(ctx);
        self.ui_sidebar(ctx, &node);
        egui::CentralPanel::default()
            .frame(theme::central_frame())
            .show(ctx, |ui| match self.target {
                None => self.ui_welcome(ui),
                Some(Target::Contact(c)) => self.ui_chat(ui, &node, c),
                Some(Target::Group(g)) => self.ui_group(ui, &node, g),
                Some(Target::Mirror(m)) => self.ui_mirror(ui, &node, m),
            });
        self.ui_windows(ctx, &node);
        self.ui_bridges(ctx);
        self.ui_toasts(ctx);
    }

    fn ui_sidebar(&mut self, ctx: &egui::Context, node: &Arc<Node>) {
        egui::SidePanel::left("sidebar")
            .resizable(true)
            .show_separator_line(false)
            .default_width(270.0)
            .min_width(220.0)
            .frame(theme::sidebar_frame())
            .show(ctx, |ui| {
                let my_fp = node.my_public().fingerprint();
                ui.horizontal(|ui| {
                    avatar(ui, &my_fp, 34.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("You").strong());
                        let full = short_fingerprint(&my_fp);
                        let short: String = full.split('-').take(3).collect::<Vec<_>>().join("-");
                        ui.label(
                            RichText::new(format!("{short}…"))
                                .small()
                                .monospace()
                                .color(Palette::MUTED),
                        )
                        .on_hover_text(full);
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(theme::icon_button("⚙"))
                            .on_hover_text("Settings")
                            .clicked()
                        {
                            self.settings_open = true;
                        }
                        if ui
                            .add(theme::icon_button("🔒"))
                            .on_hover_text("Lock now")
                            .clicked()
                        {
                            self.lock_requested = true;
                        }
                        if self.busy > 0 {
                            ui.add(egui::Spinner::new().size(14.0));
                        }
                    });
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if theme::primary_button(ui, "➕ Invite").clicked() {
                        self.spawn(|n| async move { Ok(Msg::Invite(n.create_invite()?)) });
                    }
                    if ui.button("🔗 Add").clicked() {
                        self.add_open = true;
                    }
                    if ui.button("👥 Group").clicked() {
                        self.group_open = true;
                    }
                });
                ui.add_space(8.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.search)
                        .margin(egui::Margin::symmetric(8, 6))
                        .hint_text("🔍 Search")
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);

                let q = self.search.to_lowercase();
                let rows: Vec<ContactRow> = node.state(|st| {
                    st.contacts
                        .iter()
                        .map(|c| {
                            let fp = c.public.fingerprint();
                            let last = c.history.last().map(|h| {
                                let p = if h.dir == Direction::Out { "You: " } else { "" };
                                format!("{p}{}", h.text)
                            });
                            (
                                c.local_id,
                                fp,
                                short_fingerprint(&fp),
                                c.note.clone(),
                                c.accepted,
                                c.blocked,
                                last,
                            )
                        })
                        .filter(|(id, _, sfp, note, ..)| {
                            q.is_empty()
                                || format!("#{id}").contains(&q)
                                || sfp.to_lowercase().contains(&q)
                                || note
                                    .as_deref()
                                    .is_some_and(|n| n.to_lowercase().contains(&q))
                        })
                        .collect()
                });
                let groups: Vec<(u32, usize, Option<String>)> = node.state(|st| {
                    st.groups
                        .iter()
                        .map(|g| {
                            (
                                g.local_id,
                                g.member_fps.len(),
                                g.history.last().map(|h| h.text.clone()),
                            )
                        })
                        .collect()
                });
                let files: Vec<(u32, u32, String, usize)> = node.state(|st| {
                    st.files
                        .iter()
                        .map(|f| (f.local_id, f.contact, f.name.clone(), f.data.len()))
                        .collect()
                });

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        theme::section(ui, "CONTACTS");
                        if rows.is_empty() {
                            ui.label(RichText::new("No contacts yet").color(Palette::MUTED));
                        }
                        for (id, fp, sfp, note, accepted, blocked, last) in rows {
                            let t = Target::Contact(id);
                            let title = match &note {
                                Some(n) if !n.is_empty() => format!("#{id} · {n}"),
                                _ => format!("#{id}"),
                            };
                            let sub = if blocked {
                                "Blocked".to_string()
                            } else if !accepted {
                                "★ New".to_string()
                            } else {
                                last.unwrap_or(sfp)
                            };
                            let unread = self.unread.get(&t).copied().unwrap_or(0);
                            if theme::list_row(
                                ui,
                                self.target == Some(t),
                                |ui| avatar(ui, &fp, 36.0),
                                &title,
                                &sub,
                                unread,
                            )
                            .clicked()
                            {
                                self.select(t);
                            }
                        }
                        if !groups.is_empty() {
                            ui.add_space(8.0);
                            theme::section(ui, "GROUPS");
                        }
                        for (g, n, last) in groups {
                            let t = Target::Group(g);
                            let title = format!("G{g} · {n} members");
                            let sub = last.unwrap_or_default();
                            let unread = self.unread.get(&t).copied().unwrap_or(0);
                            if theme::list_row(
                                ui,
                                self.target == Some(t),
                                |ui| theme::group_badge(ui, 36.0),
                                &title,
                                &sub,
                                unread,
                            )
                            .clicked()
                            {
                                self.select(t);
                            }
                        }
                        let mirrors: Vec<MirrorRow> = node.state(|st| {
                            st.mirrors
                                .iter()
                                .map(|m| {
                                    (
                                        m.local_id,
                                        m.fp,
                                        m.note.clone(),
                                        m.history.last().map(|h| h.text.clone()),
                                    )
                                })
                                .collect()
                        });
                        if !mirrors.is_empty() {
                            ui.add_space(8.0);
                            theme::section(ui, "FROM MY MAIN DEVICE");
                        }
                        for (m, fp, note, last) in mirrors {
                            let t = Target::Mirror(m);
                            let title = note
                                .filter(|n| !n.is_empty())
                                .unwrap_or_else(|| short_fingerprint(&fp)[..9].to_string());
                            let unread = self.unread.get(&t).copied().unwrap_or(0);
                            if theme::list_row(
                                ui,
                                self.target == Some(t),
                                |ui| avatar(ui, &fp, 36.0),
                                &title,
                                &last.unwrap_or_default(),
                                unread,
                            )
                            .clicked()
                            {
                                self.select(t);
                            }
                        }
                        if !files.is_empty() {
                            ui.add_space(8.0);
                            theme::section(ui, "FILES");
                            for (id, from, name, size) in files {
                                ui.horizontal(|ui| {
                                    ui.label("📎");
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new(&name).strong());
                                        ui.label(
                                            RichText::new(format!(
                                                "#{from} · {}",
                                                human_size(size)
                                            ))
                                            .small()
                                            .color(Palette::MUTED),
                                        );
                                    });
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui.small_button("Save").clicked() {
                                            if let Some(dest) = rfd::FileDialog::new()
                                                .set_file_name(&name)
                                                .save_file()
                                            {
                                                match node.export_file(id, &dest) {
                                                    Ok(_) => self.toast(Tone::Ok, "Saved"),
                                                    Err(e) => self.toast(Tone::Warn, e.to_string()),
                                                }
                                            }
                                        }
                                    });
                                });
                            }
                        }
                    });
            });
    }

    fn select(&mut self, t: Target) {
        self.target = Some(t);
        self.unread.remove(&t);
    }

    fn ui_welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.3).max(20.0));
            theme::logo(ui, 64.0);
            ui.add_space(14.0);
            ui.label(RichText::new("Start a conversation").size(22.0).strong());
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.add_space(((ui.available_width() - 270.0) / 2.0).max(0.0));
                if theme::primary_button(ui, "Create invite").clicked() {
                    self.spawn(|n| async move { Ok(Msg::Invite(n.create_invite()?)) });
                }
                ui.add_space(6.0);
                if ui.button("Add contact").clicked() {
                    self.add_open = true;
                }
            });
        });
    }

    fn ui_chat(&mut self, ui: &mut egui::Ui, node: &Arc<Node>, c: u32) {
        let info = node.state(|st| {
            st.contact_by_local(c).map(|ct| {
                let hist = contact_rows(ct);
                (
                    ct.public.fingerprint(),
                    ct.verified_fingerprint,
                    ct.note.clone(),
                    ct.accepted,
                    ct.blocked,
                    ct.timer,
                    ct.mailbox.is_some(),
                    ct.session.is_some(),
                    hist,
                )
            })
        });
        let Some((
            fp,
            verified_fingerprint,
            note,
            accepted,
            blocked,
            timer,
            has_mailbox,
            has_session,
            hist,
        )) = info
        else {
            self.target = None;
            return;
        };
        let asked_mailbox = node.state(|st| st.mailbox_requests.contains(&c));
        let (asked_device, is_device, is_primary) = node.state(|st| {
            (
                st.device_requests.contains(&c),
                st.contact_by_local(c).is_some_and(|x| x.own_device),
                st.primary == Some(c) || st.primary_pending == Some(c),
            )
        });

        theme::header(ui, |ui| {
            avatar(ui, &fp, 40.0);
            ui.vertical(|ui| {
                let title = match &note {
                    Some(n) if !n.is_empty() => format!("#{c} · {n}"),
                    _ => format!("#{c}"),
                };
                ui.label(RichText::new(title).size(18.0).strong());
                let mut tags = vec![if has_session {
                    "🔒 Encrypted"
                } else {
                    "⏳ No session"
                }
                .to_string()];
                if let Some(verified) = verified_fingerprint {
                    tags.push(
                        if verified == fp {
                            "✓ Key verified"
                        } else {
                            "⚠ Key changed — verify"
                        }
                        .into(),
                    );
                } else {
                    tags.push("Key not verified".into());
                }
                if let Some(t) = timer {
                    tags.push(format!("⏱ {}", human_duration(t)));
                }
                if has_mailbox {
                    tags.push("✉ Mailbox".into());
                }
                if is_device {
                    tags.push("My device".into());
                }
                if is_primary {
                    tags.push("My main device".into());
                }
                ui.label(
                    RichText::new(tags.join("  ·  "))
                        .small()
                        .color(Palette::MUTED),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button(RichText::new("•••").size(14.0).strong(), |ui| {
                    ui.set_min_width(220.0);
                    ui.label(RichText::new("Disappearing messages").strong());
                    ui.horizontal_wrapped(|ui| {
                        for (label, secs) in [
                            ("Off", 0),
                            ("5 min", 300),
                            ("1 h", 3600),
                            ("1 day", 86400),
                            ("1 week", 604800),
                        ] {
                            if ui
                                .selectable_label(timer.unwrap_or(0) == secs, label)
                                .clicked()
                            {
                                self.spawn(move |n| async move {
                                    n.set_timer(c, secs).await?;
                                    Ok(Msg::Silent)
                                });
                                ui.close_menu();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.timer_field)
                                .hint_text("e.g. 30m")
                                .desired_width(70.0),
                        );
                        if ui.small_button("Set").clicked() {
                            match parse_duration(&self.timer_field) {
                                Some(s) => self.spawn(move |n| async move {
                                    n.set_timer(c, s).await?;
                                    Ok(Msg::Silent)
                                }),
                                None => self.toast(Tone::Warn, "Invalid duration"),
                            }
                            ui.close_menu();
                        }
                    });
                    ui.separator();
                    ui.label(RichText::new("Note").strong());
                    let mut n = note.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut n).changed() {
                        node.state(|st| {
                            st.contact_by_local(c)
                                .map(|x| x.note = (!n.is_empty()).then(|| n.clone()))
                        });
                        let _ = node.save();
                    }
                    ui.separator();
                    if ui.button("✉ Ask to host my mailbox").clicked() {
                        self.spawn(move |n| async move {
                            n.request_mailbox(c).await?;
                            Ok(Msg::Info("Request sent".into()))
                        });
                        ui.close_menu();
                    }
                    if asked_mailbox && ui.button("✉ Host their mailbox").clicked() {
                        self.spawn(move |n| async move {
                            n.accept_mailbox(c).await?;
                            Ok(Msg::Info("Hosting mailbox".into()))
                        });
                        ui.close_menu();
                    }
                    if is_device || is_primary {
                        if ui.button("Unlink this device").clicked() {
                            self.spawn(move |n| async move {
                                n.unlink_device(c).await?;
                                Ok(Msg::Info("Device unlinked".into()))
                            });
                            ui.close_menu();
                        }
                    } else if ui
                        .button("This is my main device…")
                        .on_hover_text(
                            "Ask it to link this device: it will copy your conversations here",
                        )
                        .clicked()
                    {
                        self.spawn(move |n| async move {
                            n.request_device_link(c).await?;
                            Ok(Msg::Info("Asked. Now accept on your main device.".into()))
                        });
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui
                        .button(if blocked { "Unblock" } else { "🚫 Block" })
                        .clicked()
                    {
                        node.state(|st| {
                            st.contact_by_local(c).map(|x| {
                                x.blocked = !blocked;
                                x.accepted = blocked;
                            })
                        });
                        let _ = node.save();
                        ui.close_menu();
                    }
                    if ui
                        .button(RichText::new("🗑 Delete contact").color(Palette::DANGER))
                        .clicked()
                    {
                        let _ = node.forget_contact(c);
                        self.target = None;
                        ui.close_menu();
                    }
                });
                if ui
                    .add(theme::icon_button("🛡"))
                    .on_hover_text("Verify")
                    .clicked()
                {
                    self.verify = Some(c);
                }
                if ui
                    .add(theme::icon_button("📎"))
                    .on_hover_text("Send file (max 1 MB)")
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.spawn(move |n| async move {
                            n.send_file(c, &p).await?;
                            Ok(Msg::Silent)
                        });
                    }
                }
            });
        });

        if asked_device && !blocked {
            theme::banner(ui, Palette::WARN, |ui| {
                ui.label(
                    "This contact asks to be linked as one of YOUR devices. It would get a copy \
                     of your conversations and could send as you. Accept only a device you own, \
                     after verifying its code.",
                );
                ui.horizontal(|ui| {
                    if ui.button("🛡 Verify").clicked() {
                        self.verify = Some(c);
                    }
                    if theme::primary_button(ui, "Link device").clicked() {
                        self.spawn(move |n| async move {
                            n.accept_device(c).await?;
                            Ok(Msg::Info("Device linked".into()))
                        });
                    }
                    if ui.button("Decline").clicked() {
                        node.state(|st| st.device_requests.retain(|&r| r != c));
                        let _ = node.save();
                    }
                });
            });
        }

        if !accepted && !blocked {
            theme::banner(ui, Palette::WARN, |ui| {
                ui.label("New contact. Verify before accepting.");
                ui.horizontal(|ui| {
                    if ui.button("🛡 Verify").clicked() {
                        self.verify = Some(c);
                    }
                    if theme::primary_button(ui, "Accept").clicked() {
                        node.state(|st| st.contact_by_local(c).map(|x| x.accepted = true));
                        let _ = node.save();
                    }
                });
            });
        }

        let keep = self.keep_history();
        let live: Vec<(bool, String)> = self
            .live
            .get(&Target::Contact(c))
            .map(|v| v.iter().map(|l| (l.out, l.text.clone())).collect())
            .unwrap_or_default();
        let h = ui.available_height() - self.composer_height(Target::Contact(c));
        egui::ScrollArea::vertical()
            .max_height(h)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.add_space(8.0);
                let empty = if keep {
                    hist.is_empty()
                } else {
                    live.is_empty()
                };
                if empty {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.label(RichText::new("No messages yet").color(Palette::MUTED));
                    });
                }
                if keep {
                    self.show_rows(ui, Target::Contact(c), hist);
                } else {
                    for (out, text) in live {
                        bubble(ui, out, &text, out.then_some(true));
                    }
                }
                ui.add_space(4.0);
            });
        self.composer(ui, Target::Contact(c), blocked);
    }

    fn composer_height(&self, t: Target) -> f32 {
        56.0 + if self.compose.as_ref().is_some_and(|m| m.target == t) {
            36.0
        } else {
            0.0
        }
    }

    fn show_rows(&mut self, ui: &mut egui::Ui, t: Target, rows: Vec<MsgRow>) {
        for r in rows {
            let selected = self
                .compose
                .as_ref()
                .is_some_and(|m| m.target == t && m.id == r.id && r.id != [0; 16]);
            match r.attachment {
                Some((file, vault::AttachmentKind::Image)) => {
                    if let Some(tex) = self.preview(ui.ctx(), file) {
                        theme::image_preview(ui, r.out, &tex);
                    }
                }
                Some((file, vault::AttachmentKind::Audio)) => {
                    let playing = self.player.as_ref().is_some_and(|p| p.file == file);
                    if theme::voice_note(ui, r.out, playing) {
                        self.toggle_play(file);
                    }
                }
                _ => {}
            }
            let view = theme::BubbleView {
                id: ui.id().with(("msg", r.id, r.text.len())),
                out: r.out,
                text: &r.text,
                status: (r.out && !matches!(t, Target::Group(_))).then_some(r.delivered),
                quote: r.quote.as_deref(),
                reactions: &r.reactions,
                edited: r.edited,
                deleted: r.deleted,
                selected,
            };
            let resp = match r.author {
                Some(a) => {
                    ui.horizontal_top(|ui| {
                        avatar(ui, &a, 22.0).on_hover_text(short_fingerprint(&a));
                        ui.vertical(|ui| theme::message_bubble(ui, &view)).inner
                    })
                    .inner
                }
                None => theme::message_bubble(ui, &view),
            };
            if r.id != [0; 16] && !r.deleted {
                resp.context_menu(|ui| self.message_menu(ui, t, &r));
            } else if r.id != [0; 16] && matches!(t, Target::Contact(_)) && !r.out {
                resp.context_menu(|ui| {
                    if ui.button("🗑 Delete for me").clicked() {
                        self.send_op(t, MsgOp::Delete { target: r.id });
                        ui.close_menu();
                    }
                });
            }
        }
    }

    fn message_menu(&mut self, ui: &mut egui::Ui, t: Target, r: &MsgRow) {
        ui.horizontal(|ui| {
            for &e in REACTIONS {
                let mine = r.reactions.iter().any(|(x, _, m)| *m && x == e);
                let b = egui::Button::new(RichText::new(e).size(18.0))
                    .selected(mine)
                    .min_size(Vec2::splat(32.0));
                if ui.add(b).clicked() {
                    let emoji = if mine { String::new() } else { e.to_string() };
                    self.send_op(
                        t,
                        MsgOp::React {
                            target: r.id,
                            emoji,
                        },
                    );
                    ui.close_menu();
                }
            }
        });
        ui.separator();
        if ui.button("↩ Reply").clicked() {
            self.compose = Some(Compose {
                target: t,
                id: r.id,
                edit: false,
                preview: r.text.clone(),
            });
            ui.close_menu();
        }
        if ui.button("📋 Copy text").clicked() {
            ui.ctx().copy_text(r.text.clone());
            ui.close_menu();
        }
        if r.out {
            if ui.button("✏ Edit").clicked() {
                self.compose = Some(Compose {
                    target: t,
                    id: r.id,
                    edit: true,
                    preview: r.text.clone(),
                });
                self.input = r.text.clone();
                ui.close_menu();
            }
            if ui.button("🗑 Delete for everyone").clicked() {
                self.send_op(t, MsgOp::Delete { target: r.id });
                ui.close_menu();
            }
        } else if matches!(t, Target::Contact(_)) && ui.button("🗑 Delete for me").clicked() {
            self.send_op(t, MsgOp::Delete { target: r.id });
            ui.close_menu();
        }
    }

    fn send_op(&mut self, t: Target, op: MsgOp) {
        match t {
            Target::Contact(c) => self.spawn(move |n| async move {
                n.message_op(c, op).await?;
                Ok(Msg::Silent)
            }),
            Target::Group(g) => self.spawn(move |n| async move {
                n.group_op(g, op).await?;
                Ok(Msg::Silent)
            }),
            Target::Mirror(m) => self.spawn(move |n| async move {
                n.mirror_op(m, op).await?;
                Ok(Msg::Silent)
            }),
        }
    }

    fn ui_mirror(&mut self, ui: &mut egui::Ui, node: &Arc<Node>, m: u32) {
        let info = node.state(|st| {
            st.mirror_by_local(m)
                .map(|x| (x.fp, x.note.clone(), history_rows(&x.history)))
        });
        let Some((fp, note, hist)) = info else {
            self.target = None;
            return;
        };
        theme::header(ui, |ui| {
            avatar(ui, &fp, 40.0);
            ui.vertical(|ui| {
                let title = note
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| short_fingerprint(&fp));
                ui.label(RichText::new(title).size(18.0).strong());
                ui.label(
                    RichText::new("Through your main device")
                        .small()
                        .color(Palette::MUTED),
                );
            });
        });
        let t = Target::Mirror(m);
        let keep = self.keep_history();
        let h = ui.available_height() - self.composer_height(t);
        egui::ScrollArea::vertical()
            .max_height(h)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.add_space(8.0);
                if keep {
                    self.show_rows(ui, t, hist);
                } else if let Some(v) = self.live.get(&t) {
                    for l in v {
                        bubble(ui, l.out, &l.text, None);
                    }
                }
                ui.add_space(4.0);
            });
        self.composer(ui, t, false);
    }

    fn composer(&mut self, ui: &mut egui::Ui, t: Target, disabled: bool) {
        if self.compose.as_ref().is_some_and(|m| m.target != t) {
            self.compose = None;
        }
        theme::composer_frame().show(ui, |ui| {
            if let Some(m) = self.compose.clone() {
                let mut cancel = ui.input(|i| i.key_pressed(egui::Key::Escape));
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(3.0, 26.0), Sense::hover());
                    ui.painter().rect_filled(rect, 2.0, Palette::ACCENT);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(if m.edit { "Editing" } else { "Replying to" })
                                .small()
                                .strong()
                                .color(Palette::ACCENT),
                        );
                        let mut p: String = m.preview.replace('\n', " ").chars().take(90).collect();
                        if m.preview.chars().count() > 90 {
                            p.push('…');
                        }
                        ui.label(RichText::new(p).small().color(Palette::MUTED));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(theme::icon_button("×"))
                            .on_hover_text("Cancel (Esc)")
                            .clicked()
                        {
                            cancel = true;
                        }
                    });
                });
                if cancel {
                    if m.edit {
                        self.input.clear();
                    }
                    self.compose = None;
                }
                ui.add_space(4.0);
            }
            if let (Some(rec), Target::Contact(c)) = (&self.recorder, t) {
                if self.record_target == Some(c) {
                    let secs = rec.seconds();
                    let mut action = None;
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                        let pulse = (ui.input(|i| i.time) * 3.0).sin() as f32 * 0.3 + 0.7;
                        ui.painter().circle_filled(
                            dot.center(),
                            5.0,
                            Palette::DANGER.gamma_multiply(pulse),
                        );
                        ui.label(format!(
                            "Recording  0:{:02} / 0:{:02}",
                            secs as u32,
                            media::VOICE_MAX_SECS as u32
                        ));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if theme::primary_button(ui, "Send").clicked() {
                                action = Some(true);
                            }
                            if ui.button("Cancel").clicked() {
                                action = Some(false);
                            }
                        });
                    });
                    if let Some(send) = action {
                        self.finish_recording(send);
                    }
                    return;
                }
            }
            ui.horizontal(|ui| {
                let mic = matches!(t, Target::Contact(_)) && !disabled;
                let w = ui.available_width() - if mic { 130.0 } else { 90.0 };
                let r = ui.add_enabled(
                    !disabled,
                    egui::TextEdit::singleline(&mut self.input)
                        .hint_text(if disabled { "Blocked" } else { "Message" })
                        .desired_width(w)
                        .margin(egui::Margin::symmetric(10, 8)),
                );
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if let (true, Target::Contact(c)) = (mic, t) {
                    if ui
                        .add(theme::icon_button("🎤"))
                        .on_hover_text("Record a voice note (max 30 s)")
                        .clicked()
                    {
                        match media::Recorder::start() {
                            Ok(rec) => {
                                self.recorder = Some(rec);
                                self.record_target = Some(c);
                            }
                            Err(e) => self.toast(Tone::Warn, format!("Microphone: {e}")),
                        }
                    }
                }
                let editing = self.compose.as_ref().is_some_and(|m| m.edit);
                let send = theme::primary_button(ui, if editing { "Save" } else { "Send" })
                    .clicked()
                    || enter;
                if send && !disabled && !self.input.trim().is_empty() {
                    let text = std::mem::take(&mut self.input);
                    let mode = self.compose.take();
                    if !self.keep_history() {
                        self.live.entry(t).or_default().push(Live {
                            out: true,
                            text: text.clone(),
                        });
                    }
                    match (t, mode) {
                        (_, Some(m)) if m.edit => {
                            self.send_op(t, MsgOp::Edit { target: m.id, text })
                        }
                        (Target::Contact(c), m) => {
                            let reply_to = m.map(|m| m.id);
                            self.spawn(move |n| async move {
                                n.send_reply(c, text, reply_to).await?;
                                Ok(Msg::Silent)
                            })
                        }
                        (Target::Group(g), m) => {
                            let op = MsgOp::Message {
                                id: lycta_core::primitives::random_bytes(),
                                text,
                                reply_to: m.map(|m| m.id),
                            };
                            self.spawn(move |n| async move {
                                n.group_op(g, op).await?;
                                Ok(Msg::Silent)
                            })
                        }
                        (Target::Mirror(x), m) => {
                            let op = MsgOp::Message {
                                id: lycta_core::primitives::random_bytes(),
                                text,
                                reply_to: m.map(|m| m.id),
                            };
                            self.spawn(move |n| async move {
                                n.mirror_op(x, op).await?;
                                Ok(Msg::Silent)
                            })
                        }
                    }
                    r.request_focus();
                }
            });
        });
    }

    fn ui_group(&mut self, ui: &mut egui::Ui, node: &Arc<Node>, g: u32) {
        let me = node.my_public().fingerprint();
        let info = node.state(|st| {
            st.group_by_local(g)
                .map(|gr| (gr.member_fps.clone(), gr.hub, group_rows(gr, &me)))
        });
        let Some((members, hub, hist)) = info else {
            self.target = None;
            return;
        };
        theme::header(ui, |ui| {
            theme::group_badge(ui, 40.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(format!("Group G{g}")).size(18.0).strong());
                ui.label(
                    RichText::new(match hub {
                        None => format!(
                            "{} members · end-to-end encrypted · you relay",
                            members.len()
                        ),
                        Some(h) => format!(
                            "{} members · end-to-end encrypted · relayed by #{h}",
                            members.len()
                        ),
                    })
                    .small()
                    .color(Palette::MUTED),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .button(if hub.is_none() { "Delete" } else { "Leave" })
                    .clicked()
                {
                    self.spawn(move |nd| async move {
                        nd.leave_group(g).await?;
                        Ok(Msg::Silent)
                    });
                    self.target = None;
                }
                ui.horizontal(|ui| {
                    for fp in members.iter().take(8) {
                        avatar(ui, fp, 22.0).on_hover_text(short_fingerprint(fp));
                    }
                });
            });
        });
        let keep = self.keep_history();
        let h = ui.available_height() - self.composer_height(Target::Group(g));
        egui::ScrollArea::vertical()
            .max_height(h)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.add_space(8.0);
                if keep {
                    self.show_rows(ui, Target::Group(g), hist);
                } else if let Some(v) = self.live.get(&Target::Group(g)) {
                    for l in v {
                        bubble(ui, l.out, &l.text, None);
                    }
                }
            });
        self.composer(ui, Target::Group(g), false);
    }

    fn ui_windows(&mut self, ctx: &egui::Context, node: &Arc<Node>) {
        if let Some(inv) = self.invite.clone() {
            let mut open = true;
            theme::modal("Invite", &mut open).show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    draw_qr(ui, &inv, 260.0);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Single use. Share it in person.")
                            .small()
                            .color(Palette::MUTED),
                    );
                });
                ui.add_space(6.0);
                let mut s = inv.clone();
                ui.add(
                    egui::TextEdit::multiline(&mut s)
                        .desired_rows(3)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    if theme::primary_button(ui, "📋 Copy").clicked() {
                        ui.ctx().copy_text(inv.clone());
                        self.toast(Tone::Ok, "Copied");
                    }
                    if ui.button("Close").clicked() {
                        self.invite = None;
                    }
                });
            });
            if !open {
                self.invite = None;
            }
        }

        if self.add_open {
            let mut open = true;
            theme::modal("Add contact", &mut open).show(ctx, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.add_field)
                        .margin(egui::Margin::symmetric(8, 6))
                        .hint_text("lycta:…")
                        .desired_rows(4)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
                if let Some(text) = self.ui_scanner(ui) {
                    if lycta_core::identity::Invite::decode(&text).is_ok() {
                        self.add_field = text;
                    } else {
                        self.toast(Tone::Warn, "This QR code is not a LyctaCrypt invite");
                    }
                }
                let valid = lycta_core::identity::Invite::decode(&self.add_field).is_ok();
                if !self.add_field.trim().is_empty() && !valid {
                    ui.label(RichText::new("Invalid invite").color(Palette::DANGER));
                }
                if ui.add_enabled(valid, egui::Button::new("Add")).clicked() {
                    let inv = std::mem::take(&mut self.add_field);
                    self.add_open = false;
                    self.spawn(move |n| async move {
                        Ok(Msg::ContactAdded(n.add_contact(&inv).await?))
                    });
                }
            });
            if !open {
                self.add_open = false;
            }
            if !self.add_open {
                self.stop_scanner();
            }
        }

        if let Some(c) = self.verify {
            let mut open = true;
            let me = node.my_public().fingerprint();
            if let Some(fp) =
                node.state(|st| st.contact_by_local(c).map(|x| x.public.fingerprint()))
            {
                let code = safety_code(&me, &fp);
                theme::modal(&format!("Verify #{c}"), &mut open).show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        draw_qr(ui, &format!("lycta-verif:{code}"), 200.0);
                        ui.add_space(6.0);
                        ui.label(RichText::new(&code).monospace().size(18.0).strong());
                        ui.label(
                            RichText::new("Must match on both devices.")
                                .small()
                                .color(Palette::MUTED),
                        );
                    });
                    ui.add_space(6.0);

                    if let Some(text) = self.ui_scanner(ui) {
                        self.verify_result =
                            Some(text.eq_ignore_ascii_case(&format!("lycta-verif:{code}")));
                    }
                    match self.verify_result {
                        Some(true) => {
                            ui.label(RichText::new("✔ Codes match").strong().color(Palette::OK));
                            if ui.button("Trust this key").clicked() {
                                node.state(|st| {
                                    if let Some(contact) =
                                        st.contacts.iter_mut().find(|x| x.local_id == c)
                                    {
                                        contact.verified_fingerprint = Some(fp);
                                    }
                                });
                                let _ = node.save();
                                self.verify = None;
                            }
                        }
                        Some(false) => {
                            ui.label(
                                RichText::new("Codes do NOT match. Do not trust this contact.")
                                    .strong()
                                    .color(Palette::DANGER),
                            );
                        }
                        None => {}
                    }
                });
            }
            if !open {
                self.verify = None;
            }
            if self.verify.is_none() {
                self.stop_scanner();
                self.verify_result = None;
            }
        }

        if self.group_open {
            let mut open = true;
            let contacts: Vec<(u32, [u8; 32], Option<String>)> = node.state(|st| {
                st.contacts
                    .iter()
                    .filter(|c| c.accepted && !c.blocked)
                    .map(|c| (c.local_id, c.public.fingerprint(), c.note.clone()))
                    .collect()
            });
            theme::modal("New group", &mut open).show(ctx, |ui| {
                ui.label(
                    RichText::new("You relay the messages and can read them.")
                        .small()
                        .color(Palette::MUTED),
                );
                ui.add_space(4.0);
                if contacts.is_empty() {
                    ui.label(RichText::new("No contacts").color(Palette::MUTED));
                }
                for (c, fp, note) in contacts {
                    ui.horizontal(|ui| {
                        let mut on = self.group_sel.contains(&c);
                        avatar(ui, &fp, 22.0);
                        let label = match note {
                            Some(n) if !n.is_empty() => format!("#{c} · {n}"),
                            _ => format!("#{c}"),
                        };
                        if ui.checkbox(&mut on, label).changed() {
                            if on {
                                self.group_sel.push(c);
                            } else {
                                self.group_sel.retain(|&x| x != c);
                            }
                        }
                    });
                }
                ui.add_space(6.0);
                if ui
                    .add_enabled(!self.group_sel.is_empty(), egui::Button::new("Create"))
                    .clicked()
                {
                    let members = std::mem::take(&mut self.group_sel);
                    self.group_open = false;
                    self.spawn(move |n| async move {
                        let g = n.create_group(members).await?;
                        Ok(Msg::Info(format!("Group G{g} created")))
                    });
                }
            });
            if !open {
                self.group_open = false;
            }
        }

        if self.settings_open {
            let mut open = true;
            theme::modal("Settings", &mut open).show(ctx, |ui| {
                ui.set_min_width(380.0);
                theme::section(ui, "PRIVACY");
                let before = self.prefs.clone();
                ui.horizontal(|ui| {
                    ui.label("Lock after");
                    egui::ComboBox::from_id_salt("lock_after")
                        .selected_text(match self.prefs.lock_minutes {
                            0 => "Never".to_string(),
                            m => format!("{m} min"),
                        })
                        .show_ui(ui, |ui| {
                            for (m, label) in [(1, "1 min"), (5, "5 min"), (10, "10 min"), (30, "30 min"), (0, "Never")] {
                                ui.selectable_value(&mut self.prefs.lock_minutes, m, label);
                            }
                        });
                });
                ui.checkbox(&mut self.prefs.lock_on_minimize, "Lock when minimized");
                ui.checkbox(&mut self.prefs.hide_from_capture, "Hide from screenshots and screen sharing");
                ui.checkbox(&mut self.prefs.notifications, "Notifications (no content shown)");
                ui.checkbox(&mut self.prefs.close_to_tray, "Keep running in the tray when closed");
                if self.prefs != before {
                    self.prefs.save(&self.data_dir);
                }
                ui.add_space(6.0);
                theme::section(ui, "COVER TRAFFIC");
                let mut cover = node.state(|st| st.cover);
                let before = cover;
                ui.horizontal(|ui| {
                    ui.radio_value(&mut cover, CoverMode::Off, "Off");
                    ui.radio_value(&mut cover, CoverMode::Low, "Low");
                    ui.radio_value(&mut cover, CoverMode::High, "High");
                    ui.radio_value(&mut cover, CoverMode::VeryHigh, "Very high (more traffic)");
                });
                if cover != before {
                    node.state(|st| st.cover = cover);
                    let _ = node.save();
                }
                ui.add_space(6.0);
                theme::section(ui, "HISTORY");
                ui.horizontal(|ui| {
                    let mut keep = node.state(|st| st.keep_history);
                    if ui.checkbox(&mut keep, "Keep history").changed() {
                        node.state(|st| {
                            st.keep_history = keep;
                            if !keep {
                                st.purge_history();
                            }
                        });
                        let _ = node.save();
                    }
                    if ui.button("Clear").clicked() {
                        node.state(|st| st.purge_history());
                        let _ = node.save();
                        self.live.clear();
                        self.toast(Tone::Ok, "History cleared");
                    }
                });
                let pending = node.pending_invites().len();
                let mailbox = node.state(|st| st.my_mailbox.as_ref().map(|m| m.host_contact));
                if pending > 0 || mailbox.is_some() {
                    ui.add_space(6.0);
                    theme::section(ui, "INVITES & MAILBOX");
                }
                if pending > 0 {
                    ui.horizontal(|ui| {
                        ui.label(format!("{pending} unused invite(s)"));
                        if ui.button("Revoke").clicked() {
                            let _ = node.revoke_invites();
                        }
                    });
                }
                if let Some(h) = mailbox {
                    ui.horizontal(|ui| {
                        ui.label(format!("Mailbox hosted by #{h}"));
                        if ui.button("Remove").clicked() {
                            self.spawn(|n| async move {
                                n.revoke_mailbox().await?;
                                Ok(Msg::Silent)
                            });
                        }
                    });
                }
                ui.add_space(6.0);
                theme::section(ui, "CONNECTION");
                ui.horizontal(|ui| {
                    ui.label(match bridges::current(&self.data_dir) {
                        bridges::Current::Direct => "Direct connection to Tor".to_string(),
                        bridges::Current::Bridges { protocol, count } => {
                            format!("{count} {protocol} bridge(s)")
                        }
                    });
                    if ui.button("Bridges…").clicked() {
                        self.bridges_open = true;
                    }
                });
                ui.add_space(6.0);
                theme::section(ui, "UPDATES");
                let version = env!("CARGO_PKG_VERSION");
                if !update::enabled() {
                    ui.label(
                        RichText::new(format!(
                            "Version {version}. This build has no release key, so it does not update itself."
                        ))
                        .small()
                        .color(Palette::MUTED),
                    );
                } else {
                    let mut action = None;
                    ui.horizontal(|ui| match &self.update {
                        UpdateState::Checking => {
                            ui.spinner();
                            ui.label("Checking over Tor…");
                        }
                        UpdateState::Installing => {
                            ui.spinner();
                            ui.label("Downloading and verifying…");
                        }
                        UpdateState::Available(m) => {
                            ui.label(format!("Version {} is available", m.version));
                            if theme::primary_button(ui, "Install").clicked() {
                                action = Some(Some(m.clone()));
                            }
                        }
                        UpdateState::Installed(v) => {
                            ui.label(
                                RichText::new(format!("Version {v} installed. Restart to use it."))
                                    .color(Palette::OK),
                            );
                        }
                        state => {
                            ui.label(if matches!(state, UpdateState::UpToDate) {
                                format!("Version {version} is up to date")
                            } else {
                                format!("Version {version}")
                            });
                            if ui.button("Check for updates").clicked() {
                                action = Some(None);
                            }
                        }
                    });
                    match action {
                        Some(None) => {
                            self.update = UpdateState::Checking;
                            self.spawn(move |n| async move {
                                Ok(Msg::Update(update::check(n.client(), version).await?))
                            });
                        }
                        Some(Some(m)) => {
                            self.update = UpdateState::Installing;
                            self.spawn(move |n| async move {
                                let staged =
                                    update::download(n.client(), &m, "lyctacrypt-gui", &n.data_dir())
                                        .await?;
                                update::install(&staged)?;
                                Ok(Msg::UpdateInstalled(m.version))
                            });
                        }
                        None => {}
                    }
                    ui.label(
                        RichText::new("Updates are signed and checked before they are installed.")
                            .small()
                            .color(Palette::MUTED),
                    );
                }
                ui.add_space(6.0);
                theme::section(ui, "IDENTITY & BACKUP");
                if ui.button("🔄 Rotate identity key").clicked() {
                    self.spawn(|n| async move {
                        let missed = n.rotate_identity().await?;
                        Ok(Msg::Info(if missed.is_empty() {
                            "Identity key rotated".into()
                        } else {
                            format!("Identity key rotated. Not notified: {missed:?}")
                        }))
                    });
                }
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.backup_pass)
                            .margin(egui::Margin::symmetric(8, 6))
                            .password(true)
                            .hint_text("Backup passphrase")
                            .desired_width(220.0),
                    );
                    let ok = self.backup_pass.chars().count() >= 12;
                    if ui
                        .add_enabled(ok, egui::Button::new("💾 Back up…"))
                        .on_disabled_hover_text("At least 12 characters")
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_file_name("backup.lycta")
                            .save_file()
                        {
                            match node.backup(&p, self.backup_pass.as_bytes()) {
                                Ok(()) => self.toast(Tone::Ok, "Backup saved"),
                                Err(e) => self.toast(Tone::Warn, e.to_string()),
                            }
                            self.backup_pass = Zeroizing::new(String::new());
                        }
                    }
                });
                ui.add_space(6.0);
                let r = theme::section_resp(ui, "DECOY VAULT");
                if self.decoy_scroll {
                    r.scroll_to_me(Some(Align::Min));
                }
                ui.label(
                    RichText::new("Opens with a second passphrase. Your vault is never changed.")
                        .small()
                        .color(Palette::MUTED),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut *self.decoy_pass)
                        .password(true)
                        .hint_text("Decoy passphrase")
                        .margin(egui::Margin::symmetric(8, 6))
                        .desired_width(f32::INFINITY),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut *self.decoy_pass2)
                        .password(true)
                        .hint_text("Confirm")
                        .margin(egui::Margin::symmetric(8, 6))
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    ui.label("Fake contacts");
                    ui.add(egui::Slider::new(&mut self.decoy_contacts, 1..=12));
                });
                ui.checkbox(&mut self.decoy_conversations, "Fake conversations");
                let ok =
                    self.decoy_pass.chars().count() >= 12 && *self.decoy_pass == *self.decoy_pass2;
                let hint = if self.decoy_pass.chars().count() < 12 {
                    "At least 12 characters"
                } else {
                    "Passphrases don't match"
                };
                if ui
                    .add_enabled(ok, egui::Button::new("Create decoy"))
                    .on_disabled_hover_text(hint)
                    .clicked()
                {
                    let pass = Zeroizing::new(self.decoy_pass.as_bytes().to_vec());
                    let (n, conv) = (self.decoy_contacts, self.decoy_conversations);
                    self.decoy_pass = Zeroizing::new(String::new());
                    self.decoy_pass2 = Zeroizing::new(String::new());
                    self.spawn(move |node| async move {
                        tokio::task::spawn_blocking(move || node.create_decoy(&pass, n, conv))
                            .await??;
                        Ok(Msg::Info("Decoy vault created".into()))
                    });
                }
            });
            if !open {
                self.settings_open = false;
            }
        }
    }

    fn ui_toasts(&mut self, ctx: &egui::Context) {
        if self.toasts.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, Vec2::new(-16.0, -76.0))
            .interactable(false)
            .show(ctx, |ui| {
                ui.set_max_width(340.0);
                for t in &self.toasts {
                    let color = match t.tone {
                        Tone::Info => Palette::ACCENT,
                        Tone::Ok => Palette::OK,
                        Tone::Warn => Palette::WARN,
                    };
                    theme::toast_frame(color).show(ui, |ui| {
                        ui.label(&t.text);
                    });
                    ui.add_space(6.0);
                }
            });
    }
}

impl eframe::App for App {
    #[cfg(feature = "demo")]
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw: &mut egui::RawInput) {
        let Some((_, frames)) = &self.capture else {
            return;
        };
        if self.demo_click && *frames == 8 {
            let pos = egui::pos2(560.0, 305.0);
            raw.events.push(egui::Event::PointerMoved(pos));
            for pressed in [true, false] {
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Secondary,
                    pressed,
                    modifiers: Default::default(),
                });
            }
        }
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.handle_system(ctx, frame);
        self.poll();
        theme::paint_background(ctx);
        if theme::title_bar(ctx) {
            if self.prefs.close_to_tray && self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        match self.screen {
            Screen::Unlock => self.ui_unlock(ctx),
            Screen::Connecting(since) => self.ui_connecting(ctx, since),
            Screen::Main => self.ui_main(ctx),
        }
        theme::window_frame(ctx);
        self.handle_capture(ctx);
        ctx.request_repaint_after(Duration::from_millis(400));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(n) = &self.node {
            let _ = n.save();
        }
    }
}

fn draw_qr(ui: &mut egui::Ui, data: &str, size: f32) {
    let Ok((w, cells)) = qr::matrix(data) else {
        return;
    };
    let quiet = 3;
    let total = (w + 2 * quiet) as f32;
    let cell = size / total;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 8.0, Color32::WHITE);
    for y in 0..w {
        for x in 0..w {
            if cells[y * w + x] {
                let min =
                    rect.min + Vec2::new((x + quiet) as f32 * cell, (y + quiet) as f32 * cell);
                p.rect_filled(
                    egui::Rect::from_min_size(min, Vec2::splat(cell + 0.5)),
                    0.0,
                    Color32::BLACK,
                );
            }
        }
    }
}

fn strength(p: &str) -> (&'static str, Color32, f32) {
    let len = p.chars().count();
    let words = p.split_whitespace().count();
    let classes = [
        p.chars().any(|c| c.is_lowercase()),
        p.chars().any(|c| c.is_uppercase()),
        p.chars().any(|c| c.is_ascii_digit()),
        p.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    let score = len as f32 / 4.0 + words as f32 * 1.5 + classes as f32;
    if len < 12 {
        ("Too short", Palette::DANGER, 0.15)
    } else if score < 9.0 {
        ("Weak", Palette::WARN, 0.4)
    } else if score < 14.0 {
        ("Good", Palette::ACCENT, 0.7)
    } else {
        ("Strong", Palette::OK, 1.0)
    }
}

fn human_size(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / 1024.0 / 1024.0)
    }
}

fn human_duration(s: u32) -> String {
    match s {
        0 => "off".into(),
        s if s % 604800 == 0 => format!("{} w", s / 604800),
        s if s % 86400 == 0 => format!("{} d", s / 86400),
        s if s % 3600 == 0 => format!("{} h", s / 3600),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

fn parse_duration(s: &str) -> Option<u32> {
    let s = s.trim();
    if s == "off" || s == "0" {
        return Some(0);
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u32 = num.parse().ok()?;
    let mult = match unit {
        "" | "s" => 1,
        "m" | "min" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    n.checked_mul(mult)
}
