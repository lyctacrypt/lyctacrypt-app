#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use lycta_core::identity::{safety_code, short_fingerprint};
use lycta_core::vault::{self, CoverMode, Direction, State, VaultKey};
use lycta_core::wire::MsgOp;

use lycta_node::node::{Event, Node};
use lycta_node::tor::{self, TorOptions};
use lycta_node::{hardening, qr, sandbox, update};

const HELP: &str = "\
Contacts
  /invite              single-use invite (text + QR code)
  /invites             show unused invites
  /revoke              revoke unused invites
  /add <lycta:…>       add a contact from their invite
  /contacts            list contacts
  /verify <n> [qr]     safety code
  /accept <n>          accept a new contact
  /block <n>           block a contact
  /delete <n>          delete a contact
  /note <n> <text>     local note
Messages
  /chat <n>            select a contact, then type messages
  /history [n]         show history (with message numbers)
  /reply <m> <text>    reply to message m of the current chat
  /react <m> <emoji>   react to message m (/react <m> to remove)
  /edit <m> <text>     edit your message m
  /unsend <m>          delete your message m for everyone
  /timer <n> <dur>     disappearing messages (30s, 10m, 1h, 1d, off)
  /file <n> <path>     send a file (max 1 MB)
  /files               received files
  /export <f> <path>   save a received file
  /keep on|off         keep history
  /clear               clear all history
Groups
  /group new <n,n,…>   create a group (you relay)
  /group chat <g>      select a group
  /group leave <g>     leave or delete a group
  /groups              list groups
Privacy
  /cover off|low|high  cover traffic
  /mailbox ask <n>     ask #n to host your mailbox
  /mailbox host <n>    host #n's mailbox
  /mailbox remove      stop using a mailbox
  /mailbox             mailbox status
Devices
  /device link <n>     on a new device: ask your main device (#n) to link it
  /device accept <n>   on the main device: accept #n as your device
  /device unlink <n>   end a device link
  /devices             linked devices and mirrored conversations
  /mirror <m>          select a conversation mirrored from the main device
Vault
  /me                  your fingerprint
  /rotate              rotate identity key
  /backup <path>       encrypted backup
  /decoy [n]           add a decoy vault (n fake contacts)
  /update [install]    check for a signed update over Tor
  /help  /quit";

struct Args {
    data_dir: PathBuf,
    tor: TorOptions,
    restore: Option<PathBuf>,
    sandbox: bool,
}

fn parse_args() -> Result<Args> {
    let mut data_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("no data directory"))?
        .join("LyctaCrypt");
    let mut tor = TorOptions::default();
    let mut restore = None;
    let mut sandbox = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| anyhow!("{name} needs a value"));
        match a.as_str() {
            "--data-dir" => data_dir = PathBuf::from(val("--data-dir")?),
            "--bridge" => tor.bridges.push(val("--bridge")?),
            "--pt" => tor.pt_path = Some(PathBuf::from(val("--pt")?)),
            "--pt-proto" => tor.pt_protocols.push(val("--pt-proto")?),
            "--restore" => restore = Some(PathBuf::from(val("--restore")?)),
            "--sandbox" => sandbox = true,
            "-h" | "--help" => {
                println!(
                    "lyctacrypt [--data-dir <path>] [--bridge \"<line>\"]… \
                     [--pt <binary> --pt-proto <obfs4|snowflake|webtunnel>…] \
                     [--restore <backup>] [--sandbox]\n\n{HELP}"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    if tor.pt_path.is_some() && tor.pt_protocols.is_empty() {
        tor.pt_protocols.push("obfs4".into());
    }

    if tor.bridges.is_empty() && tor.pt_path.is_none() {
        tor = TorOptions::load_files(&data_dir)?;
    }
    Ok(Args {
        data_dir,
        tor,
        restore,
        sandbox,
    })
}

fn new_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    let p1 = Zeroizing::new(rpassword::prompt_password(prompt)?);
    let p2 = Zeroizing::new(rpassword::prompt_password("Confirm: ")?);
    if *p1 != *p2 {
        bail!("passphrases don't match");
    }
    if p1.chars().count() < 12 {
        bail!("at least 12 characters");
    }
    Ok(p1)
}

fn create_vault_key(pass: &[u8]) -> Result<VaultKey> {
    Ok(VaultKey::create_with_device_fallback(pass)?)
}

fn unlock(path: &Path, restore: Option<&Path>) -> Result<(State, VaultKey)> {
    if let Some(backup) = restore {
        if path.exists() {
            bail!("a vault already exists here; use --data-dir with an empty folder");
        }
        let bp = Zeroizing::new(rpassword::prompt_password("Backup passphrase: ")?);
        let (mut state, _) = vault::load(backup, bp.as_bytes()).context("reading backup")?;
        state.prepare_restore();
        let p = new_passphrase("New passphrase: ")?;
        return Ok((state, create_vault_key(p.as_bytes())?));
    }
    if path.exists() {
        let pass = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
        let (state, vk) = vault::load(path, pass.as_bytes())?;
        let vk = {
            let mut vk = vk;
            vk.bind_to_device_with_fallback()?;
            vk
        };
        Ok((state, vk))
    } else {
        let p = new_passphrase("New passphrase: ")?;
        Ok((State::new(), create_vault_key(p.as_bytes())?))
    }
}

fn parse_duration(s: &str) -> Result<u32> {
    if s == "off" || s == "0" {
        return Ok(0);
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u32 = num.parse().map_err(|_| anyhow!("invalid duration: {s}"))?;
    let mult = match unit {
        "" | "s" => 1,
        "m" | "min" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => bail!("unknown unit: {unit} (s, m, h, d, w)"),
    };
    n.checked_mul(mult)
        .ok_or_else(|| anyhow!("duration too long"))
}

fn maintainer_command() -> Result<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("update-keygen") => {
            let (secret, public) = update::keygen();
            println!("Secret key (keep offline, never commit it):\n{secret}\n");
            println!("Public key (set LYCTA_UPDATE_PUBLIC_KEY when building):\n{public}");
            Ok(true)
        }
        Some("update-sign") => {
            let Some(manifest) = args.get(1) else {
                bail!("lyctacrypt update-sign <update.json> [secret-key-file]");
            };
            let bytes = std::fs::read(manifest)?;
            let secret = Zeroizing::new(match args.get(2) {
                Some(key) => std::fs::read_to_string(key)?,
                None => std::env::var("LYCTA_UPDATE_SECRET_KEY").map_err(|_| {
                    anyhow!("secret-key file or LYCTA_UPDATE_SECRET_KEY is required")
                })?,
            });
            let sig = update::sign(&bytes, &secret)?;
            update::verify_manifest(&bytes, &sig, update::UPDATE_PUBLIC_KEY)
                .context("secret key does not match the compiled release public key")?;
            let out = format!("{manifest}.sig");
            std::fs::write(&out, &sig)?;
            println!("Signature written to {out}");
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Target {
    Contact(u32),
    Group(u32),

    Mirror(u32),
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = hardening::apply();
    if maintainer_command()? {
        return Ok(());
    }
    let args = parse_args()?;
    std::fs::create_dir_all(&args.data_dir)?;
    let vault_path = lycta_node::vault_path(&args.data_dir);

    let (state, vk) = unlock(&vault_path, args.restore.as_deref())?;
    #[cfg(windows)]
    if !vk.is_device_bound() {
        eprintln!("Warning: TPM unavailable; the vault is protected by its passphrase only.");
    }
    vault::save(&vault_path, &state, &vk)?;

    if args.sandbox {
        println!(
            "{}",
            sandbox::apply(&args.data_dir, args.tor.pt_path.as_deref())?
        );
    }

    println!("Connecting to Tor…");
    let client = tor::bootstrap(&args.data_dir, &args.tor).await?;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let node = Node::new(state, vk, vault_path, client, tx);
    node.start()?;

    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            print_event(ev);
        }
    });

    println!("Ready. /invite to start, /help for commands.");

    let mut current: Option<Target> = None;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        let line = tokio::select! {
            l = lines.next_line() => l?,
            _ = tokio::signal::ctrl_c() => None,
        };
        let Some(line) = line else { break };
        let line = Zeroizing::new(line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match handle(&node, &mut current, line).await {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => println!("! {e}"),
        }
    }
    node.save()?;
    Ok(())
}

fn print_event(ev: Event) {
    match ev {
        Event::Message {
            contact,
            text,
            accepted,
        } => {
            let tag = if accepted { "" } else { " (new)" };
            println!("<#{contact}{tag}> {text}");
        }
        Event::NewContact {
            contact,
            fingerprint,
        } => println!(
            "* New contact #{contact} ({fingerprint}). /verify {contact}, then /accept {contact}"
        ),
        Event::Delivered { .. } | Event::Deposited { .. } => {}
        Event::FileReceived {
            contact,
            file,
            name,
            size,
        } => println!("* File F{file} from #{contact}: {name} ({size} B). /export {file} <path>"),
        Event::GroupMessage {
            group,
            author,
            text,
        } => println!("<G{group} {author}> {text}"),
        Event::MirrorMessage { mirror, text } => println!("<M{mirror}> {text}"),
        Event::MirrorChanged { .. } => {}
        Event::Changed { contact } => println!("* #{contact} changed a message (/history)"),
        Event::GroupChanged { group } => println!("* A message changed in G{group} (/history)"),
        Event::Info(s) => println!("* {s}"),
        Event::Error(s) => println!("! {s}"),
    }
}

fn parse_n(s: Option<&str>) -> Result<u32> {
    s.and_then(|x| x.trim_start_matches(['#', 'G', 'g', 'F', 'f']).parse().ok())
        .ok_or_else(|| anyhow!("number expected"))
}

fn message_id(node: &Node, target: Target, m: Option<&str>) -> Result<[u8; 16]> {
    let m = parse_n(m)? as usize;
    let id = node.state(|st| match target {
        Target::Contact(c) => st
            .contact_by_local(c)
            .and_then(|c| c.history.get(m.wrapping_sub(1)).map(|e| e.id)),
        Target::Group(g) => st
            .group_by_local(g)
            .and_then(|g| g.history.get(m.wrapping_sub(1)).map(|e| e.id)),
        Target::Mirror(x) => st
            .mirror_by_local(x)
            .and_then(|x| x.history.get(m.wrapping_sub(1)).map(|e| e.id)),
    });
    match id {
        Some(id) if id != [0; 16] => Ok(id),
        Some(_) => bail!("this older message can't be changed"),
        None => bail!("no message {m}"),
    }
}

fn decorations(reply_to: Option<[u8; 16]>, edited: bool, reactions: &[vault::Reaction]) -> String {
    let mut s = String::new();
    if edited {
        s.push_str(" (edited)");
    }
    if !reactions.is_empty() {
        let r: Vec<&str> = reactions.iter().map(|r| r.emoji.as_str()).collect();
        s.push_str(&format!(" [{}]", r.join(" ")));
    }
    if reply_to.is_some() {
        s.insert_str(0, " ↩");
    }
    s
}

fn ensure_contact(node: &Node, n: u32) -> Result<()> {
    node.state(|st| st.contact_by_local(n).map(|_| ()))
        .ok_or_else(|| anyhow!("unknown contact"))
}

async fn handle(node: &Arc<Node>, current: &mut Option<Target>, line: &str) -> Result<bool> {
    if !line.starts_with('/') {
        match current.ok_or_else(|| anyhow!("select a contact first: /chat <n>"))? {
            Target::Contact(c) => node.send_text(c, line.to_string()).await?,
            Target::Group(g) => node.send_group(g, line.to_string()).await?,
            Target::Mirror(m) => {
                let op = MsgOp::Message {
                    id: lycta_core::primitives::random_bytes(),
                    text: line.to_string(),
                    reply_to: None,
                };
                node.mirror_op(m, op).await?
            }
        }
        return Ok(false);
    }
    let mut parts = line.splitn(3, ' ');
    let cmd = parts.next().unwrap_or("");
    let a1 = parts.next();
    let a2 = parts.next();
    match cmd {
        "/quit" | "/q" => return Ok(true),
        "/help" => println!("{HELP}"),
        "/update" => {
            let current = env!("CARGO_PKG_VERSION");
            match update::check(node.client(), current).await? {
                None => println!("Up to date ({current})"),
                Some(m) => {
                    println!("Version {} is available. {}", m.version, m.notes);
                    if a1 == Some("install") {
                        let staged =
                            update::download(node.client(), &m, "lyctacrypt", &node.data_dir())
                                .await?;
                        update::install(&staged)?;
                        println!("Installed. Restart to use version {}.", m.version);
                    } else {
                        println!("/update install to download, verify and install it");
                    }
                }
            }
        }
        "/me" => println!("{}", short_fingerprint(&node.my_public().fingerprint())),
        "/invite" => {
            let inv = node.create_invite()?;
            println!("{}", qr::to_terminal(&inv)?);
            println!("{inv}");
        }
        "/invites" => {
            for i in node.pending_invites() {
                println!("{i}");
            }
        }
        "/revoke" => println!("{} revoked", node.revoke_invites()?),
        "/add" => {
            let inv = a1.ok_or_else(|| anyhow!("/add <lycta:…>"))?;
            let id = node.add_contact(inv).await?;
            *current = Some(Target::Contact(id));
            println!("Contact #{id} added");
        }
        "/contacts" => node.state(|st| {
            for c in &st.contacts {
                let mut flags = Vec::new();
                if !c.accepted {
                    flags.push("new".to_string());
                }
                if c.blocked {
                    flags.push("blocked".into());
                }
                if c.session.is_none() {
                    flags.push("no session".into());
                }
                if let Some(t) = c.timer {
                    flags.push(format!("timer {t}s"));
                }
                println!(
                    "#{:<3} {}  {}{}",
                    c.local_id,
                    short_fingerprint(&c.public.fingerprint()),
                    c.note.as_deref().unwrap_or(""),
                    if flags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", flags.join(", "))
                    }
                );
            }
        }),
        "/chat" => {
            let n = parse_n(a1)?;
            ensure_contact(node, n)?;
            *current = Some(Target::Contact(n));
        }
        "/history" if a1.is_none() && matches!(*current, Some(Target::Mirror(_))) => {
            let Some(Target::Mirror(m)) = *current else {
                unreachable!()
            };
            node.state(|st| {
                if let Some(mi) = st.mirror_by_local(m) {
                    for (k, h) in mi.history.iter().enumerate() {
                        let who = if h.dir == Direction::Out {
                            "me"
                        } else {
                            "them"
                        };
                        let text = if h.deleted {
                            "(deleted)"
                        } else {
                            h.text.as_str()
                        };
                        println!(
                            "{:>3} <{who}> {text}{}",
                            k + 1,
                            decorations(h.reply_to, h.edited, &h.reactions)
                        );
                    }
                }
            });
        }
        "/history" => match (a1, *current) {
            (None, Some(Target::Group(g))) => node.state(|st| -> Result<()> {
                let g = st
                    .group_by_local(g)
                    .ok_or_else(|| anyhow!("unknown group"))?;
                for (k, h) in g.history.iter().enumerate() {
                    let text = if h.deleted {
                        "(deleted)"
                    } else {
                        h.text.as_str()
                    };
                    println!(
                        "{:>3} <{}> {text}{}",
                        k + 1,
                        short_fingerprint(&h.author),
                        decorations(h.reply_to, h.edited, &h.reactions)
                    );
                }
                Ok(())
            })?,
            _ => {
                let n = match (a1, *current) {
                    (Some(_), _) => parse_n(a1)?,
                    (None, Some(Target::Contact(c))) => c,
                    _ => bail!("/history <n>"),
                };
                node.state(|st| -> Result<()> {
                    let c = st
                        .contact_by_local(n)
                        .ok_or_else(|| anyhow!("unknown contact"))?;
                    for (k, h) in c.history.iter().enumerate() {
                        let who = match h.dir {
                            Direction::In => format!("#{n}"),
                            Direction::Out => "me".into(),
                        };
                        let mark = if h.dir == Direction::Out && !h.delivered {
                            " …"
                        } else {
                            ""
                        };
                        let text = if h.deleted {
                            "(deleted)"
                        } else {
                            h.text.as_str()
                        };
                        println!(
                            "{:>3} <{who}> {text}{}{mark}",
                            k + 1,
                            decorations(h.reply_to, h.edited, &h.reactions)
                        );
                    }
                    Ok(())
                })?;
            }
        },
        "/reply" | "/react" | "/edit" | "/unsend" => {
            let target = current.ok_or_else(|| anyhow!("select a chat first: /chat <n>"))?;
            let id = message_id(node, target, a1)?;
            let text = a2.unwrap_or("").to_string();
            let op = match cmd {
                "/reply" if text.is_empty() => bail!("/reply <m> <text>"),
                "/reply" => MsgOp::Message {
                    id: lycta_core::primitives::random_bytes(),
                    text,
                    reply_to: Some(id),
                },
                "/react" => MsgOp::React {
                    target: id,
                    emoji: text.trim().to_string(),
                },
                "/edit" if text.is_empty() => bail!("/edit <m> <text>"),
                "/edit" => MsgOp::Edit { target: id, text },
                _ => MsgOp::Delete { target: id },
            };
            match (target, op) {
                (Target::Contact(c), MsgOp::Message { text, reply_to, .. }) => {
                    node.send_reply(c, text, reply_to).await?
                }
                (Target::Contact(c), op) => node.message_op(c, op).await?,
                (Target::Group(g), op) => node.group_op(g, op).await?,
                (Target::Mirror(m), op) => node.mirror_op(m, op).await?,
            }
        }
        "/device" => {
            let n = parse_n(a2)?;
            match a1 {
                Some("link") => {
                    node.request_device_link(n).await?;
                    println!("Asked #{n}. Accept on that device: /device accept <this device>");
                }
                Some("accept") => {
                    node.accept_device(n).await?;
                    println!("#{n} is now one of your devices");
                }
                Some("unlink") => {
                    node.unlink_device(n).await?;
                    println!("Link with #{n} ended");
                }
                _ => bail!("/device link|accept|unlink <n>"),
            }
        }
        "/devices" => node.state(|st| {
            for d in st.devices() {
                println!("#{d}  companion device");
            }
            for r in &st.device_requests {
                println!("#{r}  asks to be linked (/device accept {r})");
            }
            if let Some(p) = st.primary {
                println!("#{p}  main device");
            }
            if let Some(p) = st.primary_pending {
                println!("#{p}  main device (waiting for it to accept)");
            }
            for m in &st.mirrors {
                println!(
                    "M{:<3} {}  {}",
                    m.local_id,
                    short_fingerprint(&m.fp),
                    m.note.as_deref().unwrap_or("")
                );
            }
        }),
        "/mirror" => {
            let m = parse_n(a1)?;
            node.state(|st| st.mirror_by_local(m).map(|_| ()))
                .ok_or_else(|| anyhow!("unknown conversation"))?;
            *current = Some(Target::Mirror(m));
        }
        "/verify" => {
            let n = parse_n(a1)?;
            let me = node.my_public().fingerprint();
            let fp = node
                .state(|st| st.contact_by_local(n).map(|c| c.public.fingerprint()))
                .ok_or_else(|| anyhow!("unknown contact"))?;
            let code = safety_code(&me, &fp);
            if a2 == Some("qr") {
                println!("{}", qr::to_terminal(&format!("lycta-verif:{code}"))?);
            }
            println!("{code}");
        }
        "/accept" | "/block" => {
            let n = parse_n(a1)?;
            let accept = cmd == "/accept";
            node.state(|st| -> Result<()> {
                let c = st
                    .contact_by_local(n)
                    .ok_or_else(|| anyhow!("unknown contact"))?;
                c.accepted = accept;
                c.blocked = !accept;
                if !accept {
                    c.session = None;
                    c.history.clear();
                }
                st.outbox.retain(|o| accept || o.contact != n);
                Ok(())
            })?;
            node.save()?;
        }
        "/delete" => {
            let n = parse_n(a1)?;
            ensure_contact(node, n)?;
            node.forget_contact(n)?;
            if *current == Some(Target::Contact(n)) {
                *current = None;
            }
        }
        "/note" => {
            let n = parse_n(a1)?;
            let note = a2.map(|s| s.to_string());
            node.state(|st| st.contact_by_local(n).map(|c| c.note = note))
                .ok_or_else(|| anyhow!("unknown contact"))?;
            node.save()?;
        }
        "/timer" => {
            let n = parse_n(a1)?;
            let secs = parse_duration(a2.ok_or_else(|| anyhow!("/timer <n> <duration|off>"))?)?;
            node.set_timer(n, secs).await?;
        }
        "/file" => {
            let n = parse_n(a1)?;
            let path = PathBuf::from(a2.ok_or_else(|| anyhow!("/file <n> <path>"))?);
            node.send_file(n, &path).await?;
        }
        "/files" => node.state(|st| {
            for f in &st.files {
                println!(
                    "F{:<3} #{}  {}  {} B",
                    f.local_id,
                    f.contact,
                    f.name,
                    f.data.len()
                );
            }
            for f in &st.incoming_files {
                println!(
                    "      #{}  {}  {}/{}",
                    f.contact,
                    f.name,
                    f.received(),
                    f.chunks.len()
                );
            }
        }),
        "/export" => {
            let f = parse_n(a1)?;
            let dest = PathBuf::from(a2.ok_or_else(|| anyhow!("/export <f> <path>"))?);
            println!("{}", node.export_file(f, &dest)?.display());
        }
        "/group" => match a1 {
            Some("new") => {
                let list = a2.ok_or_else(|| anyhow!("/group new <n,n,…>"))?;
                let members = list
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(|s| parse_n(Some(s)))
                    .collect::<Result<Vec<_>>>()?;
                let g = node.create_group(members).await?;
                *current = Some(Target::Group(g));
                println!("Group G{g}");
            }
            Some("chat") => {
                let g = parse_n(a2)?;
                node.state(|st| st.group_by_local(g).map(|_| ()))
                    .ok_or_else(|| anyhow!("unknown group"))?;
                *current = Some(Target::Group(g));
            }
            Some("leave") => {
                let g = parse_n(a2)?;
                node.leave_group(g).await?;
                if *current == Some(Target::Group(g)) {
                    *current = None;
                }
            }
            _ => bail!("/group new <n,n,…> | chat <g> | leave <g>"),
        },
        "/groups" => node.state(|st| {
            for g in &st.groups {
                let role = match g.hub {
                    None => "you relay".to_string(),
                    Some(h) => format!("relayed by #{h}"),
                };
                println!("G{:<3} {} members, {role}", g.local_id, g.member_fps.len());
            }
        }),
        "/keep" => {
            let keep = match a1 {
                Some("on") => true,
                Some("off") => false,
                _ => bail!("/keep on|off"),
            };
            node.state(|st| {
                st.keep_history = keep;
                if !keep {
                    st.purge_history();
                }
            });
            node.save()?;
        }
        "/clear" => {
            node.state(|st| st.purge_history());
            node.save()?;
        }
        "/cover" => {
            let mode = match a1 {
                Some("off") => CoverMode::Off,
                Some("low") => CoverMode::Low,
                Some("high") => CoverMode::High,
                Some("very-high") => CoverMode::VeryHigh,
                _ => bail!("/cover off|low|high"),
            };
            node.state(|st| st.cover = mode);
            node.save()?;
        }
        "/mailbox" => match a1 {
            Some("ask") => node.request_mailbox(parse_n(a2)?).await?,
            Some("host") => node.accept_mailbox(parse_n(a2)?).await?,
            Some("remove") => node.revoke_mailbox().await?,
            None => node.state(|st| {
                match &st.my_mailbox {
                    Some(m) => println!("Mailbox hosted by #{}", m.host_contact),
                    None => println!("No mailbox"),
                }
                for h in &st.hosted {
                    println!(
                        "Hosting #{}'s mailbox ({} waiting)",
                        h.owner,
                        h.frames.len()
                    );
                }
                for r in &st.mailbox_requests {
                    println!("#{r} asks you to host their mailbox: /mailbox host {r}");
                }
            }),
            _ => bail!("/mailbox [ask <n>|host <n>|remove]"),
        },
        "/rotate" => {
            let missed = node.rotate_identity().await?;
            println!("{}", short_fingerprint(&node.my_public().fingerprint()));
            if !missed.is_empty() {
                println!("! Not notified: {missed:?}");
            }
        }
        "/backup" => {
            let path = PathBuf::from(a1.ok_or_else(|| anyhow!("/backup <path>"))?);
            let p = new_passphrase("Backup passphrase: ")?;
            node.backup(&path, p.as_bytes())?;
        }
        "/decoy" => {
            let n: usize = a1.and_then(|s| s.parse().ok()).unwrap_or(4);
            let p = new_passphrase("Decoy passphrase: ")?;
            node.create_decoy(p.as_bytes(), n, true)?;
            println!("Decoy vault created");
        }
        _ => println!("Unknown command. /help"),
    }
    Ok(false)
}
