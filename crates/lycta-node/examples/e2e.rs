use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use tokio::sync::mpsc::UnboundedReceiver;

use lycta_core::identity::Invite;
use lycta_core::vault::{CoverMode, State, VaultKey};
use lycta_node::node::{Event, Node};
use lycta_node::tor::{self, TorOptions};

async fn make_node(
    dir: PathBuf,
    name: &str,
) -> Result<(std::sync::Arc<Node>, UnboundedReceiver<Event>)> {
    std::fs::create_dir_all(&dir)?;
    let t = Instant::now();
    let client = tor::bootstrap(&dir, &TorOptions::default()).await?;
    println!("[{name}] Tor ready in {:?}", t.elapsed());
    let mut state = State::new();
    state.cover = CoverMode::Off;
    let vk = VaultKey::create(b"test passphrase")?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let node = Node::new(state, vk, dir.join("vault.lycta"), client, tx);
    node.start()?;
    Ok((node, rx))
}

async fn wait_for<F: Fn(&Event) -> bool>(
    rx: &mut UnboundedReceiver<Event>,
    f: F,
    secs: u64,
) -> Result<Event> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(e)) if f(&e) => return Ok(e),
            Ok(Some(_)) => continue,
            _ => bail!("timed out"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let base = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("temporary folder as argument"),
    );
    let _ = std::fs::remove_dir_all(&base);

    let ((a, mut a_rx), (b, mut b_rx)) = tokio::try_join!(
        make_node(base.join("a"), "A"),
        make_node(base.join("b"), "B")
    )?;

    let inv = a.create_invite()?;
    println!("[A] invite: {inv}");
    let parsed = Invite::decode(&inv)?;

    let c_client = tor::bootstrap(&base.join("c"), &TorOptions::default()).await?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    match tokio::time::timeout(
        Duration::from_secs(120),
        tor::connect(&c_client, &parsed.onion_key),
    )
    .await
    {
        Ok(Ok(_)) => bail!(
            "FAIL: a client without the key reached the service (restricted discovery not working)"
        ),
        _ => {
            println!(
                "[C] ✓ without the access key the address is unreachable (restricted discovery OK)"
            )
        }
    }

    let t = Instant::now();
    let id_on_b = loop {
        match b.add_contact(&inv).await {
            Ok(id) => break id,
            Err(e) if t.elapsed() < Duration::from_secs(600) => {
                println!("[B] not reachable yet ({e}), retrying…");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Err(e) => return Err(e),
        }
    };
    println!("[B] ✓ contact #{id_on_b} added in {:?}", t.elapsed());
    let id_on_a = match wait_for(&mut a_rx, |e| matches!(e, Event::NewContact { .. }), 60).await? {
        Event::NewContact { contact, .. } => contact,
        _ => unreachable!(),
    };
    println!("[A] ✓ new contact #{id_on_a}");

    b.send_text(id_on_b, "hello from B".into()).await?;
    let e = wait_for(&mut a_rx, |e| matches!(e, Event::Message { .. }), 300).await?;
    println!("[A] ✓ received: {e:?}");

    let t = Instant::now();
    loop {
        match a.send_text(id_on_a, "reply from A".into()).await {
            Ok(()) => break,
            Err(e) if t.elapsed() < Duration::from_secs(300) => {
                println!("[A] send: {e}, retrying…");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Err(e) => return Err(e),
        }
    }
    let t = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(20), b_rx.recv()).await {
            Ok(Some(e @ Event::Message { .. })) => {
                println!("[B] ✓ received: {e:?}");
                break;
            }
            Ok(Some(_)) => {}
            _ if t.elapsed() < Duration::from_secs(600) => {
                let _ = a.flush(id_on_a).await;
            }
            _ => bail!("B did not receive the reply"),
        }
    }

    let (z, mut z_rx) = make_node(base.join("z"), "Z").await?;
    match tokio::time::timeout(Duration::from_secs(180), z.add_contact(&inv)).await {
        Ok(Ok(_)) => bail!("FAIL: the invite worked twice"),
        _ => println!("[Z] ✓ invite already used: refused"),
    }

    let file_path = base.join("note.bin");
    let payload: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&file_path, &payload)?;
    b.send_file(id_on_b, &file_path).await?;
    match wait_for(&mut a_rx, |e| matches!(e, Event::FileReceived { .. }), 300).await? {
        Event::FileReceived { file, size, .. } => {
            let out = base.join("received.bin");
            a.export_file(file, &out)?;
            if std::fs::read(&out)? != payload || size != payload.len() {
                bail!("FAIL: file was altered");
            }
            println!("[A] ✓ {size}-byte file received intact");
        }
        _ => unreachable!(),
    }

    let old_fp = a.my_public().fingerprint();
    let missed = a.rotate_identity().await?;
    if !missed.is_empty() {
        bail!("FAIL: rotation not announced to {missed:?}");
    }
    wait_for(
        &mut b_rx,
        |e| matches!(e, Event::Info(s) if s.contains("changed identity key")),
        300,
    )
    .await?;
    let seen_by_b = b.state(|st| st.contact_by_local(id_on_b).map(|c| c.public.fingerprint()));
    if seen_by_b != Some(a.my_public().fingerprint()) || seen_by_b == Some(old_fp) {
        bail!("FAIL: B did not adopt A's new identity");
    }
    println!("[B] ✓ A's new identity adopted");
    b.send_text(id_on_b, "after rotation".into()).await?;
    wait_for(
        &mut a_rx,
        |e| matches!(e, Event::Message { text, .. } if text == "after rotation"),
        300,
    )
    .await?;
    println!("[A] ✓ message received after rotation");

    let inv_z = a.create_invite()?;
    let t = Instant::now();
    let z_on_a_side = loop {
        match z.add_contact(&inv_z).await {
            Ok(id) => break id,
            Err(e) if t.elapsed() < Duration::from_secs(600) => {
                println!("[Z] not reachable yet ({e}), retrying…");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let _ = z_on_a_side;
    let z_id_on_a =
        match wait_for(&mut a_rx, |e| matches!(e, Event::NewContact { .. }), 120).await? {
            Event::NewContact { contact, .. } => contact,
            _ => unreachable!(),
        };
    a.state(|st| st.contact_by_local(z_id_on_a).map(|c| c.accepted = true));

    let t = Instant::now();
    let g = loop {
        match a.create_group(vec![id_on_a, z_id_on_a]).await {
            Ok(g) => break g,
            Err(e) if t.elapsed() < Duration::from_secs(600) => {
                println!("[A] group: {e}, retrying…");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let _ = g;
    wait_for(
        &mut b_rx,
        |e| matches!(e, Event::Info(s) if s.contains("added you to group")),
        600,
    )
    .await?;
    let g_on_b = b
        .state(|st| st.groups.first().map(|g| g.local_id))
        .expect("group on B");

    let t = Instant::now();
    while b.state(|st| st.groups.first().map(|g| g.member_keys.len())) < Some(2) {
        if t.elapsed() > Duration::from_secs(300) {
            bail!("FAIL: B did not receive the member keys");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    b.send_group(g_on_b, "hello group".into()).await?;
    let t = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(20), z_rx.recv()).await {
            Ok(Some(Event::GroupMessage { text, .. })) if text == "hello group" => break,
            Ok(Some(_)) => {}
            _ if t.elapsed() < Duration::from_secs(600) => {
                let _ = a.flush(z_id_on_a).await;
            }
            _ => bail!("FAIL: Z did not receive the group message"),
        }
    }
    println!("[Z] ✓ group message from B received through relay A");

    z.request_device_link(z_on_a_side).await?;
    wait_for(
        &mut a_rx,
        |e| matches!(e, Event::Info(s) if s.contains("asks to be linked")),
        600,
    )
    .await?;
    a.accept_device(z_id_on_a).await?;
    wait_for(
        &mut z_rx,
        |e| matches!(e, Event::Info(s) if s.contains("now linked")),
        600,
    )
    .await?;
    println!("[Z] ✓ linked as a companion device of A");
    b.send_text(id_on_b, "for all my devices".into()).await?;
    let mirror = match wait_for(
        &mut z_rx,
        |e| matches!(e, Event::MirrorMessage { text, .. } if text == "for all my devices"),
        600,
    )
    .await?
    {
        Event::MirrorMessage { mirror, .. } => mirror,
        _ => unreachable!(),
    };
    println!("[Z] ✓ message from B to A copied to the companion");
    z.mirror_op(
        mirror,
        lycta_core::wire::MsgOp::Message {
            id: lycta_core::primitives::random_bytes(),
            text: "reply from the second device".into(),
            reply_to: None,
        },
    )
    .await?;
    wait_for(
        &mut b_rx,
        |e| matches!(e, Event::Message { text, .. } if text == "reply from the second device"),
        600,
    )
    .await?;
    println!("[B] ✓ reply sent from the companion arrived (through A)");

    println!("\nALL END-TO-END TESTS PASSED");
    let _ = std::fs::remove_dir_all(&base);
    std::process::exit(0);
}
