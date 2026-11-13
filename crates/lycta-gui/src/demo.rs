use lycta_core::identity::Identity;
use lycta_core::vault::{
    Attachment, AttachmentKind, Direction, Group, GroupEntry, HistoryEntry, Origin, Reaction,
    State, StoredFile, PEER,
};

fn entry(dir: Direction, text: &str, delivered: bool) -> HistoryEntry {
    let mut e = HistoryEntry::new(dir, text.into(), delivered, None);
    e.id = lycta_core::primitives::random_bytes();
    e
}

fn gentry(author: [u8; 32], text: &str) -> GroupEntry {
    let mut e = GroupEntry::new(author, text.into(), None);
    e.id = lycta_core::primitives::random_bytes();
    e
}

pub fn state() -> State {
    let mut st = State::new();
    let a = st.add_contact(Identity::generate().public(), Origin::Invite);
    let b = st.add_contact(Identity::generate().public(), Origin::Invite);
    let _c = st.add_contact(Identity::generate().public(), Origin::Request);
    let d = st.add_contact(Identity::generate().public(), Origin::Invite);

    let ca = st.contact_by_local(a).unwrap();
    ca.note = Some("Studio".into());
    ca.timer = Some(3600);
    let first = entry(
        Direction::In,
        "Hi! Did you get the plan for Saturday?",
        true,
    );
    let mut meet = entry(
        Direction::Out,
        "Yes. Let's meet at 2:30 pm outside the library.",
        true,
    );
    meet.edited = true;
    meet.reply_to = Some(first.id);
    meet.reactions.push(Reaction {
        from: Some(PEER),
        emoji: "👍".into(),
    });
    let mut long = entry(Direction::In, "Perfect. I'm also sending Sam's voice note, it explains the route because the usual path is closed for roadwork until the end of the month.", true);
    long.reactions.push(Reaction {
        from: None,
        emoji: "🔥".into(),
    });
    let mut gone = entry(Direction::In, "", true);
    gone.deleted = true;
    let mut photo = entry(Direction::In, "[file] map.png", true);
    photo.attachment = Some(Attachment {
        file: 2,
        name: "map.png".into(),
        kind: AttachmentKind::Image,
    });
    let mut voice = entry(Direction::Out, "[file] voice-note.wav", true);
    voice.attachment = Some(Attachment {
        file: 3,
        name: "voice-note.wav".into(),
        kind: AttachmentKind::Audio,
    });
    for e in [
        first,
        meet,
        long,
        gone,
        photo,
        voice,
        entry(Direction::Out, "Thanks, see you Saturday 👋", false),
    ] {
        ca.push_history(e);
    }

    let img = image::RgbaImage::from_fn(320, 200, |x, y| {
        let road = ((x as i32 - y as i32 * 2).rem_euclid(90) < 10) || (y % 70 < 8);
        if road {
            image::Rgba([255, 255, 255, 255])
        } else {
            image::Rgba([140 + (x / 4) as u8, 210, 170 + (y / 4) as u8, 255])
        }
    });
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .expect("png");
    let tone: Vec<i16> = (0..crate::media::VOICE_RATE)
        .map(|i| ((i as f32 * 0.17).sin() * 6000.0) as i16)
        .collect();
    st.files.push(StoredFile {
        local_id: 2,
        contact: a,
        name: "map.png".into(),
        data: png,
    });
    st.files.push(StoredFile {
        local_id: 3,
        contact: a,
        name: "voice-note.wav".into(),
        data: crate::media::encode_wav(&tone),
    });
    st.contact_by_local(b).unwrap().push_history(entry(
        Direction::In,
        "Safety code checked on my side ✔",
        true,
    ));
    st.contact_by_local(d).unwrap().blocked = true;

    let me = st.identity.public().fingerprint();
    let fa = st.contact_by_local(a).unwrap().public.fingerprint();
    let fb = st.contact_by_local(b).unwrap().public.fingerprint();
    let mut grp = Group::new(1, [7; 16], None);
    grp.members = vec![a, b];
    grp.member_fps = vec![me, fa, fb];
    let hello = gentry(fa, "Hello everyone");
    let mut welcome = gentry(me, "Welcome to the group!");
    welcome.reactions.push(Reaction {
        from: Some(fa),
        emoji: "❤".into(),
    });
    welcome.reactions.push(Reaction {
        from: Some(fb),
        emoji: "❤".into(),
    });
    let mut thanks = gentry(fb, "Thanks for the invite.");
    thanks.reply_to = Some(hello.id);
    grp.history = vec![hello, welcome, thanks];
    st.groups.push(grp);
    st.next_group_id = 2;
    st.files.push(StoredFile {
        local_id: 1,
        contact: a,
        name: "route.ogg".into(),
        data: vec![0; 186_777],
    });
    st.next_file_id = 4;
    st
}
