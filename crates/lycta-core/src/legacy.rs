use serde::Deserialize;

use crate::identity::{Identity, IdentityPublic};
use crate::vault::{
    Contact, CoverMode, Direction, Group, GroupEntry, HistoryEntry, HostedMailbox, IncomingFile,
    MyMailbox, Origin, OutboxItem, PeerMailbox, Session, Slot, State, StoredFile,
};

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct LegacyHistoryEntry {
    dir: Direction,
    text: String,
    delivered: bool,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct LegacyContact {
    local_id: u32,
    public: IdentityPublic,
    origin: Origin,
    accepted: bool,
    blocked: bool,
    note: Option<String>,
    session: Option<Session>,
    my_slot: Option<u32>,
    peer_onion: Option<[u8; 32]>,
    peer_auth: Option<[u8; 32]>,
    timer: Option<u32>,
    mailbox: Option<PeerMailbox>,
    history: Vec<LegacyHistoryEntry>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct LegacyGroupEntry {
    author: [u8; 32],
    text: String,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct LegacyGroup {
    local_id: u32,
    group_id: [u8; 16],
    hub: Option<u32>,
    members: Vec<u32>,
    member_fps: Vec<[u8; 32]>,
    history: Vec<LegacyGroupEntry>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct LegacyState {
    identity: Identity,
    contacts: Vec<LegacyContact>,
    slots: Vec<Slot>,
    outbox: Vec<OutboxItem>,
    seen: Vec<[u8; 32]>,
    next_local_id: u32,
    next_slot_id: u32,
    keep_history: bool,
    cover: CoverMode,
    my_mailbox: Option<MyMailbox>,
    mailbox_pending_host: Option<u32>,
    hosted: Vec<HostedMailbox>,
    mailbox_requests: Vec<u32>,
    incoming_files: Vec<IncomingFile>,
    files: Vec<StoredFile>,
    next_file_id: u32,
    groups: Vec<LegacyGroup>,
    next_group_id: u32,
}

impl From<LegacyHistoryEntry> for HistoryEntry {
    fn from(h: LegacyHistoryEntry) -> Self {
        HistoryEntry::new(h.dir, h.text, h.delivered, h.expires_at)
    }
}

impl From<LegacyState> for State {
    fn from(l: LegacyState) -> Self {
        let mut st = State::new();
        st.identity = l.identity;
        st.contacts = l
            .contacts
            .into_iter()
            .map(|c| Contact {
                local_id: c.local_id,
                public: c.public,
                origin: c.origin,
                accepted: c.accepted,
                blocked: c.blocked,
                note: c.note,
                session: c.session,
                my_slot: c.my_slot,
                peer_onion: c.peer_onion,
                peer_auth: c.peer_auth,
                timer: c.timer,
                mailbox: c.mailbox,
                history: c.history.into_iter().map(HistoryEntry::from).collect(),
                own_device: false,
            })
            .collect();
        st.slots = l.slots;
        st.outbox = l.outbox;
        st.seen = l.seen;
        st.next_local_id = l.next_local_id;
        st.next_slot_id = l.next_slot_id;
        st.keep_history = l.keep_history;
        st.cover = l.cover;
        st.my_mailbox = l.my_mailbox;
        st.mailbox_pending_host = l.mailbox_pending_host;
        st.hosted = l.hosted;
        st.mailbox_requests = l.mailbox_requests;
        st.incoming_files = l.incoming_files;
        st.files = l.files;
        st.next_file_id = l.next_file_id;
        st.groups = l
            .groups
            .into_iter()
            .map(|g| {
                let mut ng = Group::new(g.local_id, g.group_id, g.hub);
                ng.members = g.members;
                ng.member_fps = g.member_fps;
                ng.history = g
                    .history
                    .into_iter()
                    .map(|h| GroupEntry::new(h.author, h.text, h.expires_at))
                    .collect();
                ng
            })
            .collect();
        st.next_group_id = l.next_group_id;
        st
    }
}

#[cfg(test)]
pub(crate) fn sample_bytes(identity: &Identity) -> Vec<u8> {
    let legacy = LegacyState {
        identity: identity.clone(),
        contacts: vec![LegacyContact {
            local_id: 1,
            public: Identity::generate().public(),
            origin: Origin::Invite,
            accepted: false,
            blocked: false,
            note: None,
            session: None,
            my_slot: None,
            peer_onion: None,
            peer_auth: None,
            timer: None,
            mailbox: None,
            history: vec![],
        }],
        slots: vec![],
        outbox: vec![],
        seen: vec![],
        next_local_id: 2,
        next_slot_id: 1,
        keep_history: true,
        cover: CoverMode::Low,
        my_mailbox: None,
        mailbox_pending_host: None,
        hosted: vec![],
        mailbox_requests: vec![],
        incoming_files: vec![],
        files: vec![],
        next_file_id: 1,
        groups: vec![],
        next_group_id: 1,
    };
    bincode::serialize(&legacy).expect("serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{decode_state, SlotKind};

    #[test]
    fn reads_old_bincode_vault_with_history() {
        let identity = Identity::generate();
        let fp_a = Identity::generate().public();
        let legacy = LegacyState {
            identity: identity.clone(),
            contacts: vec![LegacyContact {
                local_id: 1,
                public: fp_a.clone(),
                origin: Origin::Invite,
                accepted: true,
                blocked: false,
                note: Some("Mom".into()),
                session: None,
                my_slot: Some(1),
                peer_onion: Some([3; 32]),
                peer_auth: Some([4; 32]),
                timer: Some(3600),
                mailbox: None,
                history: vec![
                    LegacyHistoryEntry {
                        dir: Direction::In,
                        text: "hello".into(),
                        delivered: true,
                        expires_at: None,
                    },
                    LegacyHistoryEntry {
                        dir: Direction::Out,
                        text: "hi".into(),
                        delivered: false,
                        expires_at: Some(99),
                    },
                ],
            }],
            slots: vec![Slot {
                id: 1,
                hs_seed: [5; 32],
                onion_key: Some([6; 32]),
                authorized_client: [7; 32],
                invite_auth_secret: None,
                kind: SlotKind::Contact(1),
            }],
            outbox: vec![],
            seen: vec![[8; 32]],
            next_local_id: 2,
            next_slot_id: 2,
            keep_history: true,
            cover: CoverMode::Low,
            my_mailbox: None,
            mailbox_pending_host: None,
            hosted: vec![],
            mailbox_requests: vec![],
            incoming_files: vec![],
            files: vec![],
            next_file_id: 1,
            groups: vec![LegacyGroup {
                local_id: 1,
                group_id: [9; 16],
                hub: None,
                members: vec![1],
                member_fps: vec![fp_a.fingerprint()],
                history: vec![LegacyGroupEntry {
                    author: [1; 32],
                    text: "group hi".into(),
                    expires_at: None,
                }],
            }],
            next_group_id: 2,
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        let st = decode_state(&bytes).unwrap();
        assert_eq!(st.identity.public(), identity.public());
        let c = &st.contacts[0];
        assert_eq!(c.note.as_deref(), Some("Mom"));
        assert_eq!(c.timer, Some(3600));
        assert_eq!(c.history.len(), 2);
        assert_eq!(c.history[1].text, "hi");
        assert_eq!(c.history[1].expires_at, Some(99));
        assert!(!c.history[1].delivered);
        assert_eq!(st.slots[0].hs_seed, [5; 32]);
        assert_eq!(st.groups[0].history[0].text, "group hi");
        assert_eq!(st.next_local_id, 2);
    }
}
