#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lycta_core::handshake::{self, Hs1};
use lycta_core::identity::Identity;
use lycta_core::ratchet::RatchetMessage;

static ID: OnceLock<Identity> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let me = ID.get_or_init(Identity::generate);
    if let Ok(hs1) = bincode::deserialize::<Hs1>(data) {
        let _ = handshake::respond(me, &hs1);
    }
    if let Ok(msg) = bincode::deserialize::<RatchetMessage>(data) {
        let peer = Identity::generate();
        if let Ok((hs1, _)) = handshake::initiate(&peer, &me.public(), b"") {
            if let Ok((_, mut est)) = handshake::respond(me, &hs1) {
                let _ = est.ratchet.decrypt(&msg, &est.session_id);
            }
        }
    }
});
