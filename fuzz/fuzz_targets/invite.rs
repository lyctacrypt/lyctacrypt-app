#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = lycta_core::identity::Invite::decode(s);
    }
    let _ = lycta_core::identity::IdentityPublic::from_bytes(data);
});
