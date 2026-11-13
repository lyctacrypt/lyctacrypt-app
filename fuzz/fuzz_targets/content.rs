#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let n = data.len() - data.len() % 1024;
    let _ = lycta_core::wire::decode_content(&data[..n]);
});
