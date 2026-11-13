#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lycta_core::wire::decode_raw_frame(data);
    if data.len() >= 4096 {
        let n = data.len() - data.len() % 4096;
        let _ = lycta_core::wire::decode_frame(&data[..n]);
    }
});
