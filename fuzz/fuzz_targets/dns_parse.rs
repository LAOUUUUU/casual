#![no_main]

use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes to the DNS response parser. It must never panic —
// only return Ok/Err.
fuzz_target!(|data: &[u8]| {
    let _ = casual::dns::parse_response(data, "fuzz.example");
});
