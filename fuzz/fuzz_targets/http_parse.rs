#![no_main]

use libfuzzer_sys::fuzz_target;

// Feed arbitrary text to the proxy's HTTP request-line/header parsers.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let (_host, _port, path) = casual::proxy::parse_http_target(s);
        let _ = casual::proxy::rewrite_head(s, &path);
    }
});
