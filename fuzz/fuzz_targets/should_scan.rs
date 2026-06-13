#![no_main]
//! Fuzz the scan-eligibility filter over degenerate URL / content-type pairs.
//! The extension calls this on every request; the only contract is: never
//! panic. Input is split on the first NUL byte into (url, content_type).

use libfuzzer_sys::fuzz_target;
use secrets_spotter_core::filter::should_scan;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(2, |&b| b == 0);
    let url = String::from_utf8_lossy(parts.next().unwrap_or(b""));
    let content_type = String::from_utf8_lossy(parts.next().unwrap_or(b""));
    let _ = should_scan(&url, &content_type);
});
