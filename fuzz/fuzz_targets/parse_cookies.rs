#![no_main]
//! Fuzz the cookie-header parser over arbitrary Set-Cookie / Cookie input.
//! Network responses feed this raw, so the only contract is: never panic.

use libfuzzer_sys::fuzz_target;
use secrets_spotter_core::cookies::parse_cookies;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let _ = parse_cookies(&raw);
});
