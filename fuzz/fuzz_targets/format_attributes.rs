#![no_main]
//! Fuzz the attribute-formatting path over adversarial JSON. The input is a
//! JSON string from the content script; the only contract is: never panic.

use libfuzzer_sys::fuzz_target;
use secrets_spotter_core::attributes::format_attributes;

fuzz_target!(|data: &[u8]| {
    let pairs_json = String::from_utf8_lossy(data);
    let _ = format_attributes(&pairs_json);
});
