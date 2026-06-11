use wasm_bindgen::prelude::*;

use secrets_spotter_core::types::SecretFinding;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn scan_text(text: &str) -> JsValue {
    let findings = secrets_spotter_core::scan_text(text);
    serde_wasm_bindgen::to_value(&findings).unwrap()
}

#[wasm_bindgen]
pub fn pattern_count() -> usize {
    secrets_spotter_core::patterns::PATTERNS.len()
}

#[wasm_bindgen]
pub fn should_scan(url: &str, content_type: &str) -> bool {
    secrets_spotter_core::filter::should_scan(url, content_type)
}

#[wasm_bindgen]
pub fn parse_cookies(raw: &str) -> String {
    secrets_spotter_core::cookies::parse_cookies(raw)
}

#[wasm_bindgen]
pub fn format_attributes(pairs_json: &str) -> String {
    secrets_spotter_core::attributes::format_attributes(pairs_json)
}

#[wasm_bindgen]
pub fn merge_findings(existing: JsValue, new_findings: JsValue) -> JsValue {
    // `existing` is a tab's accumulated findings, which the service worker
    // persists straight back from this return value. If it ever fails to
    // round-trip, return it unchanged rather than silently resetting the tab to
    // zero findings — the old `unwrap_or_default()` did exactly that, turning a
    // transient decode hiccup into permanent data loss. A malformed `new` batch
    // is merely skipped (it gets re-scanned); and we never panic on serialize,
    // falling back to the preserved `existing` instead.
    let existing_vec: Vec<SecretFinding> = match serde_wasm_bindgen::from_value(existing.clone()) {
        Ok(v) => v,
        Err(_) => return existing,
    };
    let new_vec: Vec<SecretFinding> =
        serde_wasm_bindgen::from_value(new_findings).unwrap_or_default();
    let merged = secrets_spotter_core::merge_findings(existing_vec, new_vec);
    serde_wasm_bindgen::to_value(&merged).unwrap_or(existing)
}
