mod attributes;
mod cookies;
mod detector;
mod filter;
mod patterns;
mod types;

use wasm_bindgen::prelude::*;

use crate::detector::SecretDetector;
use crate::types::SecretFinding;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn scan_text(text: &str) -> JsValue {
    let findings = SecretDetector::scan(text);
    serde_wasm_bindgen::to_value(&findings).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn pattern_count() -> usize {
    patterns::PATTERNS.len()
}

#[wasm_bindgen]
pub fn should_scan(url: &str, content_type: &str) -> bool {
    filter::should_scan(url, content_type)
}

#[wasm_bindgen]
pub fn parse_cookies(raw: &str) -> String {
    cookies::parse_cookies(raw)
}

#[wasm_bindgen]
pub fn format_attributes(pairs_json: &str) -> String {
    attributes::format_attributes(pairs_json)
}

#[wasm_bindgen]
pub fn merge_findings(existing: JsValue, new_findings: JsValue) -> JsValue {
    let existing: Vec<SecretFinding> =
        serde_wasm_bindgen::from_value(existing).unwrap_or_default();
    let new: Vec<SecretFinding> =
        serde_wasm_bindgen::from_value(new_findings).unwrap_or_default();
    let merged = SecretDetector::merge_findings(existing, new);
    serde_wasm_bindgen::to_value(&merged).unwrap_or(JsValue::NULL)
}
