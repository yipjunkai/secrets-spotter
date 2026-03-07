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

const MAX_SCAN_SIZE: usize = 2 * 1024 * 1024; // 2MB

#[wasm_bindgen]
pub fn scan_text(text: &str) -> JsValue {
    let text = if text.len() > MAX_SCAN_SIZE {
        // Find a valid UTF-8 char boundary at or before the limit
        let mut end = MAX_SCAN_SIZE;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };
    let findings = SecretDetector::scan(text);
    serde_wasm_bindgen::to_value(&findings).unwrap()
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
    let existing: Vec<SecretFinding> = serde_wasm_bindgen::from_value(existing).unwrap_or_default();
    let new: Vec<SecretFinding> = serde_wasm_bindgen::from_value(new_findings).unwrap_or_default();
    let merged = SecretDetector::merge_findings(existing, new);
    serde_wasm_bindgen::to_value(&merged).unwrap()
}
