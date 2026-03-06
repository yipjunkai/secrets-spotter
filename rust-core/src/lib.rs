mod detector;
mod patterns;
mod types;

use wasm_bindgen::prelude::*;

use crate::detector::SecretDetector;

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
