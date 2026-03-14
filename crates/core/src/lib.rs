pub mod attributes;
pub mod cookies;
pub mod detector;
pub mod filter;
pub mod patterns;
pub mod types;

use crate::detector::SecretDetector;
use crate::types::SecretFinding;

/// Maximum text size to scan (2 MB).
pub const MAX_SCAN_SIZE: usize = 2 * 1024 * 1024;

/// Scan text for secrets, truncating to `MAX_SCAN_SIZE` at a valid UTF-8 boundary.
pub fn scan_text(text: &str) -> Vec<SecretFinding> {
    let text = if text.len() > MAX_SCAN_SIZE {
        let mut end = MAX_SCAN_SIZE;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };
    SecretDetector::scan(text)
}

/// Merge existing findings with new ones, deduplicating by full_match value.
pub fn merge_findings(existing: Vec<SecretFinding>, new: Vec<SecretFinding>) -> Vec<SecretFinding> {
    SecretDetector::merge_findings(existing, new)
}
