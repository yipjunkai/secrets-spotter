pub mod attributes;
pub mod cookies;
pub mod detector;
pub mod filter;
pub mod patterns;
pub mod types;

#[cfg(test)]
mod pattern_tests;
#[cfg(test)]
mod test_fixtures;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{tok, UPPER_NUM};
    use crate::types::SecretKind;

    #[test]
    fn scan_text_truncates_at_multibyte_boundary_without_panic() {
        // 'é' is 2 bytes; an odd cap would split it without the boundary walk
        let text = "é".repeat(MAX_SCAN_SIZE / 2 + 16);
        let findings = scan_text(&text);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_text_finds_secret_before_cap_but_not_after() {
        let aws = tok("AKIA", UPPER_NUM, 16);
        let filler = "x".repeat(MAX_SCAN_SIZE);
        let text = format!("{aws} {filler} {aws}");
        let findings = scan_text(&text);
        assert_eq!(findings.len(), 1, "only the pre-cap occurrence is found");
        assert!(matches!(findings[0].kind, SecretKind::AwsAccessKey));
    }
}
