pub mod attributes;
pub mod cookies;
pub mod detector;
pub mod filter;
pub mod patterns;
pub mod types;

#[cfg(test)]
mod pattern_tests;
// Public under the `fixtures` feature so the fuzz workspace can reuse the same
// shape-assembly the tests use; still compiled for the crate's own tests.
#[cfg(any(test, feature = "fixtures"))]
pub mod test_fixtures;

use crate::detector::SecretDetector;
use crate::types::SecretFinding;

/// Default maximum text size to scan (2 MB). Bounds main-thread work in the
/// browser extension; the CLI passes its own `--max-size` instead.
pub const MAX_SCAN_SIZE: usize = 2 * 1024 * 1024;

/// Scan text for secrets, truncating to `max_size` at a valid UTF-8 boundary.
pub fn scan_text_limited(text: &str, max_size: usize) -> Vec<SecretFinding> {
    let text = if text.len() > max_size {
        let mut end = max_size;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };
    SecretDetector::scan(text)
}

/// Scan text, truncating to the default `MAX_SCAN_SIZE` cap.
pub fn scan_text(text: &str) -> Vec<SecretFinding> {
    scan_text_limited(text, MAX_SCAN_SIZE)
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

    #[test]
    fn scan_text_limited_honors_larger_limit() {
        let aws = tok("AKIA", UPPER_NUM, 16);
        let filler = "x".repeat(MAX_SCAN_SIZE);
        // Secret placed past the default 2 MiB cap.
        let text = format!("{filler} {aws}");
        // Default cap misses it...
        assert!(
            scan_text(&text).is_empty(),
            "default cap should miss the post-2MiB secret"
        );
        // ...but a larger explicit limit finds it.
        let findings = scan_text_limited(&text, text.len());
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].kind, SecretKind::AwsAccessKey));
    }
}
