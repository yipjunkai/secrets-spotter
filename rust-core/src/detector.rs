use lazy_static::lazy_static;
use regex::Regex;

use crate::patterns::PATTERNS;
use crate::types::{SecretFinding, SecretKind};

lazy_static! {
    // Values that are clearly not secrets: plain lowercase words with hyphens,
    // common error/status strings, placeholder values
    static ref FALSE_POSITIVE: Regex = Regex::new(
        r#"(?i)^(true|false|null|none|undefined|error|invalid|missing|wrong|expired|default|example|changeme|replace.me|your[_-]?.+|TODO|FIXME|xxx+|placeholder|test(ing)?|sample|dummy|fake|mock|N/?A|TBD)$"#
    ).unwrap();

    // Looks like plain English: all lowercase letters and hyphens, no digits or mixed case
    static ref PLAIN_WORDS: Regex = Regex::new(
        r"^[a-z]+(-[a-z]+)+$"
    ).unwrap();

    // Value looks like a URL or file path — not a secret
    static ref URL_OR_PATH: Regex = Regex::new(
        r"(?i)^(https?://|ftp://|s3://|gs://|/[a-z]|\.\.?/|[a-z]:\\)"
    ).unwrap();

    // Value contains a file extension — likely a filename/URL, not a secret
    static ref HAS_FILE_EXT: Regex = Regex::new(
        r"\.(pdf|html?|js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|json|xml|ya?ml|txt|md|csv|zip|gz|tar|exe|dmg|pkg|deb|rpm|sh|bat|py|rb|go|rs|java|ts|tsx|jsx|vue|php)\b"
    ).unwrap();
}

const MAX_MATCH_LEN: usize = 2048;

pub struct SecretDetector;

impl SecretDetector {
    pub fn scan(text: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for pattern in PATTERNS.iter() {
            for mat in pattern.regex.find_iter(text) {
                if mat.len() > MAX_MATCH_LEN {
                    continue;
                }
                let matched = mat.as_str().to_string();

                // For generic patterns, filter out false positives
                if Self::is_false_positive(&pattern.kind, &matched) {
                    continue;
                }

                let redacted = Self::redact(&matched);

                findings.push(SecretFinding {
                    kind: pattern.kind.clone(),
                    label: pattern.label.to_string(),
                    matched_text: redacted,
                    full_match: matched,
                    start: mat.start(),
                    end: mat.end(),
                    severity: pattern.severity.clone(),
                });
            }
        }

        Self::deduplicate(&mut findings);
        findings
    }

    fn extract_value(matched: &str) -> &str {
        // Split on the first `=` or `:` (the assignment operator), not the last,
        // so base64 padding (`==`) in the value is preserved.
        let after_sep = matched
            .find(['=', ':'])
            .map(|i| &matched[i + 1..])
            .unwrap_or(matched);
        after_sep
            .trim()
            .trim_matches(|c| c == '\'' || c == '"' || c == ' ')
    }

    fn is_url_or_path(value: &str) -> bool {
        URL_OR_PATH.is_match(value) || HAS_FILE_EXT.is_match(value)
    }

    fn is_false_positive(kind: &SecretKind, matched: &str) -> bool {
        match kind {
            SecretKind::GenericSecret | SecretKind::GenericApiKey | SecretKind::GenericToken => {
                let value = Self::extract_value(matched);

                if Self::is_url_or_path(value) {
                    return true;
                }
                if FALSE_POSITIVE.is_match(value) {
                    return true;
                }
                if PLAIN_WORDS.is_match(value) {
                    return true;
                }
                false
            }
            SecretKind::HighEntropyString => {
                let value = Self::extract_value(matched);

                if Self::is_url_or_path(value) {
                    return true;
                }
                // Must have high Shannon entropy (>3.5 bits per char)
                if Self::shannon_entropy(value) < 3.5 {
                    return true;
                }
                // Must contain at least 2 of: uppercase, lowercase, digits
                let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
                let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
                let has_digit = value.chars().any(|c| c.is_ascii_digit());
                let char_classes = has_upper as u8 + has_lower as u8 + has_digit as u8;
                if char_classes < 2 {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Shannon entropy in bits per character
    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let len = s.len() as f64;
        let mut freq = [0u32; 256];
        for &b in s.as_bytes() {
            freq[b as usize] += 1;
        }
        let mut entropy = 0.0f64;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn redact(s: &str) -> String {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() <= 8 {
            return "*".repeat(chars.len());
        }
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}...{}", prefix, suffix)
    }

    fn deduplicate(findings: &mut Vec<SecretFinding>) {
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(a.severity.cmp(&b.severity)));

        let mut i = 0;
        while i + 1 < findings.len() {
            if findings[i + 1].start < findings[i].end {
                // Overlapping — keep the higher severity (lower ordinal)
                if findings[i + 1].severity < findings[i].severity {
                    findings.remove(i);
                } else {
                    findings.remove(i + 1);
                }
            } else {
                i += 1;
            }
        }
    }

    /// Merge existing findings with new ones, deduplicating by label + full_match.
    pub fn merge_findings(
        existing: Vec<SecretFinding>,
        new: Vec<SecretFinding>,
    ) -> Vec<SecretFinding> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        let mut merged = Vec::with_capacity(existing.len() + new.len());

        for f in existing.into_iter().chain(new.into_iter()) {
            let key = format!("{}:{}:{}", f.label, f.full_match, f.start);
            if seen.insert(key) {
                merged.push(f);
            }
        }

        merged
    }
}
