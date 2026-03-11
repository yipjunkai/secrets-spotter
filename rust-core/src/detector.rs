use lazy_static::lazy_static;
use memchr::memmem;
use regex::{Regex, RegexSet};

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

    // Value looks like a code identifier (variable, class, or constant name).
    // Matches camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case,
    // and dot-notation property paths — none of which are real secrets.
    static ref CODE_IDENTIFIER: Regex = Regex::new(
        concat!(
            r"^_*[a-z][a-zA-Z0-9]*([A-Z][a-z0-9]+)+[a-zA-Z0-9]*$",  // camelCase (2+ humps), optional _ prefix
            r"|^_*[A-Z][a-z]+([A-Z][a-z0-9]+)+$",                     // PascalCase (2+ humps), optional _ prefix
            r"|^_*[a-z]+(_[a-z0-9]+){2,}_*$",                         // snake_case (3+ segments), optional _/__ prefix/suffix
            r"|^_*[A-Z]+(_[A-Z0-9]+){2,}$",                           // SCREAMING_SNAKE (3+ segments), optional _ prefix
            r"|^[a-zA-Z][a-zA-Z0-9]*(-[a-zA-Z0-9]+){2,}$",           // kebab-case (3+ segments)
            r"|^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*){2,}$"   // dot-notation (3+ segments)
        )
    ).unwrap();

    static ref REGEX_SET: RegexSet = RegexSet::new(
        PATTERNS.iter().map(|p| p.regex.as_str())
    ).unwrap();
}

const MAX_MATCH_LEN: usize = 2048;

pub struct SecretDetector;

impl SecretDetector {
    pub fn scan(text: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        let candidates = REGEX_SET.matches(text);
        for idx in candidates.iter() {
            let pattern = &PATTERNS[idx];

            if !Self::prefix_matches(pattern.prefixes, text) {
                continue;
            }

            for caps in pattern.regex.captures_iter(text) {
                let full = caps.get(0).unwrap();
                if full.len() > MAX_MATCH_LEN {
                    continue;
                }
                let matched_str = full.as_str();

                // Use capture group 1 (the value) if the pattern defines one,
                // otherwise the full match IS the value (known-prefix patterns)
                let value = caps.get(1).map(|m| m.as_str()).unwrap_or(matched_str);

                if Self::is_false_positive(&pattern.kind, value) {
                    continue;
                }

                let redacted = Self::redact(matched_str);
                let matched = matched_str.to_string();

                findings.push(SecretFinding {
                    kind: pattern.kind.clone(),
                    label: pattern.label.to_string(),
                    matched_text: redacted,
                    full_match: matched,
                    start: full.start(),
                    end: full.end(),
                    severity: pattern.severity.clone(),
                });
            }
        }

        Self::deduplicate(&mut findings);
        findings
    }

    fn is_url_or_path(value: &str) -> bool {
        URL_OR_PATH.is_match(value) || HAS_FILE_EXT.is_match(value)
    }

    fn is_code_identifier(value: &str) -> bool {
        CODE_IDENTIFIER.is_match(value)
    }

    fn is_false_positive(kind: &SecretKind, value: &str) -> bool {
        match kind {
            SecretKind::GenericSecret | SecretKind::GenericApiKey | SecretKind::GenericToken => {
                if Self::is_url_or_path(value) {
                    return true;
                }
                if FALSE_POSITIVE.is_match(value) {
                    return true;
                }
                if PLAIN_WORDS.is_match(value) {
                    return true;
                }
                if Self::is_code_identifier(value) {
                    return true;
                }
                false
            }
            SecretKind::HighEntropyString => {
                if Self::is_url_or_path(value) {
                    return true;
                }
                // Reject code identifiers before computing entropy
                if Self::is_code_identifier(value) {
                    return true;
                }
                // Must have high Shannon entropy (>3.5 bits per char)
                if Self::shannon_entropy(value) < 3.5 {
                    return true;
                }
                // Must contain at least 2 of: uppercase, lowercase, digits
                // (symbols/non-ASCII alone don't count toward the threshold to avoid
                // false positives like CSS hashes with only lowercase + symbols)
                let (mut has_upper, mut has_lower, mut has_digit) = (false, false, false);
                for c in value.chars() {
                    has_upper |= c.is_ascii_uppercase();
                    has_lower |= c.is_ascii_lowercase();
                    has_digit |= c.is_ascii_digit();
                    if has_upper as u8 + has_lower as u8 + has_digit as u8 >= 2 {
                        break;
                    }
                }
                let alnum_classes = has_upper as u8 + has_lower as u8 + has_digit as u8;
                if alnum_classes < 2 {
                    return true;
                }
                false
            }
            SecretKind::BearerToken => {
                // Strip "Bearer " prefix to check just the token value
                let token = value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
                    .unwrap_or(value);
                if Self::is_code_identifier(token) {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    fn prefix_matches(prefixes: &[&str], text: &str) -> bool {
        if prefixes.is_empty() {
            return true;
        }
        let haystack = text.as_bytes();
        prefixes
            .iter()
            .any(|prefix| memmem::find(haystack, prefix.as_bytes()).is_some())
    }

    /// Shannon entropy in bits per character
    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        use std::collections::HashMap;
        let mut freq: HashMap<char, u32> = HashMap::new();
        let mut char_count = 0u32;
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
            char_count += 1;
        }
        let len = char_count as f64;
        let mut entropy = 0.0f64;
        for &count in freq.values() {
            let p = count as f64 / len;
            entropy -= p * p.log2();
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
        if findings.len() <= 1 {
            return;
        }
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(a.severity.cmp(&b.severity)));

        let mut kept: Vec<SecretFinding> = Vec::with_capacity(findings.len());
        let mut drain = findings.drain(..);

        if let Some(first) = drain.next() {
            kept.push(first);
        }

        for f in drain {
            let last = kept.last().unwrap();
            if f.start < last.end {
                // Overlapping — keep the higher severity (lower ordinal)
                if f.severity < last.severity {
                    *kept.last_mut().unwrap() = f;
                }
                // else: discard f, keep current last
            } else {
                kept.push(f);
            }
        }

        *findings = kept;
    }

    /// Merge existing findings with new ones, deduplicating by full_match value.
    /// When the same value is found by multiple patterns, keeps the highest severity.
    /// Note: full_match includes the variable/key name (e.g. `apiKey:"sk-..."`), so the
    /// same secret assigned to different variable names appears as separate findings —
    /// this is intentional to give visibility into every location the secret is exposed.
    pub fn merge_findings(
        existing: Vec<SecretFinding>,
        new: Vec<SecretFinding>,
    ) -> Vec<SecretFinding> {
        use std::collections::HashMap;

        let mut best: HashMap<String, SecretFinding> = HashMap::new();

        for f in existing.into_iter().chain(new.into_iter()) {
            match best.get(&f.full_match) {
                Some(prev) if prev.severity <= f.severity => {}
                _ => {
                    best.insert(f.full_match.clone(), f);
                }
            }
        }

        let mut result: Vec<SecretFinding> = best.into_values().collect();
        result.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.full_match.cmp(&b.full_match))
        });
        result
    }
}
