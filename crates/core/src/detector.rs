use std::collections::HashSet;
use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use crate::patterns::PATTERNS;
use crate::types::{SecretFinding, SecretKind};

// Values that are clearly not secrets: plain lowercase words with hyphens,
// common error/status strings, placeholder values.
// `(?u-i:.)` re-enables Unicode (case-folding off) for just the dot
// constructs — under `-u` a bare `.` can match invalid UTF-8, which the
// regex crate rejects on &str patterns. Needs no optional unicode-* feature.
static FALSE_POSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i-u)^(true|false|null|none|undefined|error|invalid|missing|wrong|expired|default|example|changeme|replace(?u-i:.)me|your[_-]?(?u-i:.+)|TODO|FIXME|xxx+|placeholder|test(ing)?|sample|dummy|fake|mock|N/?A|TBD)$"#
    )
    .unwrap()
});

// Looks like plain English: lowercase letters, optionally hyphen-joined
// (single words included now — a real key almost always has a digit or a
// capital). No digits, no mixed case.
static PLAIN_WORDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z]+(-[a-z]+)*$").unwrap());

// Value looks like a URL or file path — not a secret
static URL_OR_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)^(https?://|ftp://|s3://|gs://|/[a-z]|\.\.?/|[a-z]:\\)").unwrap()
});

// Value contains a file extension — likely a filename/URL, not a secret
static HAS_FILE_EXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\.(pdf|html?|js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|json|xml|ya?ml|txt|md|csv|zip|gz|tar|exe|dmg|pkg|deb|rpm|sh|bat|py|rb|go|rs|java|ts|tsx|jsx|vue|php)(?-u:\b)"
    )
    .unwrap()
});

// Value looks like a code identifier (variable, class, or constant name).
// Matches camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case,
// and dot-notation property paths — none of which are real secrets.
static CODE_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^_*[a-z][a-zA-Z0-9]*([A-Z][a-z0-9]+)+[a-zA-Z0-9]*$", // camelCase (2+ humps), optional _ prefix
        r"|^_*[A-Z][a-z]+([A-Z][a-z0-9]+)+$", // PascalCase (2+ humps), optional _ prefix
        r"|^_*[a-z]+(_[a-z0-9]+){2,}_*$", // snake_case (3+ segments), optional _/__ prefix/suffix
        r"|^_*[A-Z]+(_[A-Z0-9]+){2,}$",   // SCREAMING_SNAKE (3+ segments), optional _ prefix
        r"|^[a-zA-Z][a-zA-Z0-9]*(-[a-zA-Z0-9]+){2,}$", // kebab-case (3+ segments)
        r"|^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*){2,}$"  // dot-notation (3+ segments)
    ))
    .unwrap()
});

// Published, non-functional example credentials that appear verbatim in vendor
// docs and tutorials. Known-prefix and keyword kinds bypass the kind-specific FP
// checks below, so without this they are reported as real findings. ONLY add a
// value an official vendor publishes as a non-working example — never a guessed or
// scraped key, which could be a live leaked secret that this list would then
// silently suppress. AWS's keys carry the `EXAMPLE` marker and are also caught by
// the substring heuristic in `is_false_positive`; non-marked examples (Stripe's
// docs keys) require this exact-match set. Split with `concat!` so a contiguous
// secret-shaped literal never appears in source (see test_fixtures.rs rationale).
static EXAMPLE_ALLOWLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // AWS — canonical docs examples (also matched by the EXAMPLE heuristic;
        // listed explicitly for defense in depth).
        concat!("AKIA", "IOSFODNN7", "EXAMPLE"),
        concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"),
        // Stripe — documentation sample keys (test mode), present in every Stripe
        // API example. No EXAMPLE marker, so they need this exact-match entry.
        concat!("sk_test_", "4eC39HqLyjWDarjtT1zdp7dc"),
        concat!("pk_test_", "TYooMQauvdEDq54NiTphI7jx"),
    ])
});

static REGEX_SET: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(PATTERNS.iter().map(|p| p.regex.as_str())).unwrap());

const MAX_MATCH_LEN: usize = 2048;

pub struct SecretDetector;

impl SecretDetector {
    pub fn scan(text: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        let candidates = REGEX_SET.matches(text);
        for idx in candidates.iter() {
            let pattern = &PATTERNS[idx];

            // Known-prefix patterns have no capture groups — use faster find_iter.
            // Keyword/generic patterns use capture groups to extract the value.
            if !pattern.prefixes.is_empty() {
                for mat in pattern.regex.find_iter(text) {
                    if mat.len() > MAX_MATCH_LEN {
                        continue;
                    }
                    let matched_str = mat.as_str();

                    if Self::is_false_positive(&pattern.kind, matched_str) {
                        continue;
                    }

                    let redacted = Self::redact(matched_str);
                    let matched = matched_str.to_string();

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
            } else {
                for caps in pattern.regex.captures_iter(text) {
                    let full = caps.get(0).unwrap();
                    if full.len() > MAX_MATCH_LEN {
                        continue;
                    }
                    let matched_str = full.as_str();

                    // Use capture group 1 (the value) for false-positive checks
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

    // Template / interpolation / function-call wrappers are never literal
    // secrets: `{{cf-secret}}`, `${API_KEY}`, `getPassword()`, `<your-token>`,
    // `%API_KEY%`. Plain ASCII string ops — no regex (and the `regex` crate has
    // no backreferences, so such a pattern could not be expressed anyway).
    fn is_template_or_call(value: &str) -> bool {
        value.contains("{{")
            || value.contains("${")
            || value.ends_with("()")
            || (value.starts_with('<') && value.ends_with('>'))
            || (value.starts_with('%') && value.ends_with('%'))
    }

    // True when a single character repeats `n` or more times consecutively
    // (e.g. `AAAAA`) — a cheap structural tell for padded or templated blobs that
    // still clear the Shannon-entropy gate. Imperative because the `regex` crate
    // has no backreferences, so `(\S)\1{4,}` will not compile.
    fn has_repeated_run(value: &str, n: usize) -> bool {
        let mut prev = None;
        let mut run = 0usize;
        for c in value.chars() {
            run = if Some(c) == prev { run + 1 } else { 1 };
            prev = Some(c);
            if run >= n {
                return true;
            }
        }
        false
    }

    fn is_false_positive(kind: &SecretKind, value: &str) -> bool {
        // Universal pre-filter — runs for EVERY kind, including the known-prefix
        // and keyword kinds that otherwise fall straight through to `_ => false`.
        // Rejects published example credentials (e.g. `AKIAIOSFODNN7EXAMPLE`,
        // Stripe's docs keys) and template / interpolation / call placeholders.
        // `EXAMPLE` (case-sensitive) is AWS's documented example-key marker.
        if EXAMPLE_ALLOWLIST.contains(value)
            || value.contains("EXAMPLE")
            || Self::is_template_or_call(value)
        {
            return true;
        }

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
                // Keyword-anchored, but still require some randomness: a
                // low-entropy value (repeated chars, dictionary-ish) sitting
                // next to `api_key=` is far more likely config noise than a key.
                if Self::shannon_entropy(value) < 3.0 {
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
                // A run of 5+ identical chars signals padding/templating even when
                // the value clears the entropy bar (e.g. a base64 blob with `AAAAA`).
                if Self::has_repeated_run(value, 5) {
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

    /// Shannon entropy in bits per character
    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        // ASCII fast path: count bytes into a fixed stack histogram — no heap
        // allocation, no hashing. Every pattern's value class is ASCII-scoped so
        // this is the common case, and byte counts equal char counts here, so
        // the result is identical to the char path below.
        if s.is_ascii() {
            let mut freq = [0u32; 128];
            for &b in s.as_bytes() {
                freq[b as usize] += 1;
            }
            let len = s.len() as f64;
            let mut entropy = 0.0f64;
            for &count in &freq {
                if count != 0 {
                    let p = count as f64 / len;
                    entropy -= p * p.log2();
                }
            }
            return entropy;
        }
        // Non-ASCII fallback: count Unicode scalar values, not bytes. Only the
        // GenericSecret tier admits multi-byte UTF-8, where the per-symbol
        // buckets and the length must stay in chars — byte counting would change
        // the value and could flip the entropy gate.
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
        let len = chars.len();
        // Reveal scales with length (capped at 4 per side) so short secrets
        // aren't mostly exposed: a 9-char value shows 1+1, not 4+4 (8 of 9).
        let reveal = if len <= 8 { 0 } else { (len / 6).min(4) };
        if reveal == 0 {
            return "*".repeat(len);
        }
        let prefix: String = chars[..reveal].iter().collect();
        let suffix: String = chars[len - reveal..].iter().collect();
        format!("{}...{}", prefix, suffix)
    }

    fn deduplicate(findings: &mut Vec<SecretFinding>) {
        if findings.len() <= 1 {
            return;
        }
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(a.severity.cmp(&b.severity)));

        let mut kept: Vec<SecretFinding> = Vec::with_capacity(findings.len());
        let mut drain = findings.drain(..);

        // Track the current overlap cluster's coverage end separately from the
        // kept representative. Swapping the representative for a narrower, higher
        // severity match must NOT shrink the window used to absorb later
        // overlapping findings — otherwise a match nested inside the original
        // wide span leaks out as a spurious separate finding.
        let first = drain.next().expect("len > 1 checked above");
        let mut cluster_end = first.end;
        kept.push(first);

        for f in drain {
            if f.start < cluster_end {
                // Overlapping the cluster — extend coverage, and keep the higher
                // severity (lower ordinal) as the representative.
                cluster_end = cluster_end.max(f.end);
                if f.severity < kept.last().unwrap().severity {
                    *kept.last_mut().unwrap() = f;
                }
                // else: discard f, keep current representative
            } else {
                cluster_end = f.end;
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

        for f in existing.into_iter().chain(new) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{body, opaque, tok, UPPER_NUM, URL_SAFE};
    use crate::types::{SecretFinding, SecretKind, Severity};
    use rstest::rstest;

    // ── shannon_entropy ──────────────────────────────────────────────

    #[test]
    fn entropy_empty_string() {
        assert_eq!(SecretDetector::shannon_entropy(""), 0.0);
    }

    #[rstest]
    #[case("aaaaaaa", 0.0)]
    #[case("ab", 1.0)]
    #[case("aabb", 1.0)]
    fn entropy_known_values(#[case] input: &str, #[case] expected: f64) {
        let e = SecretDetector::shannon_entropy(input);
        assert!(
            (e - expected).abs() < 0.01,
            "entropy({input}) = {e}, expected {expected}"
        );
    }

    #[test]
    fn entropy_high_for_random_string() {
        // A realistic secret-like string should have high entropy
        let e = SecretDetector::shannon_entropy(&opaque(21));
        assert!(e > 3.5, "expected high entropy, got {e}");
    }

    #[test]
    fn entropy_low_for_repetitive() {
        let e = SecretDetector::shannon_entropy("abcabcabcabc");
        assert!(
            e < 2.0,
            "expected low entropy for repetitive string, got {e}"
        );
    }

    // ── redact ───────────────────────────────────────────────────────

    #[rstest]
    #[case("abc", "***")]
    #[case("12345678", "********")]
    #[case("short", "*****")]
    fn redact_short_strings(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(SecretDetector::redact(input), expected);
    }

    #[rstest]
    #[case("123456789", "1...9")] // 9 chars: 1+1, not 4+4
    #[case("0123456789abcdef", "01...ef")] // 16 chars: 2+2
    #[case(&format!("sk_live_{}", "abcdefghij"), "sk_...hij")] // 18 chars: 3+3
    #[case(&format!("AKIA{}", "0123456789ABCDEF0123"), "AKIA...0123")] // 24 chars: 4+4 (capped)
    fn redact_long_strings(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(SecretDetector::redact(input), expected);
    }

    // ── is_false_positive ────────────────────────────────────────────
    // Receives the extracted VALUE (capture group), not the full match.

    #[rstest]
    #[case("changeme")]
    #[case("TODO")]
    #[case("placeholder")]
    #[case("undefined")]
    #[case("your-api-key")]
    fn fp_generic_placeholder_values(#[case] value: &str) {
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            value
        ));
    }

    #[rstest]
    #[case("my-variable-name")]
    #[case("some-plain-words")]
    fn fp_generic_plain_words(#[case] value: &str) {
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            value
        ));
    }

    #[rstest]
    #[case("https://example.com/api")]
    #[case("/usr/local/config")]
    #[case("./config.json")]
    fn fp_generic_urls_and_paths(#[case] value: &str) {
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            value
        ));
    }

    #[test]
    fn fp_generic_camel_case_shaped_value_filtered() {
        // Alternating-case strings decompose into camelCase humps, so the
        // CODE_IDENTIFIER filter rejects them even when they look random.
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            "aB3xZ9qW7mK2pL5nR8vJ"
        ));
    }

    #[test]
    fn fp_generic_real_key_not_filtered() {
        // Digit-led opaque value defeats every identifier shape — and clears
        // the entropy gate, so the generic tier still flags real keys.
        assert!(!SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            &opaque(20)
        ));
    }

    #[test]
    fn fp_generic_low_entropy_filtered() {
        // Keyword-anchored but near-zero entropy ("Xy9" repeated): mixed-class
        // so it dodges the plain-word / identifier filters, but the entropy
        // gate (new) catches it.
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            "Xy9Xy9Xy9Xy9Xy9Xy9Xy9"
        ));
    }

    #[test]
    fn fp_generic_single_plain_word_filtered() {
        // A single lowercase word (no hyphen) is filtered now that PLAIN_WORDS
        // no longer requires one.
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericApiKey,
            "supersecretpassword"
        ));
    }

    #[test]
    fn fp_high_entropy_low_entropy_filtered() {
        assert!(SecretDetector::is_false_positive(
            &SecretKind::HighEntropyString,
            "abcabcabcabcabcabcabcabcabcabcabcabc"
        ));
    }

    #[test]
    fn fp_high_entropy_single_char_class_filtered() {
        // Only lowercase — fails the 2-of-3 character-class requirement
        assert!(SecretDetector::is_false_positive(
            &SecretKind::HighEntropyString,
            "qwertyuiopasdfghjklzxcvbnmqwerty"
        ));
    }

    #[test]
    fn fp_high_entropy_valid_not_filtered() {
        assert!(!SecretDetector::is_false_positive(
            &SecretKind::HighEntropyString,
            &opaque(32)
        ));
    }

    #[test]
    fn fp_bearer_token_strips_prefix_and_rejects_identifiers() {
        // The strip_prefix branch is defensive (scan passes capture group 1,
        // which excludes "Bearer "); this documents the intended behavior.
        assert!(SecretDetector::is_false_positive(
            &SecretKind::BearerToken,
            "Bearer myAuthTokenValueHandler"
        ));
        assert!(SecretDetector::is_false_positive(
            &SecretKind::BearerToken,
            "myAuthTokenValueHandler"
        ));
        assert!(!SecretDetector::is_false_positive(
            &SecretKind::BearerToken,
            &opaque(24)
        ));
    }

    #[test]
    fn fp_known_prefix_random_not_filtered() {
        // Known-prefix kinds skip the kind-specific checks, so a real (random)
        // token is never filtered — only the universal pre-filter (example
        // allowlist / EXAMPLE marker / template wrappers) can reject them.
        assert!(!SecretDetector::is_false_positive(
            &SecretKind::AwsAccessKey,
            &tok("AKIA", UPPER_NUM, 16)
        ));
    }

    #[test]
    fn fp_known_prefix_example_key_filtered() {
        // The canonical AWS docs key carries the EXAMPLE marker and must be
        // filtered even though known-prefix kinds bypass the kind-specific checks.
        assert!(SecretDetector::is_false_positive(
            &SecretKind::AwsAccessKey,
            concat!("AKIA", "IOSFODNN7", "EXAMPLE")
        ));
    }

    #[test]
    fn fp_allowlisted_stripe_test_key_filtered() {
        // Exact-match allowlist entry with no EXAMPLE marker (Stripe's docs key).
        assert!(SecretDetector::is_false_positive(
            &SecretKind::StripeKey,
            concat!("sk_test_", "4eC39HqLyjWDarjtT1zdp7dc")
        ));
    }

    #[rstest]
    #[case("${DATABASE_PASSWORD}")]
    #[case("{{cf-client-secret}}")]
    #[case("getPassword()")]
    #[case("<your-api-key>")]
    fn fp_template_and_call_values_filtered(#[case] value: &str) {
        // Universal pre-filter rejects interpolation / template / call wrappers
        // regardless of kind.
        assert!(SecretDetector::is_false_positive(
            &SecretKind::GenericSecret,
            value
        ));
    }

    #[test]
    fn fp_high_entropy_repeated_run_filtered() {
        // Clears the entropy gate and the 2-of-3 class check, but the 5+ identical
        // run (`AAAAA`) trips the structural reject.
        let value = format!("AAAAA{}", opaque(27));
        assert!(
            SecretDetector::shannon_entropy(&value) >= 3.5,
            "fixture must clear the entropy gate so the run check is what rejects it"
        );
        assert!(SecretDetector::is_false_positive(
            &SecretKind::HighEntropyString,
            &value
        ));
    }

    // ── deduplicate ──────────────────────────────────────────────────

    fn make_finding(start: usize, end: usize, severity: Severity) -> SecretFinding {
        SecretFinding {
            kind: SecretKind::GenericApiKey,
            label: "test".to_string(),
            matched_text: "redacted".to_string(),
            full_match: format!("match_{start}_{end}"),
            start,
            end,
            severity,
        }
    }

    #[test]
    fn dedup_overlapping_keeps_higher_severity() {
        let mut findings = vec![
            make_finding(0, 20, Severity::Medium),
            make_finding(10, 30, Severity::Critical),
        ];
        SecretDetector::deduplicate(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn dedup_non_overlapping_preserves_both() {
        let mut findings = vec![
            make_finding(0, 10, Severity::High),
            make_finding(20, 30, Severity::Low),
        ];
        SecretDetector::deduplicate(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_nested_overlap_absorbs_interior_finding() {
        // A wide low-severity span (0..100) fully contains a narrower, higher
        // severity match (10..20) at its front plus another interior match
        // (30..40). The interior finding must be absorbed by the cluster's
        // original coverage window even after the representative is swapped to
        // the higher-severity match — otherwise the coverage end shrinks to 20
        // and the interior finding leaks out as a spurious separate finding.
        let mut findings = vec![
            make_finding(0, 100, Severity::Low),
            make_finding(10, 20, Severity::Critical),
            make_finding(30, 40, Severity::Medium),
        ];
        SecretDetector::deduplicate(&mut findings);
        assert_eq!(
            findings.len(),
            1,
            "interior finding must be absorbed, not leaked"
        );
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    // ── merge_findings ───────────────────────────────────────────────

    #[test]
    fn merge_deduplicates_by_full_match() {
        let existing = vec![make_finding(0, 10, Severity::Medium)];
        let new = vec![make_finding(0, 10, Severity::Critical)];
        let merged = SecretDetector::merge_findings(existing, new);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].severity, Severity::Critical);
    }

    #[test]
    fn merge_keeps_higher_existing_severity() {
        let existing = vec![make_finding(0, 10, Severity::Critical)];
        let new = vec![make_finding(0, 10, Severity::Low)];
        let merged = SecretDetector::merge_findings(existing, new);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].severity, Severity::Critical);
    }

    #[test]
    fn merge_different_full_match_preserved() {
        let existing = vec![make_finding(0, 10, Severity::High)];
        let new = vec![make_finding(20, 30, Severity::High)];
        let merged = SecretDetector::merge_findings(existing, new);
        assert_eq!(merged.len(), 2);
    }

    // ── scan (integration) ───────────────────────────────────────────

    #[test]
    fn scan_detects_aws_key() {
        let text = format!("my key is {} here", tok("AKIA", UPPER_NUM, 16));
        let findings = SecretDetector::scan(&text);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].kind, SecretKind::AwsAccessKey));
    }

    #[test]
    fn scan_skips_aws_example_key() {
        // The canonical AWS docs key matches the AKIA pattern but is a published
        // non-functional example, so it must not be reported.
        let text = format!(
            "aws_access_key_id = {}",
            concat!("AKIA", "IOSFODNN7", "EXAMPLE")
        );
        let findings = SecretDetector::scan(&text);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.kind, SecretKind::AwsAccessKey)),
            "AWS example key should be filtered out"
        );
    }

    #[test]
    fn scan_clean_text_returns_empty() {
        let findings = SecretDetector::scan("Hello, this is perfectly normal text.");
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_skips_oversized_match() {
        // JWT's last segment is unbounded — inflate it past MAX_MATCH_LEN
        let long_jwt = format!(
            "eyJ{}.eyJ{}.{}",
            body(URL_SAFE, 12),
            body(URL_SAFE, 12),
            "A".repeat(MAX_MATCH_LEN)
        );
        let findings = SecretDetector::scan(&long_jwt);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.kind, SecretKind::JwtToken)),
            "oversized match should be skipped"
        );
    }
}
