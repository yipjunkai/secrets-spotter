#![no_main]
//! Fuzz the scan path over arbitrary (lossy-decoded) input.
//!
//! Beyond "no panic", asserts the finding-span contract the extension relies
//! on when it slices page text by `start..end`:
//!   * spans are ordered and in-bounds,
//!   * spans land on UTF-8 char boundaries (a non-boundary slice panics), and
//!   * `full_match` is exactly the bytes the span points at.
//! Also checks determinism — the same input must yield the same spans.

use libfuzzer_sys::fuzz_target;
use secrets_spotter_core::{scan_text_limited, MAX_SCAN_SIZE};

fn spans(findings: &[secrets_spotter_core::types::SecretFinding]) -> Vec<(usize, usize)> {
    findings.iter().map(|f| (f.start, f.end)).collect()
}

fuzz_target!(|data: &[u8]| {
    // Peel a cap off the front so the 2 MiB-boundary truncation loop is fuzzed
    // too; the rest is the text. Bounded by MAX_SCAN_SIZE.
    let (cap, rest) = match data.split_first_chunk::<3>() {
        Some((c, rest)) => {
            let cap = u32::from_le_bytes([c[0], c[1], c[2], 0]) as usize % (MAX_SCAN_SIZE + 1);
            (cap, rest)
        }
        None => (MAX_SCAN_SIZE, data),
    };

    // We scan the lossy string and the findings index into it. `s` shares a
    // prefix with the internally-truncated text, so indices into the truncated
    // text are valid indices into `s` with identical bytes.
    let s = String::from_utf8_lossy(rest);
    let findings = scan_text_limited(&s, cap);

    for f in &findings {
        assert!(f.start <= f.end, "span start past end: {f:?}");
        assert!(f.end <= s.len(), "span end past input length: {f:?}");
        assert!(
            s.is_char_boundary(f.start) && s.is_char_boundary(f.end),
            "span not on char boundaries: {f:?}"
        );
        assert_eq!(
            f.full_match.as_str(),
            &s[f.start..f.end],
            "full_match disagrees with its own span"
        );
    }

    // Determinism: a second scan of the same input yields the same spans.
    let again = scan_text_limited(&s, cap);
    assert_eq!(spans(&findings), spans(&again), "scan is nondeterministic");
});
