#![no_main]
//! Fuzz the findings-merge path with attacker-controlled "new" findings.
//!
//! Mirrors the extension merging a tab's freshly-scanned findings into the set
//! already shown. The invariant — frozen here after the regression fixed in
//! PR #16 ("preserve tab findings when merge input fails to deserialize") — is
//! that no previously-held finding is ever dropped, whatever the new input is.

use libfuzzer_sys::fuzz_target;
use secrets_spotter_core::test_fixtures::{tok, UPPER_NUM};
use secrets_spotter_core::types::SecretFinding;
use secrets_spotter_core::{merge_findings, scan_text};

fuzz_target!(|data: &[u8]| {
    // Try to deserialize the fuzzer bytes as the "new" findings list. Most
    // inputs fail to parse — that path (Err -> caller keeps existing) is the
    // exact PR #16 scenario and must not lose anything either, but there's
    // nothing to merge, so we only exercise the Ok branch here.
    let Ok(new) = serde_json::from_slice::<Vec<SecretFinding>>(data) else {
        return;
    };

    // A fixed, non-empty existing set built from a real fixture token (assembled
    // at runtime via the `fixtures` feature, never a source literal).
    let existing = scan_text(&tok("AKIA", UPPER_NUM, 16));
    assert!(!existing.is_empty(), "fixture failed to produce a finding");
    let existing_keys: Vec<String> = existing.iter().map(|f| f.full_match.clone()).collect();

    let merged = merge_findings(existing, new);

    for key in &existing_keys {
        assert!(
            merged.iter().any(|f| &f.full_match == key),
            "merge dropped an existing finding (full_match={key})"
        );
    }
});
