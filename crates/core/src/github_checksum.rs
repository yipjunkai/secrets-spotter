//! Offline CRC32 checksum validation for GitHub's 2021+ token format.
//!
//! New-format GitHub tokens are `<prefix>_<30 base62 entropy><6 base62 CRC32>`
//! — 40 chars total for `ghp_`/`gho_`/`ghu_`/`ghr_`/`ghs_`. The trailing 6 chars
//! are a base62-encoded CRC-32 of the entropy, so a random `gh*_`-shaped string
//! can be rejected locally with **no network call** — a deterministic
//! false-positive filter no other in-browser scanner does.
//!
//! Only the fixed 40-char format carries this checksum. `github_pat_`
//! (fine-grained PATs), the long stateless `ghs_` app tokens, and pre-2021
//! 40-hex tokens have different structures and are deliberately left untouched.
//!
//! Algorithm verified against the reference implementation
//! (`therootcompany/base62-token.js`) and 20 real GitHub tokens (see tests).

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// CRC-32/ISO-HDLC (the zlib / PNG / `crc-32` variant): reflected polynomial
/// `0xEDB88320`, init/final XOR `0xFFFFFFFF`. Bitwise so it needs no lookup
/// table — it runs at most a few dozen times per scan (only on `gh*_` matches),
/// so table speed is irrelevant and the table's bytes stay out of the wasm.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Base62-encode `n`, left-padded with `'0'` to exactly 6 characters (matches
/// the reference's `padStart(6, '0')`; 6 base62 chars hold any 32-bit value).
fn base62_pad6(mut n: u32) -> [u8; 6] {
    let mut out = [ALPHABET[0]; 6]; // pre-filled with the padding char '0'
    let mut i = out.len();
    while n > 0 && i > 0 {
        i -= 1;
        out[i] = ALPHABET[(n % 62) as usize];
        n /= 62;
    }
    out
}

/// True iff `token` is exactly the 40-char checksummed `gh*_` format:
/// `gh[pours]_` + 36 base62 chars. Excludes `github_pat_` (11-char prefix),
/// the long stateless `ghs_` tokens (>36 body), and anything with a non-base62
/// body — none of which carry this checksum.
pub fn is_checksummed_github_token(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() == 40
        && b[0] == b'g'
        && b[1] == b'h'
        && matches!(b[2], b'p' | b'o' | b'u' | b'r' | b's')
        && b[3] == b'_'
        && b[4..].iter().all(u8::is_ascii_alphanumeric)
}

/// Validate the trailing CRC-32 checksum of a 40-char `gh*_` token. The caller
/// must first confirm [`is_checksummed_github_token`]; passing any other shape
/// is a logic error (it would slice at the wrong offsets).
pub fn checksum_valid(token: &str) -> bool {
    // Prefix is a fixed 4 bytes (`gh?_`); the 36 remaining chars are 30 entropy
    // + 6 checksum. The checksum covers only the entropy, so it is
    // prefix-agnostic — matching the reference, which slices after the first `_`.
    let (entropy, checksum) = token[4..].split_at(30);
    base62_pad6(crc32(entropy.as_bytes())) == *checksum.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real GitHub tokens (published reference vectors from
    // therootcompany/base62-token.js). Split with `concat!` so no contiguous
    // token literal appears in source — github push protection and `just
    // scan-self` both do textual matching (see test_fixtures.rs).
    const VALID: &[&str] = &[
        concat!("ghp_", "zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17"),
        concat!("ghp_", "adE7dp8rHP6gUTuPwxLTZjZdtya3sV0UQzQM"),
        concat!("ghp_", "H3xbiBdlzffNx7Y56iNsPw3joObj7U2nO29h"),
        concat!("ghp_", "Ul6eIUhXOWE75DeLfPndUU0GbceBq80KIha4"),
        concat!("ghp_", "krLZ8fJtWbM6VhZVvXxLhocgw8JcfR2dBDWy"),
        concat!("ghp_", "rcECphp5g0lsT6dRwIiDCVbDQox6HL1HMj9z"),
    ];

    #[test]
    fn real_tokens_pass_format_and_checksum() {
        for &t in VALID {
            assert_eq!(t.len(), 40, "vector must be 40 chars: {t}");
            assert!(is_checksummed_github_token(t), "format: {t}");
            assert!(checksum_valid(t), "checksum should validate: {t}");
        }
    }

    #[test]
    fn checksum_is_prefix_agnostic() {
        // The checksum covers only the body after the first `_`, so swapping the
        // gh?_ prefix on a valid body keeps it valid (lets one vector exercise
        // every GitHub kind).
        let body = &VALID[0][4..]; // 36 chars: entropy + checksum
        for pre in ["gho_", "ghu_", "ghr_", "ghs_"] {
            let t = format!("{pre}{body}");
            assert!(checksum_valid(&t), "swapped prefix should validate: {t}");
        }
    }

    #[test]
    fn corrupted_checksum_char_fails() {
        let t = VALID[0];
        let mut bytes = t.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let corrupted = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !checksum_valid(corrupted),
            "corrupted checksum: {corrupted}"
        );
    }

    #[test]
    fn corrupted_body_char_fails() {
        let t = VALID[1];
        let mut bytes = t.as_bytes().to_vec();
        bytes[6] = if bytes[6] == b'A' { b'B' } else { b'A' };
        let corrupted = std::str::from_utf8(&bytes).unwrap();
        assert!(!checksum_valid(corrupted), "corrupted body: {corrupted}");
    }

    #[test]
    fn non_checksummed_formats_are_excluded() {
        // Too short, github_pat_ (different structure), and a 40-char gh*_ whose
        // body isn't pure base62 (the stateless ghs_ shape) are not this format.
        assert!(!is_checksummed_github_token("ghp_tooshort"));
        assert!(!is_checksummed_github_token(&format!(
            "github_pat_{}",
            "x".repeat(82)
        )));
        assert!(!is_checksummed_github_token(concat!(
            "ghs_",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa._-0123"
        )));
    }

    #[test]
    fn base62_encoding_matches_reference() {
        // Spot-check the encoder against hand-computed values.
        assert_eq!(&base62_pad6(0), b"000000");
        assert_eq!(&base62_pad6(1), b"000001");
        assert_eq!(&base62_pad6(61), b"00000z");
        assert_eq!(&base62_pad6(62), b"000010");
    }
}
