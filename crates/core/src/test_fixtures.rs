//! Deterministic fixture assembly for tests.
//!
//! Secret-shaped fixtures must NEVER appear as contiguous literals in source:
//! GitHub push protection and the TruffleHog job in CI (verify.yml) both do
//! textual matching on raw file content and reject real-looking tokens. Every
//! positive fixture is therefore built at runtime by joining a prefix with a
//! generated body, so the assembled token exists only in memory. The `just
//! scan-self` recipe enforces this by scanning the source tree with our own
//! CLI.

/// Alphabets matching the character classes used by the patterns.
pub const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const HEX: &str = "0123456789abcdef";
pub const UPPER_NUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const URL_SAFE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub const DIGITS: &str = "0123456789";

/// Deterministic pseudo-random body in the given alphabet (LCG with a fixed
/// seed). High character diversity, identical on every run.
pub fn body(alphabet: &str, len: usize) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chars[((state >> 33) as usize) % chars.len()]
        })
        .collect()
}

/// `prefix` + generated body — the workhorse for known-prefix fixtures.
pub fn tok(prefix: &str, alphabet: &str, len: usize) -> String {
    format!("{prefix}{}", body(alphabet, len))
}

/// Digit-led opaque value for generic/keyword fixtures. Never matches the
/// detector's CODE_IDENTIFIER shapes (camelCase, PascalCase, etc. all require
/// a letter start), while keeping high entropy and mixed character classes.
pub fn opaque(len: usize) -> String {
    format!("9{}", body(ALNUM, len - 1))
}
