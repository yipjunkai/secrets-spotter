pub fn parse_cookies(raw: &str) -> String {
    raw.split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            let (key, value) = pair.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            let escaped = value.replace('"', "\\\"");
            Some(format!("{key}=\"{escaped}\""))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("a=1; b=2", "a=\"1\"\nb=\"2\"")]
    #[case("  a = 1 ;  b=2  ", "a=\"1\"\nb=\"2\"")] // surrounding whitespace trimmed
    fn parses_basic_pairs(#[case] raw: &str, #[case] expected: &str) {
        assert_eq!(parse_cookies(raw), expected);
    }

    #[rstest]
    #[case("a=; =2; c=3", "c=\"3\"")] // empty key or value dropped
    #[case("novalue; a=1", "a=\"1\"")] // pair without '=' dropped
    #[case("", "")]
    fn drops_malformed_pairs(#[case] raw: &str, #[case] expected: &str) {
        assert_eq!(parse_cookies(raw), expected);
    }

    #[test]
    fn escapes_double_quotes_in_value() {
        assert_eq!(parse_cookies("token=ab\"cd"), "token=\"ab\\\"cd\"");
    }
}
