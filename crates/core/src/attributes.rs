use serde::Deserialize;

#[derive(Deserialize)]
struct AttrPair {
    name: String,
    value: String,
}

/// Format attribute pairs from a JSON string (used by WASM layer).
pub fn format_attributes(pairs_json: &str) -> String {
    let pairs: Vec<AttrPair> = match serde_json::from_str(pairs_json) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };

    let as_tuples: Vec<(&str, &str)> = pairs
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    format_attributes_from_pairs(&as_tuples)
}

/// Format attribute pairs from typed data (used by CLI and library consumers).
pub fn format_attributes_from_pairs(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .filter(|(name, value)| !name.is_empty() && value.len() >= 8)
        .map(|(name, value)| format!("{}=\"{}\"", name, value.replace('"', "&quot;")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_valid_pairs_from_json() {
        let json = r#"[{"name":"data-x","value":"longvalue123"}]"#;
        assert_eq!(format_attributes(json), "data-x=\"longvalue123\"");
    }

    #[test]
    fn filters_short_values_and_empty_names() {
        assert_eq!(format_attributes(r#"[{"name":"a","value":"short"}]"#), "");
        assert_eq!(
            format_attributes(r#"[{"name":"","value":"longvalue123"}]"#),
            ""
        );
    }

    #[test]
    fn invalid_json_yields_empty() {
        assert_eq!(format_attributes("not json"), "");
    }

    #[test]
    fn escapes_double_quotes() {
        let json = r#"[{"name":"data-x","value":"a\"bcdefgh"}]"#;
        assert_eq!(format_attributes(json), "data-x=\"a&quot;bcdefgh\"");
    }

    #[test]
    fn from_pairs_filters_and_joins() {
        let pairs = [
            ("data-a", "longvalue1"),
            ("b", "short"),
            ("data-c", "anothervalue"),
        ];
        assert_eq!(
            format_attributes_from_pairs(&pairs),
            "data-a=\"longvalue1\"\ndata-c=\"anothervalue\""
        );
    }
}
