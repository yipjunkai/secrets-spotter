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
