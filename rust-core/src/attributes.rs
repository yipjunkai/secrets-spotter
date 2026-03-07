use serde::Deserialize;

#[derive(Deserialize)]
struct AttrPair {
    name: String,
    value: String,
}

pub fn format_attributes(pairs_json: &str) -> String {
    let pairs: Vec<AttrPair> = match serde_json::from_str(pairs_json) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };

    pairs
        .iter()
        .filter(|p| !p.name.is_empty() && p.value.len() >= 8)
        .map(|p| format!("{}=\"{}\"", p.name, p.value))
        .collect::<Vec<_>>()
        .join("\n")
}
