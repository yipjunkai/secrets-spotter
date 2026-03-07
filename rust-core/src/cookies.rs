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
            Some(format!("{key}=\"{value}\""))
        })
        .collect::<Vec<_>>()
        .join("\n")
}
