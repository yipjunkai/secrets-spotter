use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use ignore::WalkBuilder;

use secrets_spotter_core::types::SecretFinding;

pub struct ScanResult {
    pub source: String,
    pub findings: Vec<SecretFinding>,
}

/// Compute the 1-based line number for a byte offset in text.
fn line_number(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset].matches('\n').count() + 1
}

/// Attach line numbers to findings based on their start offset in the scanned text.
fn enrich_findings(text: &str, findings: &mut [SecretFinding]) {
    for f in findings.iter_mut() {
        f.start = line_number(text, f.start);
        // Reuse `end` to hold the line number (for display purposes)
        f.end = f.start;
    }
}

pub fn scan_file(path: &Path, max_size: usize) -> Result<ScanResult> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Cannot access {}", path.display()))?;

    if metadata.len() as usize > max_size {
        return Ok(ScanResult {
            source: path.display().to_string(),
            findings: Vec::new(),
        });
    }

    let content = std::fs::read_to_string(path).unwrap_or_else(|_| {
        // Binary file or invalid UTF-8 — skip
        String::new()
    });

    let mut findings = secrets_spotter_core::scan_text(&content);
    enrich_findings(&content, &mut findings);

    Ok(ScanResult {
        source: path.display().to_string(),
        findings,
    })
}

pub fn scan_dir(dir: &Path, max_size: usize, glob_patterns: &[String]) -> Result<Vec<ScanResult>> {
    let mut builder = WalkBuilder::new(dir);
    builder.hidden(false).git_ignore(true).git_global(true);

    // Add glob filters via overrides
    if !glob_patterns.is_empty() {
        let mut overrides = ignore::overrides::OverrideBuilder::new(dir);
        for pattern in glob_patterns {
            overrides
                .add(pattern)
                .with_context(|| format!("Invalid glob pattern: {pattern}"))?;
        }
        builder.overrides(overrides.build()?);
    }

    let mut results = Vec::new();
    for entry in builder.build() {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let result = scan_file(path, max_size)?;
        if !result.findings.is_empty() {
            results.push(result);
        }
    }

    Ok(results)
}

pub fn scan_stdin(max_size: usize) -> Result<ScanResult> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("Failed to read from stdin")?;

    if content.len() > max_size {
        let mut end = max_size;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }
        content.truncate(end);
    }

    let mut findings = secrets_spotter_core::scan_text(&content);
    enrich_findings(&content, &mut findings);

    Ok(ScanResult {
        source: "<stdin>".to_string(),
        findings,
    })
}
