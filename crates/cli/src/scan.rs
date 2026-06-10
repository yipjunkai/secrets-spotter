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
    let metadata =
        std::fs::metadata(path).with_context(|| format!("Cannot access {}", path.display()))?;

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

    let mut findings = secrets_spotter_core::scan_text_limited(&content, max_size);
    enrich_findings(&content, &mut findings);

    Ok(ScanResult {
        source: path.display().to_string(),
        findings,
    })
}

pub fn scan_dir(
    dir: &Path,
    max_size: usize,
    glob_patterns: &[String],
    no_ignore: bool,
) -> Result<Vec<ScanResult>> {
    let mut builder = WalkBuilder::new(dir);
    builder
        .hidden(false)
        .git_ignore(!no_ignore)
        .git_global(!no_ignore)
        .git_exclude(!no_ignore)
        .ignore(!no_ignore);

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
        // A single unreadable directory or entry must not abort the whole scan
        // and discard everything found so far — warn and keep going.
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("secrets-spotter: skipping unreadable entry: {err}");
                continue;
            }
        };
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        match scan_file(path, max_size) {
            Ok(result) if !result.findings.is_empty() => results.push(result),
            Ok(_) => {}
            Err(err) => eprintln!("secrets-spotter: skipping {}: {err}", path.display()),
        }
    }

    Ok(results)
}

pub fn scan_stdin(max_size: usize) -> Result<ScanResult> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("Failed to read from stdin")?;

    let mut findings = secrets_spotter_core::scan_text_limited(&content, max_size);
    enrich_findings(&content, &mut findings);

    Ok(ScanResult {
        source: "<stdin>".to_string(),
        findings,
    })
}
