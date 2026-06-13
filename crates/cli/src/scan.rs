use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use ignore::WalkBuilder;

use secrets_spotter_core::types::SecretFinding;

/// A core finding paired with its 1-based line number. The CLI needs line
/// numbers for display, but `SecretFinding.start`/`end` are byte offsets —
/// so the line is carried alongside rather than overwriting those fields.
pub struct CliFinding {
    pub finding: SecretFinding,
    pub line: usize,
}

/// Why a file produced no scan — surfaced as an end-of-run stderr notice so a
/// clean exit isn't mistaken for "scanned everything".
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Oversized,
    Unreadable,
}

pub struct ScanResult {
    pub source: String,
    pub findings: Vec<CliFinding>,
    pub skipped: Option<SkipReason>,
}

/// Compute the 1-based line number for a byte offset in text.
fn line_number(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset.min(text.len())].matches('\n').count() + 1
}

fn to_cli_findings(text: &str, findings: Vec<SecretFinding>) -> Vec<CliFinding> {
    findings
        .into_iter()
        .map(|finding| {
            let line = line_number(text, finding.start);
            CliFinding { finding, line }
        })
        .collect()
}

pub fn scan_file(path: &Path, max_size: usize) -> Result<ScanResult> {
    let source = path.display().to_string();
    let metadata =
        std::fs::metadata(path).with_context(|| format!("Cannot access {}", path.display()))?;

    if metadata.len() as usize > max_size {
        return Ok(ScanResult {
            source,
            findings: Vec::new(),
            skipped: Some(SkipReason::Oversized),
        });
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        // Binary file or invalid UTF-8 — can't scan as text.
        Err(_) => {
            return Ok(ScanResult {
                source,
                findings: Vec::new(),
                skipped: Some(SkipReason::Unreadable),
            })
        }
    };

    let findings = secrets_spotter_core::scan_text_limited(&content, max_size);
    Ok(ScanResult {
        source,
        findings: to_cli_findings(&content, findings),
        skipped: None,
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
    let mut oversized = 0usize;
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
            Ok(result) => {
                match result.skipped {
                    Some(SkipReason::Oversized) => oversized += 1,
                    // Binary / non-UTF-8 skips are benign and numerous (images,
                    // archives, .git objects, ...) — not worth a notice.
                    Some(SkipReason::Unreadable) | None => {}
                }
                if !result.findings.is_empty() {
                    results.push(result);
                }
            }
            Err(err) => eprintln!("secrets-spotter: skipping {}: {err}", path.display()),
        }
    }

    notify_skipped(oversized);
    Ok(results)
}

/// Warn when files were skipped for exceeding the size limit — a too-big *text*
/// file may hide secrets, so a clean exit shouldn't be read as "scanned
/// everything". Binary / non-UTF-8 skips are intentionally silent (no scannable
/// text, and there are many).
pub fn notify_skipped(oversized: usize) {
    if oversized == 0 {
        return;
    }
    eprintln!(
        "secrets-spotter: skipped {oversized} file(s) over the size limit \
         (raise --max-size to include them)"
    );
}

pub fn scan_stdin(max_size: usize) -> Result<ScanResult> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("Failed to read from stdin")?;

    let findings = secrets_spotter_core::scan_text_limited(&content, max_size);
    Ok(ScanResult {
        source: "<stdin>".to_string(),
        findings: to_cli_findings(&content, findings),
        skipped: None,
    })
}
