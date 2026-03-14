mod output;
mod scan;

use std::process;

use anyhow::Result;
use clap::Parser;

use crate::output::Format;
use crate::scan::ScanResult;

#[derive(Parser)]
#[command(
    name = "secrets-spotter",
    version,
    about = "Detect secrets in files and directories"
)]
struct Cli {
    /// Files or directories to scan (reads from stdin if omitted)
    #[arg()]
    paths: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Minimum severity to report
    #[arg(short, long, value_enum, default_value_t = SeverityFilter::Low)]
    severity: SeverityFilter,

    /// Only scan files matching glob pattern (e.g. "*.js,*.env")
    #[arg(short, long)]
    glob: Option<String>,

    /// Max file size in bytes
    #[arg(long, default_value_t = secrets_spotter_core::MAX_SCAN_SIZE)]
    max_size: usize,

    /// Suppress output, exit code only
    #[arg(short, long)]
    quiet: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

#[derive(Clone, clap::ValueEnum)]
enum SeverityFilter {
    Critical,
    High,
    Medium,
    Low,
}

impl SeverityFilter {
    fn matches(&self, severity: &secrets_spotter_core::types::Severity) -> bool {
        use secrets_spotter_core::types::Severity;
        match self {
            SeverityFilter::Low => true,
            SeverityFilter::Medium => matches!(
                severity,
                Severity::Critical | Severity::High | Severity::Medium
            ),
            SeverityFilter::High => matches!(severity, Severity::Critical | Severity::High),
            SeverityFilter::Critical => matches!(severity, Severity::Critical),
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let glob_patterns: Vec<String> = cli
        .glob
        .as_deref()
        .map(|g| g.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let results: Vec<ScanResult> = if cli.paths.is_empty() {
        vec![scan::scan_stdin(cli.max_size)?]
    } else {
        let mut all = Vec::new();
        for path in &cli.paths {
            let p = std::path::Path::new(path);
            if p.is_dir() {
                all.extend(scan::scan_dir(p, cli.max_size, &glob_patterns)?);
            } else {
                all.push(scan::scan_file(p, cli.max_size)?);
            }
        }
        all
    };

    // Filter by severity
    let results: Vec<ScanResult> = results
        .into_iter()
        .map(|mut r| {
            r.findings.retain(|f| cli.severity.matches(&f.severity));
            r
        })
        .filter(|r| !r.findings.is_empty())
        .collect();

    let has_findings = !results.is_empty();

    if !cli.quiet {
        output::print_results(&results, cli.format)?;
    }

    if has_findings {
        process::exit(1);
    }
    Ok(())
}
