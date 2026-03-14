use anyhow::Result;
use colored::Colorize;
use serde::Serialize;

use secrets_spotter_core::types::Severity;

use crate::scan::ScanResult;

#[derive(Clone, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

pub fn print_results(results: &[ScanResult], format: Format) -> Result<()> {
    match format {
        Format::Text => print_text(results),
        Format::Json => print_json(results),
        Format::Sarif => print_sarif(results),
    }
}

fn severity_colored(severity: &Severity) -> colored::ColoredString {
    let label = format!("{severity:?}");
    match severity {
        Severity::Critical => label.red().bold(),
        Severity::High => label.yellow().bold(),
        Severity::Medium => label.yellow(),
        Severity::Low => label.blue(),
    }
}

fn print_text(results: &[ScanResult]) -> Result<()> {
    for result in results {
        for finding in &result.findings {
            println!(
                "[{}] {}",
                severity_colored(&finding.severity),
                finding.label
            );
            println!("  File: {}:{}", result.source, finding.start);
            println!("  Match: {}", finding.matched_text);
            println!();
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct JsonFinding {
    file: String,
    line: usize,
    kind: String,
    label: String,
    severity: String,
    matched_text: String,
}

fn print_json(results: &[ScanResult]) -> Result<()> {
    let mut all: Vec<JsonFinding> = Vec::new();
    for result in results {
        for finding in &result.findings {
            all.push(JsonFinding {
                file: result.source.clone(),
                line: finding.start,
                kind: format!("{:?}", finding.kind),
                label: finding.label.clone(),
                severity: format!("{:?}", finding.severity),
                matched_text: finding.matched_text.clone(),
            });
        }
    }
    println!("{}", serde_json::to_string_pretty(&all)?);
    Ok(())
}

#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn print_sarif(results: &[ScanResult]) -> Result<()> {
    let mut sarif_results = Vec::new();

    for result in results {
        for finding in &result.findings {
            sarif_results.push(SarifResult {
                rule_id: format!("{:?}", finding.kind),
                level: sarif_level(&finding.severity).to_string(),
                message: SarifMessage {
                    text: format!("{}: {}", finding.label, finding.matched_text),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: result.source.clone(),
                        },
                        region: SarifRegion {
                            start_line: finding.start,
                        },
                    },
                }],
            });
        }
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "secrets-spotter".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/anthropics/secrets-spotter".to_string(),
                },
            },
            results: sarif_results,
        }],
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
