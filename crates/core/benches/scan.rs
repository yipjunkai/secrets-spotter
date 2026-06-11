//! Scan-throughput benchmark over a web-shaped corpus.
//!
//! Measures the real pipeline the extension and CLI run — URL/content-type
//! filter, source-specific preprocessing, secret scan, and finding merge —
//! across:
//!   * `benches/corpus/<site>/` — a committed, secret-free synthetic corpus
//!     (always present; drives the CI regression gate), and
//!   * `benches/sites/<site>/`  — optional real page dumps a developer drops in
//!     locally (gitignored; gives true real-world numbers when present).
//!
//! Secret-shaped fixtures are assembled at runtime (via the `fixtures` module,
//! shared verbatim with the unit tests) and never committed, so `just
//! scan-self` stays green.

use std::borrow::Cow;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};

use secrets_spotter_core::attributes::format_attributes;
use secrets_spotter_core::cookies::parse_cookies;
use secrets_spotter_core::detector::SecretDetector;
use secrets_spotter_core::filter::should_scan;
use secrets_spotter_core::types::{SecretFinding, SecretKind, Severity};

// Runtime fixture assembly, shared verbatim with the library's unit tests.
// Included by path because the module is `#[cfg(test)]`-private to the crate;
// this keeps a single source of truth without widening the public API.
#[allow(dead_code)]
#[path = "../src/test_fixtures.rs"]
mod fixtures;
use fixtures::{body, opaque, tok, ALNUM, DIGITS, UPPER_NUM, URL_SAFE};

/// How an intercepted payload reaches the scanner — mirrors the extension's
/// source types and selects the preprocessing step.
#[derive(Clone, Copy)]
enum Source {
    Dom,
    DomStructured,
    Cookie,
    NetworkFetch,
}

struct ScanRequest {
    text: String,
    url: String,
    content_type: String,
    source: Source,
}

/// The end-to-end per-payload pipeline: filter → preprocess → scan → merge.
fn process_scan_request(req: &ScanRequest, accumulated: Vec<SecretFinding>) -> Vec<SecretFinding> {
    if !req.url.is_empty() && !should_scan(&req.url, &req.content_type) {
        return accumulated;
    }

    let text: Cow<str> = match req.source {
        Source::Cookie => Cow::Owned(parse_cookies(&req.text)),
        Source::DomStructured => Cow::Owned(format_attributes(&req.text)),
        Source::Dom | Source::NetworkFetch => Cow::Borrowed(&req.text),
    };

    if text.len() < 10 {
        return accumulated;
    }

    let new = SecretDetector::scan(&text);
    SecretDetector::merge_findings(accumulated, new)
}

/// Maps a corpus filename to (source, content-type, synthetic URL), mirroring
/// the file-naming conventions the local-dump workflow documents.
fn classify_file(filename: &str) -> Option<(Source, &'static str, String)> {
    if filename.starts_with('.') {
        return None;
    }
    let lower = filename.to_lowercase();
    if lower == "readme.md" {
        return None;
    }
    if lower == "attributes.json" {
        return Some((
            Source::DomStructured,
            "",
            "https://bench.local/".to_string(),
        ));
    }
    if lower.contains("cookie") && lower.ends_with(".txt") {
        return Some((Source::Cookie, "", "https://bench.local/".to_string()));
    }
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        return Some((Source::Dom, "text/html", "https://bench.local/".to_string()));
    }
    if lower.ends_with(".json") {
        return Some((
            Source::NetworkFetch,
            "application/json",
            format!("https://bench.local/api/{filename}"),
        ));
    }
    // Everything else (.js, .txt, …) is treated as DOM text.
    Some((
        Source::Dom,
        "text/plain",
        "https://bench.local/".to_string(),
    ))
}

/// Reads one site directory into pre-loaded requests (file I/O excluded from
/// timing). Files are sorted by name for deterministic ordering.
fn load_site(dir: &Path) -> Vec<ScanRequest> {
    let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => return Vec::new(),
    };
    paths.sort();

    paths
        .into_iter()
        .filter_map(|path| {
            let filename = path.file_name()?.to_str()?;
            let (source, content_type, url) = classify_file(filename)?;
            let text = fs::read_to_string(&path).ok()?;
            if text.is_empty() {
                return None;
            }
            Some(ScanRequest {
                text,
                url,
                content_type: content_type.to_string(),
                source,
            })
        })
        .collect()
}

/// Lists site subdirectories under `benches/<subdir>/`, sorted by name.
fn find_sites(subdir: &str) -> Vec<(String, PathBuf)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join(subdir);
    let mut sites: Vec<(String, PathBuf)> = match fs::read_dir(&root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
            .collect(),
        Err(_) => return Vec::new(),
    };
    sites.sort_by(|a, b| a.0.cmp(&b.0));
    sites
}

/// A spread of real-shaped secrets, assembled at runtime (never committed).
/// Mixes known-prefix tokens (which match anywhere) with code-style keyword
/// assignments so the generic/entropy paths are exercised too.
fn assemble_secrets() -> Vec<String> {
    vec![
        tok("AKIA", UPPER_NUM, 16),                               // AWS access key
        tok("ghp_", ALNUM, 36),                                   // GitHub PAT
        format!("sk_live_{}", body(ALNUM, 24)),                   // Stripe secret key
        format!("xoxb-{}-{}", body(DIGITS, 12), body(ALNUM, 24)), // Slack bot token
        tok("AIza", URL_SAFE, 35),                                // Google API key
        format!(
            "eyJ{}.eyJ{}.{}",
            body(URL_SAFE, 16),
            body(URL_SAFE, 24),
            body(URL_SAFE, 32)
        ), // JWT
        tok("npm_", ALNUM, 36),                                   // npm token
        format!("api_key = \"{}\"", opaque(32)),                  // generic API key (code style)
        format!("session_secret = \"{}\"", opaque(40)),           // high-entropy secret
    ]
}

/// Splices `rounds` blocks of assembled secrets into `base` at even intervals,
/// so secrets sit in realistic surrounding context rather than in a clump.
fn seed_text(base: &str, rounds: usize) -> String {
    let secrets = assemble_secrets();
    if rounds == 0 || base.is_empty() {
        return base.to_string();
    }
    let step = (base.len() / rounds).max(1);
    let mut out = String::with_capacity(base.len() + rounds * secrets.len() * 80);
    let mut pos = 0usize;
    for r in 0..rounds {
        let mut cut = ((r + 1) * step).min(base.len());
        while cut < base.len() && !base.is_char_boundary(cut) {
            cut += 1;
        }
        out.push_str(&base[pos..cut]);
        pos = cut;
        for s in &secrets {
            out.push_str("\n<!-- ");
            out.push_str(s);
            out.push_str(" -->\n");
        }
    }
    if pos < base.len() {
        out.push_str(&base[pos..]);
    }
    out
}

fn make_findings(start: usize, count: usize) -> Vec<SecretFinding> {
    (0..count)
        .map(|i| {
            let id = start + i;
            SecretFinding {
                kind: SecretKind::GenericApiKey,
                label: "bench".to_string(),
                matched_text: "redacted".to_string(),
                full_match: format!("match_{id}"),
                start: id * 10,
                end: id * 10 + 8,
                severity: if id.is_multiple_of(2) {
                    Severity::High
                } else {
                    Severity::Low
                },
            }
        })
        .collect()
}

fn bench_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan");

    // Committed corpus (always) + optional local real-page dumps.
    let mut sites = find_sites("corpus");
    for (name, path) in find_sites("sites") {
        sites.push((format!("local-{name}"), path));
    }

    for (name, path) in &sites {
        let requests = load_site(path);
        if requests.is_empty() {
            continue;
        }
        let total: u64 = requests.iter().map(|r| r.text.len() as u64).sum();
        group.throughput(Throughput::Bytes(total));
        group.bench_with_input(BenchmarkId::new("clean", name), &requests, |b, reqs| {
            b.iter(|| {
                let mut findings: Vec<SecretFinding> = Vec::new();
                for req in reqs {
                    findings = process_scan_request(black_box(req), findings);
                }
                findings
            });
        });
    }

    // Seeded variant: the webapp DOM with runtime-injected secrets, so the
    // match → false-positive → dedup paths are exercised, not just the misses.
    let dom = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/corpus/webapp/dom.html");
    if let Ok(base) = fs::read_to_string(&dom) {
        let seeded = seed_text(&base, 3);
        let found = SecretDetector::scan(&seeded).len();
        assert!(
            found >= 8,
            "seeded corpus yielded only {found} findings — patterns may have changed"
        );
        group.throughput(Throughput::Bytes(seeded.len() as u64));
        group.bench_function(BenchmarkId::new("seeded", "webapp"), |b| {
            b.iter(|| SecretDetector::scan(black_box(&seeded)));
        });
    }

    group.finish();
}

fn bench_merge(c: &mut Criterion) {
    // Two finding sets with 50 overlapping full_match values, as the service
    // worker accumulates findings across scans of the same tab.
    let existing = make_findings(0, 100);
    let new = make_findings(50, 150);

    let mut group = c.benchmark_group("merge");
    group.bench_function("merge_findings/200", |b| {
        b.iter_batched(
            || (existing.clone(), new.clone()),
            |(e, n)| SecretDetector::merge_findings(e, n),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_scan, bench_merge);
criterion_main!(benches);
