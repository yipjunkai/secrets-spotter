//! CLI integration tests.
//!
//! Secret fixtures are assembled at runtime so the full token never appears as a
//! contiguous literal in source — keeps the `scan-self` dogfood guard (and push
//! protection) quiet. Real secrets are only ever written into temp files outside
//! the repo, never into this source file.

use std::fs;
use std::process::Command as StdCommand;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

/// AWS example key ID — Critical.
fn aws_key() -> String {
    format!("AKIA{}", "IOSFODNN7EXAMPLE")
}

/// Stripe publishable key — Low severity (public by design).
fn stripe_publishable() -> String {
    format!("pk_live_{}", "0123456789abcdefghijABCD")
}

fn bin() -> Command {
    Command::cargo_bin("secrets-spotter").unwrap()
}

#[test]
fn clean_stdin_exits_zero() {
    bin()
        .write_stdin("nothing secret to see here\n")
        .assert()
        .code(0);
}

#[test]
fn secret_in_stdin_exits_one() {
    bin()
        .write_stdin(format!("aws key: {}\n", aws_key()))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS Access Key ID"));
}

#[test]
fn quiet_suppresses_output_but_keeps_exit_code() {
    bin()
        .arg("--quiet")
        .write_stdin(format!("{}\n", aws_key()))
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn json_format_emits_findings() {
    bin()
        .args(["--format", "json"])
        .write_stdin(format!("{}\n", aws_key()))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS Access Key ID"));
}

#[test]
fn severity_filter_excludes_lower() {
    // A Stripe publishable key is Low severity: reported at the default level...
    bin()
        .write_stdin(format!("{}\n", stripe_publishable()))
        .assert()
        .code(1);
    // ...but filtered out when only Critical is requested.
    bin()
        .args(["--severity", "critical"])
        .write_stdin(format!("{}\n", stripe_publishable()))
        .assert()
        .code(0);
}

#[test]
fn nonexistent_path_exits_two() {
    bin()
        .arg("/no/such/path/secrets-spotter-test-xyz")
        .assert()
        .code(2);
}

#[test]
fn scans_directory_and_finds_secret() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("config.txt"),
        format!("key = {}", aws_key()),
    )
    .unwrap();
    bin()
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS Access Key ID"));
}

#[test]
fn no_ignore_scans_gitignored_files() {
    let dir = tempdir().unwrap();
    // Make it a git repo so .gitignore takes effect.
    StdCommand::new("git")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("git init");
    fs::write(dir.path().join(".gitignore"), "secret.env\n").unwrap();
    fs::write(
        dir.path().join("secret.env"),
        format!("AWS_KEY={}", aws_key()),
    )
    .unwrap();

    // Default: the gitignored file is skipped → nothing found.
    bin().arg(dir.path()).assert().code(0);
    // --no-ignore: the gitignored file is scanned → found.
    bin()
        .arg("--no-ignore")
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS Access Key ID"));
}

#[test]
fn reports_the_finding_line_number() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("creds.txt");
    // Secret on the 3rd line.
    fs::write(&file, format!("first line\nsecond line\nkey = {}\n", aws_key())).unwrap();
    bin()
        .arg(&file)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("creds.txt:3"));
}

#[test]
fn warns_about_oversized_skipped_files() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("big.txt");
    fs::write(&file, format!("key = {}\n", aws_key())).unwrap();
    // max-size below the file size → skipped entirely → exit 0 + a stderr notice.
    bin()
        .args(["--max-size", "5"])
        .arg(&file)
        .assert()
        .code(0)
        .stderr(predicate::str::contains("over the size limit"));
}
