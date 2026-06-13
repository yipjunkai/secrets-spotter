wasm-out := "extension/wasm"

# Hard ceiling on the shipped wasm (bytes). ASCII-only regex keeps it ~669 KB;
# this catches a Unicode-table regression (which jumps it back to ~970 KB). The
# headroom (~12%) absorbs toolchain drift — CI's wasm-pack differs from local.
wasm-budget := "770000"

# Build everything (CLI + WASM in parallel; fails if either build fails)
build:
    #!/usr/bin/env bash
    set -euo pipefail
    just build-cli & pid_cli=$!
    just build-wasm & pid_wasm=$!
    wait $pid_cli
    wait $pid_wasm

# Build CLI binary
build-cli:
    cargo build --release -p secrets-spotter

# Build WASM for Chrome extension
build-wasm:
    wasm-pack build crates/wasm --target web --out-dir ../../{{wasm-out}} --release
    rm -f {{wasm-out}}/.gitignore {{wasm-out}}/package.json {{wasm-out}}/*.d.ts

# Deterministic wasm size gate (Gate 2). Asserts the built artifact is within
# `wasm-budget`. Build first (`just build-wasm`); CI runs it after `just build`.
check-wasm-size:
    #!/usr/bin/env bash
    set -euo pipefail
    f="{{wasm-out}}/secrets_spotter_wasm_bg.wasm"
    [ -f "$f" ] || { echo "::error::$f not built — run 'just build-wasm' first"; exit 1; }
    size=$(wc -c < "$f" | tr -d ' ')
    echo "wasm size: ${size} bytes (budget {{wasm-budget}})"
    if [ "$size" -gt "{{wasm-budget}}" ]; then
      echo "::error::wasm ${size}B exceeds budget {{wasm-budget}}B — did a regex re-enable Unicode tables?"
      exit 1
    fi

# Run all workspace tests
test:
    cargo test --workspace

# Run the extension JS test suite (vitest + happy-dom). Requires `npm ci` first.
test-js:
    npm test

# Run scan-throughput benchmarks (native, speed-optimized bench profile).
# Reads the committed corpus under crates/core/benches/corpus/ plus any local
# real-page dumps in crates/core/benches/sites/ (gitignored).
bench:
    cargo bench -p secrets-spotter-core --bench scan

# Dogfood: scan our own source with the CLI — must find nothing.
# Guards the test-fixture policy: secret-shaped strings must never appear
# as contiguous literals in source (see crates/core/src/test_fixtures.rs).
scan-self:
    cargo run -q -p secrets-spotter -- .

# Fuzz one target for `secs` seconds (default 60). Uses the standalone fuzz/
# workspace and its pinned nightly. Targets: scan_text, merge_findings,
# parse_cookies, format_attributes, should_scan.
#
# First corpus dir (corpus/<target>, gitignored) is the writable working set;
# seeds/<target> is read-only baseline input. Order matters — never pass seeds
# first, or libFuzzer writes evolved inputs back into the committed seed dir.
fuzz target='scan_text' secs='60':
    cd fuzz && mkdir -p corpus/{{target}} && \
        cargo fuzz run {{target}} corpus/{{target}} seeds/{{target}} -- -max_total_time={{secs}}

# Check formatting and lints
lint:
    cargo fmt --all -- --check
    cargo clippy -p secrets-spotter-core -p secrets-spotter -- -D warnings
    cargo clippy -p secrets-spotter-wasm --target wasm32-unknown-unknown -- -D warnings

# Auto-format and apply lint fixes
format:
    cargo fmt --all
    cargo clippy -p secrets-spotter-core -p secrets-spotter --fix --allow-dirty --allow-staged -- -D warnings
    cargo clippy -p secrets-spotter-wasm --target wasm32-unknown-unknown --fix --allow-dirty --allow-staged -- -D warnings

# Clean all build artifacts
clean:
    rm -rf {{wasm-out}}
    cargo clean
