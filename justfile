wasm-out := "extension/wasm"

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

# Run all workspace tests
test:
    cargo test --workspace

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
