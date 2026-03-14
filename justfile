wasm-out := "extension/wasm"

# Build everything (CLI + WASM extension)
build: build-cli build-wasm

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

# Check formatting and lints (native + wasm)
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
