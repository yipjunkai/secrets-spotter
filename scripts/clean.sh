#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_CRATE="$PROJECT_ROOT/rust-core"
WASM_OUT="$PROJECT_ROOT/extension/wasm"

echo "==> Cleaning WASM build output..."
rm -rf "$WASM_OUT"

echo "==> Cleaning Rust build artifacts..."
cd "$RUST_CRATE"
cargo clean

echo "==> Clean complete!"
