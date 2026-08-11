#!/usr/bin/env bash
set -euo pipefail

echo "=== cargo fmt --check ==="
cargo fmt --check

echo "=== cargo clippy ==="
cargo clippy --all-targets -- -D warnings

echo "=== building filters ==="
bash scripts/build-filters.sh

echo "=== cargo test ==="
cargo test --workspace

echo "=== All Phase 0 checks passed ==="
