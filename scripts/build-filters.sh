#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "$0")/.."
OUT_DIR="$ROOT/target/components"
TARGET="wasm32-unknown-unknown"
BIN_DIR="$ROOT/target/$TARGET/release"

mkdir -p "$OUT_DIR"

# name|package-name
FILTERS=(
  "noop|noop"
  "pii-default|pii-default"
  "email-detect|email-detect"
  "ssn-detect|ssn-detect"
  "card-detect|card-detect"
  "envelope-encrypt|envelope-encrypt"
  "stable-encrypt|stable-encrypt"
)

for entry in "${FILTERS[@]}"; do
  name="${entry%%|*}"
  crate="${entry##*|}"
  # Rust crate names use underscores; package names use dashes.
  lib_name="${crate//-/_}"
  echo "=== Building ${crate} ==="
  cargo build --release -p "${crate}" --target "${TARGET}"
  wasm-tools component new \
    "${BIN_DIR}/${lib_name}.wasm" \
    -o "${OUT_DIR}/${name}.component.wasm"
  echo "    -> ${OUT_DIR}/${name}.component.wasm"
done

echo "=== All filters built ==="
