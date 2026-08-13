#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "$0")/.."
OUT_DIR="$ROOT/target/components"
# WASI preview 1 target: filters are proper WASI reactors, not bare
# wasm32-unknown-unknown modules. The wasi_snapshot_preview1.reactor adapter
# lifts WASI preview1 imports to component-model WASI, so filters can use
# standard WASI interfaces (random, io, environment) when they need them.
TARGET="wasm32-wasip1"
BIN_DIR="$ROOT/target/$TARGET/release"

# The reactor adapter ships with the wasi-preview1-component-adapter-provider
# crate (a dev-dependency of this repo); fall back to the wit-bindgen-cli one.
ADAPTER="${S4_WASI_ADAPTER:-}"
if [ -z "$ADAPTER" ]; then
  ADAPTER=$(find "$HOME/.cargo/registry/src" -name "wasi_snapshot_preview1.reactor.wasm" 2>/dev/null | head -1)
fi
if [ -z "$ADAPTER" ]; then
  echo "ERROR: wasi_snapshot_preview1.reactor.wasm adapter not found; install wasi-preview1-component-adapter-provider" >&2
  exit 1
fi

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
  echo "=== Building ${crate} (WASI) ==="
  cargo build --release -p "${crate}" --target "${TARGET}"
  wasm-tools component new \
    "${BIN_DIR}/${lib_name}.wasm" \
    --adapt "wasi_snapshot_preview1=${ADAPTER}" \
    -o "${OUT_DIR}/${name}.component.wasm"
  echo "    -> ${OUT_DIR}/${name}.component.wasm (WASI)"
done

echo "=== All filters built (WASI) ==="
