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

# Keep the adapter aligned with the workspace's Wasmtime major and verify the
# release asset instead of depending on arbitrary Cargo registry cache state.
ADAPTER_VERSION="47.0.0"
ADAPTER_SHA256="cdecdb3d5c06cd7cf585c865c6615dc9463777f0b45b74cc1b42ce630e2788e2"
ADAPTER_URL="https://github.com/bytecodealliance/wasmtime/releases/download/v${ADAPTER_VERSION}/wasi_snapshot_preview1.reactor.wasm"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    echo "ERROR: sha256sum or shasum is required" >&2
    return 1
  fi
}

ADAPTER="${S4_WASI_ADAPTER:-}"
if [ -z "$ADAPTER" ]; then
  ADAPTER_DIR="$ROOT/target/wasi-preview1-adapter-v${ADAPTER_VERSION}"
  ADAPTER="$ADAPTER_DIR/wasi_snapshot_preview1.reactor.wasm"
  mkdir -p "$ADAPTER_DIR"

  if [ ! -f "$ADAPTER" ] || [ "$(sha256_file "$ADAPTER")" != "$ADAPTER_SHA256" ]; then
    ADAPTER_TMP="${ADAPTER}.tmp"
    rm -f "$ADAPTER_TMP"
    curl --fail --location --retry 3 --silent --show-error "$ADAPTER_URL" -o "$ADAPTER_TMP"
    if [ "$(sha256_file "$ADAPTER_TMP")" != "$ADAPTER_SHA256" ]; then
      rm -f "$ADAPTER_TMP"
      echo "ERROR: checksum mismatch for WASI preview1 reactor adapter v${ADAPTER_VERSION}" >&2
      exit 1
    fi
    mv "$ADAPTER_TMP" "$ADAPTER"
  fi
elif [ ! -f "$ADAPTER" ]; then
  echo "ERROR: S4_WASI_ADAPTER does not exist: $ADAPTER" >&2
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

# Failure-injection component is built for runtime tests but never placed in the
# production auto-load directory.
TEST_OUT_DIR="$ROOT/target/test-components"
mkdir -p "$TEST_OUT_DIR"
cargo build --release -p test-filter --target "$TARGET"
wasm-tools component new \
  "${BIN_DIR}/test_filter.wasm" \
  --adapt "wasi_snapshot_preview1=${ADAPTER}" \
  -o "${TEST_OUT_DIR}/test-filter.component.wasm"

echo "=== All filters built (WASI) ==="
