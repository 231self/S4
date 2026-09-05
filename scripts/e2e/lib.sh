#!/usr/bin/env bash
# Shared harness for the Maskura local e2e.
#
# Sourced by scripts/e2e-local.sh (the orchestrator that owns infrastructure
# lifecycle) and by each scripts/e2e/features/*.sh feature script. This file
# only defines the booted-gateway contract and assertion helpers — it never
# boots or tears down infrastructure by itself.
#
# A feature script may be run directly against an already-booted gateway
# (same contract: AUTH_DISABLED=true, MinIO on :9000, isolated keys file);
# the orchestrator boots that environment and then runs every feature.

set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ -z "${E2E_RUN_ID:-}" ]; then
    E2E_RUN_ID="${GITHUB_RUN_ID:-$$}"
    export E2E_RUN_ID
fi
export E2E_ROOT

# Booted-gateway contract (exported so feature subprocesses inherit it).
: "${MASKURA_E2E_GW_PORT:=9010}"
export MASKURA_E2E_GW_PORT
E2E_GW_URL="http://127.0.0.1:$MASKURA_E2E_GW_PORT"
E2E_BUCKET="s4-local"
E2E_GW_BIN="$E2E_ROOT/target/debug/s4-gateway"
E2E_MASKURA_BIN="$E2E_ROOT/target/debug/maskura"
E2E_COMPONENT="$E2E_ROOT/target/components/pii-default.component.wasm"
E2E_NOOP_COMPONENT="$E2E_ROOT/target/components/noop.component.wasm"
E2E_COMPOSE_PROJECT="maskura-e2e-${E2E_RUN_ID}"
E2E_COMPOSE=(docker compose --project-name "$E2E_COMPOSE_PROJECT" -f "$E2E_ROOT/local/docker-compose.yml")
E2E_MC_IMAGE="minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
E2E_MC_CONF="${E2E_COMPOSE_PROJECT}-mc"
export E2E_GW_URL E2E_BUCKET E2E_GW_BIN E2E_MASKURA_BIN E2E_COMPONENT E2E_NOOP_COMPONENT
export E2E_COMPOSE_PROJECT E2E_MC_IMAGE E2E_MC_CONF

# One scratch area shared by the orchestrator and every feature so nothing
# is left behind; the orchestrator's EXIT trap removes it.
if [ -z "${E2E_KEYS_DIR:-}" ]; then
    E2E_KEYS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/maskura-e2e-keys-${E2E_RUN_ID}.XXXXXX")"
    export E2E_KEYS_DIR
fi
E2E_KEYS_FILE="$E2E_KEYS_DIR/keys.json"
E2E_GW_LOG="$E2E_KEYS_DIR/gateway.log"
E2E_TMP="$E2E_KEYS_DIR/http"
mkdir -p "$E2E_TMP"
export E2E_KEYS_FILE E2E_GW_LOG E2E_TMP

pass() {
    printf '    PASS: %s\n' "$1"
}

fail() {
    printf '    FAIL: %s\n' "$1" >&2
    E2E_FEATURE_FAILED=1
}

begin_feature() {
    E2E_FEATURE_FAILED=0
    echo "=== $1 ==="
}

end_feature() {
    local name="$1"
    if [ "${E2E_FEATURE_FAILED:-0}" -eq 0 ]; then
        echo "--- $name: passed ---"
    else
        echo "--- $name: FAILED ---" >&2
    fi
    exit "${E2E_FEATURE_FAILED:-0}"
}

# Require an expected HTTP status; body of the response is left on stdin's file.
expect_status() { # expected_code actual_code label
    if [ "$1" = "$2" ]; then
        pass "$3 -> HTTP $2"
    else
        fail "$3 -> expected HTTP $1, got $2"
    fi
}

# assert_contains FILE NEEDLE LABEL
assert_contains() {
    if grep -qF -- "$2" "$1"; then
        pass "$3"
    else
        fail "$3 (did not find '$2' in $1)"
    fi
}

# assert_absent FILE NEEDLE LABEL
assert_absent() {
    if grep -qF -- "$2" "$1"; then
        fail "$3 (found forbidden '$2' in $1)"
    else
        pass "$3"
    fi
}

# json_field FILE <python-suffix> — print a JSON field, e.g.:
#   json_field "$f" '["key_id"]'
json_field() {
    python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    doc = json.load(fh)
print(eval("doc" + sys.argv[2]))
PY
}
