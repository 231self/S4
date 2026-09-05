#!/usr/bin/env bash
# Maskura local end-to-end suite.
#
# Boots MinIO + the gateway once, then runs every discrete feature script in
# scripts/e2e/features/ against that shared environment. Each feature is an
# independently-runnable script; `bash scripts/e2e-local.sh <name>` runs only
# the matching feature (after boot).
#
# Features covered today:
#   10-http-surface.sh        /health, dashboard HTML, /openapi.json, /docs, legacy tombstones
#   15-avro-gate.sh           Avro-content PUT rejected while MASKURA_ENABLE_AVRO is unset
#   20-redaction-roundtrip.sh PII redaction on PUT -> object read-back from MinIO
#   25-strict-auth-denial.sh  second strict gateway (no AUTH_DISABLED): unauthenticated S3/dashboard denied
#   30-keys-s3-lifecycle.sh   dashboard key CRUD + authenticated S3 PUT/HEAD/GET/LIST/DELETE
#   40-plugin-admin-http.sh   plugin import / list / enable / reorder / remove over HTTP
#
# Features that need a different gateway configuration or extra tooling are
# intentionally separate future harnesses (each keeps its own boot contract):
# the positive Avro round trip and envelope/stable field encryption need
# MASKURA_ENABLE_AVRO=true plus OCF fixtures and an Avro codec to assert on;
# managed service storage needs an S4_SERVICE_BUCKETS multi-backend boot
# without S3_ENDPOINT; staged multipart needs Postgres + a durable KEK; key
# expiry/revocation rejection on the data plane needs an auth-enabled boot
# that can create keys; presigned URL proxying needs a container-network
# harness (the host process cannot deterministically reach the local MinIO's
# loopback over IPv4 on all Docker setups and IP literals are not allowlisted);
# SDK/MCP live round trips need their runtimes.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib.sh
source "$ROOT/scripts/e2e/lib.sh"

GW_PID=""
E2E_STARTED_MINIO=0

cleanup() {
    if [ -n "$GW_PID" ]; then
        kill "$GW_PID" 2>/dev/null || true
        wait "$GW_PID" 2>/dev/null || true
    fi
    if [ "$E2E_STARTED_MINIO" -eq 1 ]; then
        "${E2E_COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    docker volume rm "$E2E_MC_CONF" >/dev/null 2>&1 || true
    rm -rf "$E2E_KEYS_DIR"
}
trap cleanup EXIT

e2e_boot() {
    echo "=== Maskura E2E: boot MinIO + gateway ==="

    # 1. MinIO on :9000: reuse a healthy instance (common when the local
    # dev/ad MinIO is already running) or start one via docker compose.
    if curl -fs http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; then
        echo "--- Reusing running MinIO on :9000 ---"
        E2E_STARTED_MINIO=0
    else
        echo "--- Starting MinIO ---"
        "${E2E_COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
        docker volume rm "$E2E_MC_CONF" >/dev/null 2>&1 || true
        "${E2E_COMPOSE[@]}" up -d --wait minio 2>&1
        E2E_STARTED_MINIO=1
    fi

    # mc config lives in a shared volume so alias set and the read-back steps
    # (separate --rm containers) see the same configuration.
    local mc_opts=(--rm -i --network host -v "$E2E_MC_CONF:/root/.mc" "$E2E_MC_IMAGE" --no-color)
    docker run "${mc_opts[@]}" alias set local http://localhost:9000 minioadmin minioadmin
    docker run "${mc_opts[@]}" mb "local/$E2E_BUCKET" --ignore-existing

    # 2. Build the filters and the debug binaries.
    echo "--- Building filters and binaries ---"
    (cd "$ROOT" && bash scripts/build-filters.sh)
    (cd "$ROOT" && cargo build --locked -p s4-gateway --bin s4-gateway)
    (cd "$ROOT" && cargo build --locked -p s4ctl --bin maskura)

    # 3. Start the gateway against MinIO (auth disabled, isolated keys file).
    echo "--- Starting Maskura Gateway on $E2E_GW_URL ---"
    S3_ENDPOINT=http://127.0.0.1:9000 \
    S3_ACCESS_KEY_ID=minioadmin \
    S3_SECRET_ACCESS_KEY=minioadmin \
    S3_REGION=us-east-1 \
    LISTEN_ADDR="127.0.0.1:$MASKURA_E2E_GW_PORT" \
    MASKURA_FILTER_COMPONENT="$E2E_COMPONENT" \
    MASKURA_STREAMING_WRITE_MODE=single \
    MASKURA_STREAMING_READ_MODE=passthrough \
    MASKURA_STREAMING_S3_PROVIDER=minio \
    MASKURA_KEYS_FILE="$E2E_KEYS_FILE" \
    AUTH_DISABLED=true \
    "$E2E_GW_BIN" > "$E2E_GW_LOG" 2>&1 &
    GW_PID=$!

    echo "--- Waiting for gateway health ---"
    local ok=0
    for _ in $(seq 1 30); do
        if curl -sf "$E2E_GW_URL/health" >/dev/null 2>&1; then
            ok=1
            break
        fi
        sleep 1
    done
    if [ "$ok" -ne 1 ]; then
        echo "FAIL: gateway did not become healthy" >&2
        tail -5 "$E2E_GW_LOG" >&2 || true
        exit 1
    fi
    echo "Gateway healthy"
}

FEATURES_DIR="$ROOT/scripts/e2e/features"
select_features() {
    if [ "$#" -eq 0 ]; then
        printf '%s\n' "$FEATURES_DIR"/*.sh | sort
    else
        for want in "$@"; do
            # Accept a bare feature number/name or a path.
            local base
            base="$(basename "$want")"
            case "$base" in
                *.sh) printf '%s\n' "$want" ;;
                *) printf '%s\n' "$FEATURES_DIR/${base}.sh" ;;
            esac
        done
    fi
}

e2e_boot
TOTAL_FAILED=0
FEATURES_LIST="$E2E_TMP/features.txt"
select_features "$@" > "$FEATURES_LIST"
while IFS= read -r feature; do
    [ -n "$feature" ] || continue
    if [ ! -f "$feature" ]; then
        echo "ERROR: feature not found: $feature" >&2
        exit 2
    fi
    echo ""
    echo "######## $(basename "$feature") ########"
    # < /dev/null keeps the child from consuming the features list via stdin
    # (docker run -i inside a feature would otherwise eat the remaining lines).
    if bash "$feature" < /dev/null; then
        echo "RESULT: $(basename "$feature") passed"
    else
        echo "RESULT: $(basename "$feature") FAILED" >&2
        TOTAL_FAILED=1
    fi
done < "$FEATURES_LIST"

echo ""
if [ "$TOTAL_FAILED" -eq 0 ]; then
    echo "=== E2E VALIDATION PASSED ==="
else
    echo "=== E2E VALIDATION FAILED ===" >&2
    exit 1
fi
