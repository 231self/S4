#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "$0")/.."
RUN_ID="${GITHUB_RUN_ID:-$$}"
COMPOSE_PROJECT="s4-e2e-${RUN_ID}"
COMPOSE=(docker compose --project-name "$COMPOSE_PROJECT" -f "$ROOT/local/docker-compose.yml")
READBACK="/tmp/s4-e2e-readback-${RUN_ID}.txt"
GW_LOG="/tmp/s4-e2e-gateway-${RUN_ID}.log"
# Isolate the local-mode key store from the user's real config directory so a
# stale `~/Library/Application Support/s4/keys.json` (DEK wrapped by an earlier
# ephemeral/secret key) can never abort gateway startup.
KEYS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/s4-e2e-keys-${RUN_ID}.XXXXXX")"
KEYS_FILE="$KEYS_DIR/keys.json"
MC_CONF="${COMPOSE_PROJECT}-mc"
MC_IMAGE="minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
GW_PORT="${S4_E2E_GW_PORT:-9010}"
GW_URL="http://127.0.0.1:$GW_PORT"
GW_PID=""

cleanup() {
    [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
    [ -n "$GW_PID" ] && wait "$GW_PID" 2>/dev/null || true
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -f "$READBACK" "$GW_LOG"
    rm -rf "$KEYS_DIR"
    docker volume rm "$MC_CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== S4 E2E: MinIO read/write validation ==="

# 1. Start MinIO
echo "--- Starting MinIO ---"
"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker volume rm "$MC_CONF" >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --wait minio 2>&1

# mc config lives in a shared volume so alias set and subsequent ops
# (run as separate --rm containers) see the same configuration.
MC_OPTS=(--rm -i --network host -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color)

# 2. Configure MinIO client alias + create the bucket the gateway will use
echo "--- Configuring MinIO alias ---"
docker run "${MC_OPTS[@]}" alias set local http://localhost:9000 minioadmin minioadmin

echo "--- Creating s4-local bucket ---"
docker run "${MC_OPTS[@]}" mb local/s4-local --ignore-existing

# 3. Build filters and binaries
echo "--- Building filters and binaries ---"
(cd "$ROOT" && bash scripts/build-filters.sh)
(cd "$ROOT" && cargo build --locked -p s4-gateway -p s4ctl)

# 4. Start the gateway against MinIO (auth disabled)
echo "--- Starting S4 gateway on $GW_URL ---"
S3_ENDPOINT=http://127.0.0.1:9000 \
S3_ACCESS_KEY_ID=minioadmin \
S3_SECRET_ACCESS_KEY=minioadmin \
S3_REGION=us-east-1 \
LISTEN_ADDR="127.0.0.1:$GW_PORT" \
S4_KEYS_FILE="$KEYS_FILE" \
S4_FILTER_COMPONENT="$ROOT/target/components/pii-default.component.wasm" \
S4_STREAMING_WRITE_MODE=single \
S4_STREAMING_READ_MODE=passthrough \
S4_STREAMING_S3_PROVIDER=minio \
AUTH_DISABLED=true \
"$ROOT/target/debug/s4-gateway" > "$GW_LOG" 2>&1 &
GW_PID=$!

echo "--- Waiting for gateway health ---"
for _ in $(seq 1 30); do
    if curl -sf "$GW_URL/health" >/dev/null 2>&1; then
        echo "Gateway healthy"
        break
    fi
    sleep 1
done
curl -sf "$GW_URL/health" >/dev/null 2>&1 || {
    echo "FAIL: gateway did not become healthy"
    tail -5 "$GW_LOG"
    exit 1
}

# 5. Upload PII fixture through the gateway, read it back (verifies redaction)
echo "--- Running s4ctl test upload through the gateway ---"
S4_GATEWAY_URL="$GW_URL" "$ROOT/target/debug/s4ctl" test upload

# 6. Verify the stored object in MinIO is redacted
echo "--- Verifying object in MinIO ---"
docker run "${MC_OPTS[@]}" cat local/s4-local/test-upload.txt > "$READBACK"

echo "--- Read-back content ---"
cat "$READBACK"

echo ""
echo "=== Verification ==="
FAIL=0

for pat in "REDACTED_EMAIL" "REDACTED_SSN" "REDACTED_CARD"; do
    if grep -q "\[$pat\]" "$READBACK"; then
        echo "PASS: $pat present in stored object"
    else
        echo "FAIL: $pat missing from stored object"
        FAIL=1
    fi
done

if ! grep -q "jane.doe@example.com" "$READBACK"; then
    echo "PASS: original email absent from stored object"
else
    echo "FAIL: original email found in stored object"
    FAIL=1
fi

if ! grep -q "4111111111111111" "$READBACK"; then
    echo "PASS: original card absent from stored object"
else
    echo "FAIL: original card found in stored object"
    FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "=== E2E VALIDATION PASSED ==="
    echo "Filtered data is written to MinIO and read back with PII removed."
else
    echo ""
    echo "=== E2E VALIDATION FAILED ==="
    exit 1
fi
