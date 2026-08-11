#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "$0")/.."
READBACK="/tmp/s4-e2e-readback.txt"
MC_CONF="s4-mc-config"
GW_PORT="${S4_E2E_GW_PORT:-9010}"
GW_URL="http://127.0.0.1:$GW_PORT"
GW_PID=""

cleanup() {
    [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
    rm -f "$READBACK"
    docker volume rm "$MC_CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== S4 E2E: MinIO read/write validation ==="

# 1. Start MinIO
echo "--- Starting MinIO ---"
docker compose -f "$ROOT/local/docker-compose.yml" up -d --wait minio 2>&1

# mc config lives in a shared volume so alias set and subsequent ops
# (run as separate --rm containers) see the same configuration.
MC_OPTS=(--rm -i --network host -v "$MC_CONF:/root/.mc" minio/mc --no-color)

# 2. Configure MinIO client alias + create the bucket the gateway will use
echo "--- Configuring MinIO alias ---"
docker run "${MC_OPTS[@]}" alias set local http://localhost:9000 minioadmin minioadmin

echo "--- Creating s4-local bucket ---"
docker run "${MC_OPTS[@]}" mb local/s4-local --ignore-existing

# 3. Build filters and binaries
echo "--- Building filters and binaries ---"
(cd "$ROOT" && bash scripts/build-filters.sh)
(cd "$ROOT" && cargo build -p s4-gateway -p s4ctl)

# 4. Start the gateway against MinIO (auth disabled)
echo "--- Starting S4 gateway on $GW_URL ---"
S3_ENDPOINT=http://127.0.0.1:9000 \
LISTEN_ADDR="127.0.0.1:$GW_PORT" \
S4_FILTER_COMPONENT="$ROOT/target/components/pii-default.component.wasm" \
AUTH_DISABLED=true \
"$ROOT/target/debug/s4-gateway" > /tmp/s4-e2e-gateway.log 2>&1 &
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
    tail -5 /tmp/s4-e2e-gateway.log
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
