#!/usr/bin/env bash
# B2 redaction demo: PUT a PII fixture through the pii-default pipeline into a
# real B2 bucket, then fetch the object DIRECTLY from B2 (bypassing S4) and
# confirm the stored bytes contain no plaintext PII.
#
# Credentials come from the environment (never committed):
#   B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
#   B2_REGION=us-east-005
#   B2_BUCKET=<bucket>
#   B2_ACCESS_KEY_ID=<keyId>
#   B2_SECRET_ACCESS_KEY=<applicationKey>
# The B2 application key needs readFiles/writeFiles/deleteFiles on the bucket.
#
# Run:
#   export B2_* (as above)
#   bash examples/b2-redact-demo.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${S4_TEST_PORT:-9013}"
GATEWAY_URL="http://127.0.0.1:${PORT}"
INPUT="$ROOT/tests/fixtures/pii/sample1.txt"
OBJ_KEY="demo/redacted-sample.txt"
MC_CONF="s4-mc-redact-demo"
GW_LOG="/tmp/s4-b2-redact-demo.log"
RAW="/tmp/s4-b2-redact-raw.txt"

for v in B2_S3_ENDPOINT B2_REGION B2_BUCKET B2_ACCESS_KEY_ID B2_SECRET_ACCESS_KEY; do
  [ -n "${!v:-}" ] || { echo "ERROR: $v is not set (see script header)" >&2; exit 1; }
done

GW_PID=""
cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  docker volume rm "$MC_CONF" >/dev/null 2>&1 || true
  rm -f "$RAW"
}
trap cleanup EXIT

echo "=== B2 redaction demo ==="
echo "--- building filters + gateway (first run only) ---"
(cd "$ROOT" && bash scripts/build-filters.sh >/dev/null 2>&1)
[ -x "$ROOT/target/debug/s4-gateway" ] || (cd "$ROOT" && cargo build -p s4-gateway)

SERVICE_BUCKETS="b2|${B2_S3_ENDPOINT}|${B2_REGION}|${B2_BUCKET}|${B2_ACCESS_KEY_ID}|${B2_SECRET_ACCESS_KEY}"

echo "--- starting gateway on ${GATEWAY_URL} ---"
LISTEN_ADDR="127.0.0.1:${PORT}" S4_SERVICE_BUCKETS="$SERVICE_BUCKETS" \
  "$ROOT/target/debug/s4-gateway" >"$GW_LOG" 2>&1 &
GW_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "$GATEWAY_URL/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$GATEWAY_URL/health" >/dev/null 2>&1 || { echo "gateway failed:"; tail -5 "$GW_LOG"; exit 1; }

echo "--- PUT fixture through the pii-default pipeline -> B2 ---"
curl -fsS -X PUT "$GATEWAY_URL/$OBJ_KEY" \
  -H "Content-Type: text/plain" --data-binary "@$INPUT" \
  -o /dev/null -w "PUT status: %{http_code}\n"

echo "--- stored in B2 (fetched DIRECTLY, bypassing S4) ---"
docker run --rm -v "$MC_CONF:/root/.mc" minio/mc --no-color alias set b2 "$B2_S3_ENDPOINT" "$B2_ACCESS_KEY_ID" "$B2_SECRET_ACCESS_KEY" >/dev/null
docker run --rm -v "$MC_CONF:/root/.mc" minio/mc --no-color cat "b2/$B2_BUCKET/$OBJ_KEY" | tee "$RAW"

echo "--- verification ---"
FAIL=0
for marker in REDACTED_EMAIL REDACTED_SSN REDACTED_CARD; do
  if grep -q "$marker" "$RAW"; then
    echo "PASS: $marker redacted at rest"
  else
    echo "FAIL: no $marker in stored object" >&2
    FAIL=1
  fi
done
if grep -qE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+" "$RAW"; then
  echo "FAIL: raw email leaked into B2" >&2
  FAIL=1
else
  echo "PASS: no raw emails stored"
fi

curl -fsS -X DELETE "$GATEWAY_URL/$OBJ_KEY" -o /dev/null 2>/dev/null || true

[ "$FAIL" -eq 0 ] || { echo "B2 redaction demo FAILED" >&2; exit 1; }
echo "B2 redaction demo PASSED"
