#!/usr/bin/env bash
# B2 envelope-encryption demo:
#   1. PRE-ENCRYPT  — the PII fixture as you have it
#   2. ENCRYPTED AT REST — the bytes stored in B2, fetched DIRECTLY from the
#      bucket (bypassing S4) so you can see what leaves your writer
#   3. DECRYPTED — GET through S4 + client-side decryption with the private key
#
# Credentials come from the environment (never committed):
#   B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
#   B2_REGION=us-east-005
#   B2_BUCKET=<bucket>
#   B2_ACCESS_KEY_ID=<keyId>
#   B2_SECRET_ACCESS_KEY=<applicationKey>
# The B2 application key needs readFiles/writeFiles/deleteFiles on the bucket.
#
# Requirements: docker (for the mc client), python3 + cryptography (decrypt),
# Rust toolchain + wasm-tools (first run only, to build the gateway).
#
# Usage:
#   export B2_S3_ENDPOINT=... B2_REGION=... B2_BUCKET=... \
#          B2_ACCESS_KEY_ID=... B2_SECRET_ACCESS_KEY=...
#   bash examples/b2-encrypt-demo.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${S4_TEST_PORT:-9012}"
GATEWAY_URL="http://127.0.0.1:${PORT}"
INPUT="$ROOT/tests/fixtures/pii/sample1.txt"
OBJ_KEY="demo/encrypted-sample.txt"
CERT="$ROOT/tests/fixtures/pii/crypto/cert.pem"
KEY="$ROOT/tests/fixtures/pii/crypto/key.pem"
MC_CONF="s4-mc-demo"
GW_LOG="/tmp/s4-b2-enc-demo.log"
RAW="/tmp/s4-b2-enc-raw.txt"
THROUGH="/tmp/s4-b2-enc-through.txt"
DECRYPTED="/tmp/s4-b2-decrypted.txt"

for v in B2_S3_ENDPOINT B2_REGION B2_BUCKET B2_ACCESS_KEY_ID B2_SECRET_ACCESS_KEY; do
  [ -n "${!v:-}" ] || { echo "ERROR: $v is not set (see script header)" >&2; exit 1; }
done

GW_PID=""
cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  docker volume rm "$MC_CONF" >/dev/null 2>&1 || true
  rm -f "$RAW" "$THROUGH" "$DECRYPTED"
}
trap cleanup EXIT

echo "=== B2 envelope-encryption demo ==="

echo "--- Building filters + gateway (first run only) ---"
(cd "$ROOT" && bash scripts/build-filters.sh >/dev/null 2>&1)
[ -x "$ROOT/target/debug/s4-gateway" ] || (cd "$ROOT" && cargo build -p s4-gateway)

SERVICE_BUCKETS="b2|${B2_S3_ENDPOINT}|${B2_REGION}|${B2_BUCKET}|${B2_ACCESS_KEY_ID}|${B2_SECRET_ACCESS_KEY}"

echo "--- Starting gateway on ${GATEWAY_URL} ---"
LISTEN_ADDR="127.0.0.1:${PORT}" S4_SERVICE_BUCKETS="$SERVICE_BUCKETS" \
  "$ROOT/target/debug/s4-gateway" >"$GW_LOG" 2>&1 &
GW_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "$GATEWAY_URL/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$GATEWAY_URL/health" >/dev/null 2>&1 || { echo "gateway failed:"; tail -5 "$GW_LOG"; exit 1; }

echo "--- Pipeline: pii-default OFF, envelope-encrypt ON ---"
PII_ID="$(curl -fsS "$GATEWAY_URL/dashboard/api/plugins" | python3 -c \
  "import json,sys; print([p['id'] for p in json.load(sys.stdin) if p['name']=='pii-default'][0])")"
curl -fsS -X PUT "$GATEWAY_URL/dashboard/api/plugins/$PII_ID" -H "Content-Type: application/json" -d '{"enabled":false}' -o /dev/null
curl -fsS -X POST "$GATEWAY_URL/dashboard/api/plugins" -H "x-s4-plugin-name: envelope-encrypt" \
  --data-binary "@$ROOT/target/components/envelope-encrypt.component.wasm" -o /dev/null

CERT_JSON="$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$(cat "$CERT")")"
read -r AK SK < <(curl -fsS -X POST "$GATEWAY_URL/dashboard/api/keys" -H "Content-Type: application/json" \
  -d "{\"label\":\"b2-demo\",\"public_key_pem\":$CERT_JSON}" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['key_id'], d['secret'])")

echo
echo "===== STAGE 1: PRE-ENCRYPT — the fixture as you have it ====="
cat "$INPUT"

echo
echo "===== PUT through S4 (envelope-encrypt) -> B2 ====="
curl -fsS -X PUT "$GATEWAY_URL/$OBJ_KEY" \
  -H "x-s4-access-key: $AK" -H "x-s4-secret-key: $SK" \
  -H "Content-Type: text/plain" --data-binary "@$INPUT" \
  -o /dev/null -w "PUT status: %{http_code}\n"

echo
echo "===== STAGE 2: ENCRYPTED AT REST — fetched DIRECTLY from B2 (bypassing S4) ====="
docker run --rm -v "$MC_CONF:/root/.mc" minio/mc --no-color alias set b2 "$B2_S3_ENDPOINT" "$B2_ACCESS_KEY_ID" "$B2_SECRET_ACCESS_KEY" >/dev/null
docker run --rm -v "$MC_CONF:/root/.mc" minio/mc --no-color cat "b2/$B2_BUCKET/$OBJ_KEY" | tee "$RAW"
echo "(raw object: $(wc -c < "$RAW") bytes in bucket '$B2_BUCKET', key '$OBJ_KEY')"

echo
echo "===== STAGE 3: GET through S4 ====="
curl -fsS "$GATEWAY_URL/$OBJ_KEY" -H "x-s4-access-key: $AK" -H "x-s4-secret-key: $SK" -o "$THROUGH"
echo "returned $(wc -c < "$THROUGH") bytes (envelopes pass through unchanged)"

echo
echo "===== STAGE 4: DECRYPTED — client-side with the private key ====="
python3 - "$KEY" "$THROUGH" > "$DECRYPTED" <<'EOF'
import json, re, base64, sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key_path, readback = sys.argv[1], sys.argv[2]
priv = serialization.load_pem_private_key(open(key_path, 'rb').read(), None)
s = open(readback).read()
for obj in re.findall(r'\{[^{}]*"alg"[^{}]*\}', s):
    env = json.loads(obj)
    dek = priv.decrypt(base64.b64decode(env['enc_dek']),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    pt = AESGCM(dek).decrypt(base64.b64decode(env['iv']),
        base64.b64decode(env['ct']) + base64.b64decode(env['tag']), None)
    print(pt.decode())
EOF
cat "$DECRYPTED"

echo
echo "===== VERIFY ====="
python3 - "$INPUT" "$DECRYPTED" <<'EOF'
import re, sys

def luhn(n):
    digits = [int(d) for d in str(n)]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

orig = open(sys.argv[1]).read()
dec = open(sys.argv[2]).read()
want = (set(re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', orig))
        | set(re.findall(r'\b\d{3}-\d{2}-\d{4}\b', orig))
        | {c for c in re.findall(r'\b\d{13,19}\b', orig) if luhn(c)})
got = set(dec.splitlines())
missing = want - got
if missing:
    print(f"FAIL: missing from decrypted: {missing}")
    sys.exit(1)
print(f"PASS: all {len(want)} PII values recovered by decryption")
EOF

curl -fsS -X DELETE "$GATEWAY_URL/$OBJ_KEY" -H "x-s4-access-key: $AK" -H "x-s4-secret-key: $SK" -o /dev/null 2>/dev/null || true
echo "Demo complete."
