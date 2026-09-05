#!/usr/bin/env bash
# Feature: strict auth enforcement (no demo fallback).
#
# The shared e2e gateway runs AUTH_DISABLED=true, where unauthenticated and
# unresolvable-credential requests are allowed as the demo user — so key
# expiry/revocation rejection cannot be observed there. This feature boots a
# second, isolated gateway WITHOUT AUTH_DISABLED against an empty in-memory
# keystore and proves the data plane and dashboard refuse unauthenticated
# access (HTTP 403/401) instead of silently falling back. It is still fully
# local/CI: no Supabase, no Postgres, no secrets.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "Strict auth enforcement (no demo fallback)"

if [ -z "${MASKURA_STRICT_GW_PORT:-}" ]; then
    MASKURA_STRICT_GW_PORT=9011
fi
STRICT_URL="http://127.0.0.1:$MASKURA_STRICT_GW_PORT"
STRICT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/maskura-e2e-strict-${E2E_RUN_ID}.XXXXXX")"
STRICT_LOG="$STRICT_TMP/gateway.log"
STRICT_PID=""

cleanup_strict() {
    if [ -n "$STRICT_PID" ]; then
        kill "$STRICT_PID" 2>/dev/null || true
        wait "$STRICT_PID" 2>/dev/null || true
    fi
    rm -rf "$STRICT_TMP"
}
trap cleanup_strict EXIT

echo "--- Starting strict gateway (AUTH_DISABLED unset, empty in-memory keystore) on :$MASKURA_STRICT_GW_PORT ---"
S3_ENDPOINT=http://127.0.0.1:9000 \
S3_ACCESS_KEY_ID=minioadmin \
S3_SECRET_ACCESS_KEY=minioadmin \
S3_REGION=us-east-1 \
MASKURA_SINGLE_TENANT=true \
LISTEN_ADDR="127.0.0.1:$MASKURA_STRICT_GW_PORT" \
MASKURA_FILTER_COMPONENT="$E2E_COMPONENT" \
"$E2E_GW_BIN" > "$STRICT_LOG" 2>&1 &
STRICT_PID=$!

ok=0
for _ in $(seq 1 30); do
    if curl -sf "$STRICT_URL/health" >/dev/null 2>&1; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    tail -20 "$STRICT_LOG" >&2 || true
    fail "strict gateway did not become healthy"
    end_feature "Strict auth enforcement"
fi
pass "strict gateway is healthy (booted without AUTH_DISABLED)"

# Dashboard key API requires a real user identity.
code="$(curl -sS -o "$E2E_TMP/25-keys.json" -w '%{http_code}' "$STRICT_URL/dashboard/api/keys")"
expect_status 401 "$code" "GET /dashboard/api/keys without a session"

# Data-plane S3 requests without credentials are denied, not demo-user.
code="$(curl -sS -o "$E2E_TMP/25-put.out" -w '%{http_code}' \
    -X PUT -H 'Content-Type: text/plain' \
    --data-binary 'deny me' \
    "$STRICT_URL/$E2E_BUCKET/denied.txt")"
expect_status 403 "$code" "unauthenticated S3 PUT is denied"

code="$(curl -sS -o "$E2E_TMP/25-list.out" -w '%{http_code}' "$STRICT_URL/$E2E_BUCKET")"
expect_status 403 "$code" "unauthenticated S3 bucket listing is denied"

code="$(curl -sS -o "$E2E_TMP/25-get.out" -w '%{http_code}' "$STRICT_URL/$E2E_BUCKET/denied.txt")"
expect_status 403 "$code" "unauthenticated S3 GET is denied"

end_feature "Strict auth enforcement"
