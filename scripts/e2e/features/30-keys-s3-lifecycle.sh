#!/usr/bin/env bash
# Feature: API-key lifecycle + authenticated S3 data plane.
#
# Exercises previously untested public paths: GET/DELETE /dashboard/api/keys
# happy paths, header-authenticated PUT/HEAD/GET/DELETE on the S3 data plane,
# and ListObjects v1 + v2 forwarded to a real S3 backend (MinIO).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "API-key CRUD + authenticated S3 object lifecycle against MinIO"

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to parse dashboard API responses"
    end_feature "API-key CRUD + S3 lifecycle"
fi

OBJECT_KEY="e2e-lifecycle/object.txt"
PAYLOAD="hello from the maskura e2e lifecycle
"
printf '%s' "$PAYLOAD" > "$E2E_TMP/30-payload.txt"

# 1. Create an API key through the dashboard API (demo user in local mode).
code="$(curl -sS -o "$E2E_TMP/30-key.json" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d '{"label":"e2e-lifecycle"}' \
    "$E2E_GW_URL/dashboard/api/keys")"
expect_status 200 "$code" "POST /dashboard/api/keys"
KEY_ID="$(json_field "$E2E_TMP/30-key.json" '["key_id"]')"
SECRET="$(json_field "$E2E_TMP/30-key.json" '["secret"]')"
case "$KEY_ID" in
    s4_*) pass "created key id uses the s4_ prefix ($KEY_ID)" ;;
    *) fail "created key id '$KEY_ID' does not start with s4_" ;;
esac
case "$SECRET" in
    s4s_*) pass "created key secret uses the s4s_ prefix" ;;
    *) fail "created key secret does not start with s4s_" ;;
esac

# 2. GET /dashboard/api/keys lists the new key (without the secret).
code="$(curl -sS -o "$E2E_TMP/30-keys.json" -w '%{http_code}' "$E2E_GW_URL/dashboard/api/keys")"
expect_status 200 "$code" "GET /dashboard/api/keys"
assert_contains "$E2E_TMP/30-keys.json" "$KEY_ID" "created key appears in the key list"

# 3. Authenticated PUT through the S3 data plane.
code="$(curl -sS -o "$E2E_TMP/30-put.out" -w '%{http_code}' \
    -X PUT \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    -H 'Content-Type: text/plain' \
    --data-binary "@$E2E_TMP/30-payload.txt" \
    "$E2E_GW_URL/$E2E_BUCKET/$OBJECT_KEY")"
expect_status 200 "$code" "authenticated PUT /$E2E_BUCKET/$OBJECT_KEY"

# 4. HEAD returns the object metadata.
code="$(curl -sS -o /dev/null -I -w '%{http_code}' \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    "$E2E_GW_URL/$E2E_BUCKET/$OBJECT_KEY")"
expect_status 200 "$code" "HEAD /$E2E_BUCKET/$OBJECT_KEY"

# 5. GET returns the exact stored bytes.
code="$(curl -sS -o "$E2E_TMP/30-get.out" -w '%{http_code}' \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    "$E2E_GW_URL/$E2E_BUCKET/$OBJECT_KEY")"
expect_status 200 "$code" "GET /$E2E_BUCKET/$OBJECT_KEY"
if cmp -s "$E2E_TMP/30-payload.txt" "$E2E_TMP/30-get.out"; then
    pass "GET body is byte-identical to the uploaded payload"
else
    fail "GET body differs from the uploaded payload"
fi

# 6. ListObjects v2 + v1 forwarded to the MinIO backend exposes the object.
code="$(curl -sS -o "$E2E_TMP/30-list-v2.xml" -w '%{http_code}' \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    "$E2E_GW_URL/$E2E_BUCKET?list-type=2")"
expect_status 200 "$code" "ListObjectsV2 via the S3 backend"
assert_contains "$E2E_TMP/30-list-v2.xml" "<Key>$OBJECT_KEY</Key>" "ListObjectsV2 lists the uploaded object"

code="$(curl -sS -o "$E2E_TMP/30-list-v1.xml" -w '%{http_code}' \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    "$E2E_GW_URL/$E2E_BUCKET")"
expect_status 200 "$code" "ListObjectsV1 via the S3 backend"
assert_contains "$E2E_TMP/30-list-v1.xml" "<Key>$OBJECT_KEY</Key>" "ListObjectsV1 lists the uploaded object"

# 7. DELETE the object, then confirm it is gone.
code="$(curl -sS -o /dev/null -X DELETE -w '%{http_code}' \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    "$E2E_GW_URL/$E2E_BUCKET/$OBJECT_KEY")"
expect_status 204 "$code" "DELETE /$E2E_BUCKET/$OBJECT_KEY"

code="$(curl -sS -o "$E2E_TMP/30-gone.out" -w '%{http_code}' \
    -H "x-maskura-access-key: $KEY_ID" \
    -H "x-maskura-secret-key: $SECRET" \
    "$E2E_GW_URL/$E2E_BUCKET/$OBJECT_KEY")"
expect_status 404 "$code" "GET of deleted object returns 404"

# 8. Revoke the key (204), then confirm it no longer appears in the list.
code="$(curl -sS -o /dev/null -X DELETE -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"key_id\":\"$KEY_ID\"}" \
    "$E2E_GW_URL/dashboard/api/keys")"
expect_status 204 "$code" "DELETE /dashboard/api/keys (revoke)"

code="$(curl -sS -o "$E2E_TMP/30-keys-after.json" -w '%{http_code}' "$E2E_GW_URL/dashboard/api/keys")"
expect_status 200 "$code" "GET /dashboard/api/keys after revoke"
assert_absent "$E2E_TMP/30-keys-after.json" "$KEY_ID" "revoked key is absent from the key list"

end_feature "API-key CRUD + S3 lifecycle"
