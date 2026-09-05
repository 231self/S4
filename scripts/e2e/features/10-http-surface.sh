#!/usr/bin/env bash
# Feature: HTTP surface — liveness, dashboard HTML, OpenAPI spec, Swagger UI,
# and the retired demo tombstones. No S3 credentials involved.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "HTTP surface: health / dashboard HTML / OpenAPI / Swagger UI / tombstones"

# GET /health -> 200 liveness
curl -sS -o "$E2E_TMP/10-health.txt" -w '%{http_code}' "$E2E_GW_URL/health" > "$E2E_TMP/10-health.code"
expect_status 200 "$(cat "$E2E_TMP/10-health.code")" "GET /health"

# GET / (no S3 auth headers) -> dashboard HTML, not ListBuckets XML
curl -sS -o "$E2E_TMP/10-root.html" -w '%{http_code}' "$E2E_GW_URL/" > "$E2E_TMP/10-root.code"
expect_status 200 "$(cat "$E2E_TMP/10-root.code")" "GET /"
assert_contains "$E2E_TMP/10-root.html" "Maskura" "root serves the Maskura dashboard HTML"
assert_absent "$E2E_TMP/10-root.html" "<ListBucketResult" "dashboard root is not an S3 ListBuckets response"

# GET /openapi.json -> OpenAPI 3.1 with the dashboard API schemas
curl -sS -o "$E2E_TMP/10-openapi.json" -w '%{http_code}' "$E2E_GW_URL/openapi.json" > "$E2E_TMP/10-openapi.code"
expect_status 200 "$(cat "$E2E_TMP/10-openapi.code")" "GET /openapi.json"
if python3 - "$E2E_TMP/10-openapi.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc.get("openapi", "").startswith("3.1"), doc.get("openapi")
paths = doc.get("paths", {})
assert "/dashboard/api/keys" in paths, sorted(paths)
assert "/dashboard/api/backend" in paths, sorted(paths)
print("ok")
PY
then
    pass "OpenAPI spec is 3.1 and documents the dashboard key + backend APIs"
else
    fail "openapi.json is not a 3.1 spec exposing /dashboard/api/keys and /dashboard/api/backend"
fi

# GET /docs -> Swagger UI (utoipa redirects /docs to /docs/)
curl -sSL -o "$E2E_TMP/10-docs.html" -w '%{http_code}' "$E2E_GW_URL/docs" > "$E2E_TMP/10-docs.code"
expect_status 200 "$(cat "$E2E_TMP/10-docs.code")" "GET /docs (followed redirect)"
assert_contains "$E2E_TMP/10-docs.html" "Swagger" "GET /docs serves the Swagger UI"

# Legacy demo endpoints must answer 410 for every method.
for method in GET POST PUT DELETE; do
    code="$(curl -sS -o /dev/null -X "$method" -w '%{http_code}' "$E2E_GW_URL/dashboard/api/demo/store")"
    expect_status 410 "$code" "legacy $method /dashboard/api/demo/store tombstone"
done

end_feature "HTTP surface"
