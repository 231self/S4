#!/usr/bin/env bash
# Feature: plugin-management HTTP surface (local admin mode, AUTH_DISABLED).
#
# Previously only mounted-without-assertion: imports a real .wasm component,
# lists it, enables it, reorders the catalog, and removes it. Runs last in the
# suite because enabling an imported component can change the write pipeline
# for subsequent features.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "Plugin import / list / enable / reorder / remove over HTTP"

if [ ! -f "$E2E_NOOP_COMPONENT" ]; then
    fail "noop component missing at $E2E_NOOP_COMPONENT (run scripts/build-filters.sh first)"
    end_feature "Plugin management over HTTP"
fi

PLUGIN_NAME="e2e-noop-http"

# 1. Import a real component (noop) under a plugin name.
code="$(curl -sS -o "$E2E_TMP/40-import.json" -w '%{http_code}' \
    -X POST \
    -H "x-maskura-plugin-name: $PLUGIN_NAME" \
    --data-binary "@$E2E_NOOP_COMPONENT" \
    "$E2E_GW_URL/dashboard/api/plugins")"
expect_status 201 "$code" "POST /dashboard/api/plugins (import $PLUGIN_NAME)"
PLUGIN_ID="$(json_field "$E2E_TMP/40-import.json" '["id"]')"
assert_contains "$E2E_TMP/40-import.json" "$PLUGIN_NAME" "import response reports the plugin name"

# 2. The catalog lists the imported plugin.
code="$(curl -sS -o "$E2E_TMP/40-plugins.json" -w '%{http_code}' "$E2E_GW_URL/dashboard/api/plugins")"
expect_status 200 "$code" "GET /dashboard/api/plugins"
assert_contains "$E2E_TMP/40-plugins.json" "$PLUGIN_ID" "imported plugin appears in the catalog"

# 3. Enable it.
code="$(curl -sS -o "$E2E_TMP/40-enabled.json" -w '%{http_code}' \
    -X PUT -H 'Content-Type: application/json' \
    -d '{"enabled":true}' \
    "$E2E_GW_URL/dashboard/api/plugins/$PLUGIN_ID")"
expect_status 200 "$code" "PUT /dashboard/api/plugins/$PLUGIN_ID (enable)"
code="$(curl -sS -o "$E2E_TMP/40-plugins-after-enable.json" -w '%{http_code}' "$E2E_GW_URL/dashboard/api/plugins")"
expect_status 200 "$code" "GET /dashboard/api/plugins after enable"
if [ "$(python3 - "$E2E_TMP/40-plugins-after-enable.json" "$PLUGIN_ID" <<'PY'
import json, sys
plugins = json.load(open(sys.argv[1]))
print("True" if any(p.get("id") == sys.argv[2] and p.get("enabled") for p in plugins) else "False")
PY
)" = "True" ]
then
    pass "imported plugin is enabled"
else
    fail "imported plugin is not enabled after PUT"
fi

# 4. Reorder the catalog to the current id order (no semantic change).
python3 - "$E2E_TMP/40-plugins-after-enable.json" > "$E2E_TMP/40-order.json" <<'PY'
import json, sys
plugins = json.load(open(sys.argv[1]))
print(json.dumps({"order": [p["id"] for p in plugins]}))
PY
code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT -H 'Content-Type: application/json' \
    --data-binary "@$E2E_TMP/40-order.json" \
    "$E2E_GW_URL/dashboard/api/plugins/reorder")"
expect_status 200 "$code" "PUT /dashboard/api/plugins/reorder"

# 5. Remove the imported plugin.
code="$(curl -sS -o /dev/null -X DELETE -w '%{http_code}' \
    "$E2E_GW_URL/dashboard/api/plugins/$PLUGIN_ID")"
expect_status 204 "$code" "DELETE /dashboard/api/plugins/$PLUGIN_ID"
code="$(curl -sS -o "$E2E_TMP/40-plugins-after-delete.json" -w '%{http_code}' "$E2E_GW_URL/dashboard/api/plugins")"
expect_status 200 "$code" "GET /dashboard/api/plugins after delete"
assert_absent "$E2E_TMP/40-plugins-after-delete.json" "$PLUGIN_ID" "removed plugin is absent from the catalog"

end_feature "Plugin management over HTTP"
