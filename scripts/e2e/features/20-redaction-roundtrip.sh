#!/usr/bin/env bash
# Feature: PII redaction round trip — upload the PII fixture through the
# gateway pipeline and verify the object stored in MinIO is redacted with no
# plaintext leakage. This is the historical core of the MinIO e2e.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "PII redaction round trip through MinIO"

# Run the CLI fixture upload (demo mode, unauthenticated local gateway).
echo "--- Running maskura test upload ---"
MASKURA_GATEWAY_URL="$E2E_GW_URL" "$E2E_MASKURA_BIN" test upload

# Read the stored object straight out of MinIO (bypassing the gateway).
echo "--- Reading stored object from MinIO ---"
docker run --rm -i --network host -v "$E2E_MC_CONF:/root/.mc" "$E2E_MC_IMAGE" --no-color \
    alias set local http://localhost:9000 minioadmin minioadmin >/dev/null
docker run --rm -i --network host -v "$E2E_MC_CONF:/root/.mc" "$E2E_MC_IMAGE" --no-color \
    cat "local/$E2E_BUCKET/test-upload.txt" > "$E2E_TMP/20-readback.txt" 2>"$E2E_TMP/20-readback.err" || {
    cat "$E2E_TMP/20-readback.err" >&2
    fail "mc cat could not read local/$E2E_BUCKET/test-upload.txt from MinIO"
}

for marker in "REDACTED_EMAIL" "REDACTED_SSN" "REDACTED_CARD"; do
    if grep -q "\[$marker\]" "$E2E_TMP/20-readback.txt"; then
        pass "[$marker] present in the stored object"
    else
        fail "[$marker] missing from the stored object"
    fi
done

assert_absent "$E2E_TMP/20-readback.txt" "jane.doe@example.com" "original email absent from the stored object"
assert_absent "$E2E_TMP/20-readback.txt" "4111111111111111" "original card absent from the stored object"

end_feature "PII redaction round trip"
