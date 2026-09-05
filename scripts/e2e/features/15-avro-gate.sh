#!/usr/bin/env bash
# Feature: Avro processing gate — with MASKURA_ENABLE_AVRO unset (the shared
# e2e boot), an Avro-content PUT must be rejected before the body is polled.
# The positive Avro round trip needs MASKURA_ENABLE_AVRO=true plus OCF
# fixtures + an Avro codec to assert on, so it stays a separate future harness.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
begin_feature "Avro processing gate (disabled by default)"

printf 'this body never needs to be a valid Avro OCF\n' > "$E2E_TMP/15-avro-input.bin"
code="$(curl -sS -o "$E2E_TMP/15-avro.out" -w '%{http_code}' \
    -X PUT \
    -H 'Content-Type: application/avro' \
    --data-binary "@$E2E_TMP/15-avro-input.bin" \
    "$E2E_GW_URL/$E2E_BUCKET/e2e-avro-gate.avro")"
expect_status 501 "$code" "Avro PUT is rejected while MASKURA_ENABLE_AVRO is unset"

# The gate rejects before polling the body; a GET of the key must 404.
code="$(curl -sS -o /dev/null -w '%{http_code}' "$E2E_GW_URL/$E2E_BUCKET/e2e-avro-gate.avro")"
expect_status 404 "$code" "rejected Avro object was not stored"

end_feature "Avro processing gate"
