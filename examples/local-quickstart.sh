#!/usr/bin/env bash
# Local quickstart as a runnable script: start the gateway from the published
# image, push a sample through the plugin pipeline, assert it was redacted,
# then stop. No cloud account, no repo clone.
#
# Requires: maskura (cargo install --git https://github.com/231self/S4 --bin maskura s4ctl),
# Docker. The gateway image is pinned to the `maskura` executable version.
#
# Run: bash examples/local-quickstart.sh

set -euo pipefail

SAMPLE="/tmp/s4-quickstart.csv"

echo "=== Maskura local quickstart ==="
maskura --version
maskura local init
maskura plugin list

echo "--- push a sample through the pipeline ---"
printf 'jane.doe@example.com 4111111111111111\n' > "$SAMPLE"
maskura put "$SAMPLE" ingest/data.csv --bucket s4-local
echo "--- read it back ---"
maskura get ingest/data.csv --bucket s4-local

echo "--- verify redaction ---"
READBACK="$(maskura get ingest/data.csv --bucket s4-local)"
case "$READBACK" in
  *REDACTED_EMAIL*REDACTED_CARD*) echo "OK: PII redacted" ;;
  *) echo "FAIL: expected [REDACTED_EMAIL] [REDACTED_CARD], got: $READBACK"; maskura local down; rm -f "$SAMPLE"; exit 1 ;;
esac

rm -f "$SAMPLE"
maskura local down
echo "Quickstart OK"
