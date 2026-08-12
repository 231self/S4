#!/usr/bin/env bash
# Local quickstart as a runnable script: start the gateway from the published
# image, push a sample through the plugin pipeline, assert it was redacted,
# then stop. No cloud account, no repo clone.
#
# Requires: s4ctl (cargo install s4ctl --git https://github.com/231self/S4),
# docker. The gateway image is pinned to the s4ctl version.
#
# Run: bash examples/local-quickstart.sh

set -euo pipefail

SAMPLE="/tmp/s4-quickstart.csv"

echo "=== S4 local quickstart ==="
s4ctl --version
s4ctl local init
s4ctl plugin list

echo "--- push a sample through the pipeline ---"
printf 'jane.doe@example.com 4111111111111111\n' > "$SAMPLE"
s4ctl put "$SAMPLE" ingest/data.csv --bucket s4-local
echo "--- read it back ---"
s4ctl get ingest/data.csv --bucket s4-local

echo "--- verify redaction ---"
READBACK="$(s4ctl get ingest/data.csv --bucket s4-local)"
case "$READBACK" in
  *REDACTED_EMAIL*REDACTED_CARD*) echo "OK: PII redacted" ;;
  *) echo "FAIL: expected [REDACTED_EMAIL] [REDACTED_CARD], got: $READBACK"; s4ctl local down; rm -f "$SAMPLE"; exit 1 ;;
esac

rm -f "$SAMPLE"
s4ctl local down
echo "Quickstart OK"
