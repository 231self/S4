#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "$0")/.."
FILTERED="/tmp/s4-e2e-filtered.txt"
READBACK="/tmp/s4-e2e-readback.txt"
INPUT="$ROOT/tests/fixtures/pii/sample1.txt"

cleanup() {
    rm -f "$FILTERED" "$READBACK"
}
trap cleanup EXIT

echo "=== S4 E2E: MinIO read/write validation ==="

# 1. Start MinIO
echo "--- Starting MinIO ---"
docker compose -f "$ROOT/local/docker-compose.yml" up -d --wait minio 2>&1

MC_OPTS=(--rm --network host minio/mc --no-color)

# 2. Configure MinIO client alias
echo "--- Configuring MinIO alias ---"
docker run "${MC_OPTS[@]}" alias set local http://localhost:9000 minioadmin minioadmin

# 3. Create test bucket
echo "--- Creating test bucket ---"
docker run "${MC_OPTS[@]}" mb local/test-bucket --ignore-existing

# 4. Build filter component
echo "--- Building filter component ---"
(cd "$ROOT" && bash scripts/build-filters.sh 2>&1)

# 5. Run gateway binary on fixture input
echo "--- Filtering fixture input ---"
echo "Input preview:"
head -3 "$INPUT"
echo "..."

(cd "$ROOT" && cargo run -p s4-gateway -- text text/plain "$INPUT") > "$FILTERED" 2>/tmp/s4-e2e-stderr.log

echo "--- Filtered output ---"
cat "$FILTERED"

# 6. Upload filtered output to MinIO
echo "--- Uploading filtered output to MinIO ---"
docker run "${MC_OPTS[@]}" cp /dev/stdin local/test-bucket/filtered-sample.txt < "$FILTERED"

# 7. Download back from MinIO
echo "--- Downloading from MinIO ---"
docker run "${MC_OPTS[@]}" cp local/test-bucket/filtered-sample.txt /dev/stdout > "$READBACK"

echo "--- Read-back content ---"
cat "$READBACK"

# 8. Verify PII is redacted
echo ""
echo "=== Verification ==="
FAIL=0

if grep -q "REDACTED_EMAIL" "$READBACK"; then
    echo "PASS: emails redacted"
else
    echo "FAIL: no email redaction found"
    FAIL=1
fi

if grep -q "REDACTED_SSN" "$READBACK"; then
    echo "PASS: SSNs redacted"
else
    echo "FAIL: no SSN redaction found"
    FAIL=1
fi

if grep -q "REDACTED_CARD" "$READBACK"; then
    echo "PASS: cards redacted"
else
    echo "FAIL: no card redaction found"
    FAIL=1
fi

if ! grep -q "jane.doe@example.com" "$READBACK"; then
    echo "PASS: original email absent from stored object"
else
    echo "FAIL: original email found in stored object"
    FAIL=1
fi

if ! grep -q "4111111111111111" "$READBACK"; then
    echo "PASS: original card absent from stored object"
else
    echo "FAIL: original card found in stored object"
    FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "=== E2E VALIDATION PASSED ==="
    echo "Filtered data is written to MinIO and read back with PII removed."
else
    echo ""
    echo "=== E2E VALIDATION FAILED ==="
    exit 1
fi
