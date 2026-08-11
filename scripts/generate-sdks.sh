#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_DIR="$PROJECT_DIR/sdks"
GATEWAY_PORT=19001
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"

cleanup() {
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
}
trap cleanup EXIT

# The gateway needs a filter component to start; ensure it exists.
if [ ! -f "$PROJECT_DIR/target/components/pii-default.component.wasm" ]; then
    echo "→ Building filter components..."
    (cd "$PROJECT_DIR" && bash scripts/build-filters.sh)
fi

echo "→ Building gateway..."
(cd "$PROJECT_DIR" && cargo build -p s4-gateway)

echo "→ Starting gateway on port $GATEWAY_PORT..."
(cd "$PROJECT_DIR" && LISTEN_ADDR="127.0.0.1:$GATEWAY_PORT" cargo run -p s4-gateway) &
GATEWAY_PID=$!

# Wait for gateway to be ready
for i in $(seq 1 30); do
    if curl -s "$GATEWAY_URL/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

echo "→ Extracting OpenAPI spec..."
curl -s "$GATEWAY_URL/openapi.json" > "$SDK_DIR/openapi.json"
echo "   Saved to $SDK_DIR/openapi.json"

GENERATOR_IMAGE="openapitools/openapi-generator-cli:v7.14.0"

generate() {
    local lang=$1
    local dir="$SDK_DIR/$lang"
    echo "→ Generating $lang SDK..."
    rm -rf "$dir"
    docker run --rm \
        -v "$SDK_DIR:/local" \
        "$GENERATOR_IMAGE" generate \
        -i /local/openapi.json \
        -g "$lang" \
        -o "/local/$lang" \
        --additional-properties=packageName=s4_client,projectName=s4-client \
        --skip-validate-spec
    echo "   SDK generated at $dir"
}

apply_overlay() {
    local lang=$1
    local overlay="$SDK_DIR/overlay/$lang"
    local dir="$SDK_DIR/$lang"
    if [ -d "$overlay" ]; then
        echo "→ Applying $lang overlay (high-level client)..."
        cp -R "$overlay/." "$dir/"
    fi
}

generate python
apply_overlay python
generate typescript
apply_overlay typescript

echo "→ Generated SDKs:"
ls -la "$SDK_DIR/python/" "$SDK_DIR/typescript/" | head -5

cleanup
echo "Done. SDKs in $SDK_DIR/"
