#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_DIR="$PROJECT_DIR/sdks"
GATEWAY_PORT=19001
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
GATEWAY_PID=""
# Isolate the local-mode key store from the user's real config directory so a
# stale `~/Library/Application Support/s4/keys.json` (DEK wrapped by an earlier
# ephemeral/secret key) can never abort gateway startup.
KEYS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/s4-sdkgen-keys.XXXXXX")"
KEYS_FILE="$KEYS_DIR/keys.json"

cleanup() {
    if [ -n "$GATEWAY_PID" ]; then
        kill "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi
    rm -rf "$KEYS_DIR"
}
trap cleanup EXIT

# The gateway needs a filter component to start; ensure it exists.
if [ ! -f "$PROJECT_DIR/target/components/pii-default.component.wasm" ]; then
    echo "→ Building filter components..."
    (cd "$PROJECT_DIR" && bash scripts/build-filters.sh)
fi

echo "→ Building gateway..."
(cd "$PROJECT_DIR" && cargo build --locked -p s4-gateway)

echo "→ Starting gateway on port $GATEWAY_PORT..."
(cd "$PROJECT_DIR" && AUTH_DISABLED=true S4_KEYS_FILE="$KEYS_FILE" LISTEN_ADDR="127.0.0.1:$GATEWAY_PORT" cargo run --locked -p s4-gateway) &
GATEWAY_PID=$!

# Wait for gateway to be ready
GATEWAY_READY=false
for i in $(seq 1 30); do
    if curl --fail --silent "$GATEWAY_URL/health" >/dev/null 2>&1; then
        GATEWAY_READY=true
        break
    fi
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
        EXITED_GATEWAY_PID="$GATEWAY_PID"
        GATEWAY_PID=""
        GATEWAY_STATUS=0
        wait "$EXITED_GATEWAY_PID" || GATEWAY_STATUS=$?
        echo "ERROR: gateway exited before becoming ready (status $GATEWAY_STATUS)" >&2
        exit 1
    fi
    sleep 0.5
done
if [ "$GATEWAY_READY" != true ]; then
    echo "ERROR: gateway did not become ready at $GATEWAY_URL within 15 seconds" >&2
    exit 1
fi

echo "→ Extracting OpenAPI spec..."
curl --fail --silent --show-error "$GATEWAY_URL/openapi.json" > "$SDK_DIR/openapi.json"
echo "   Saved to $SDK_DIR/openapi.json"

GENERATOR_IMAGE="openapitools/openapi-generator-cli:v7.14.0@sha256:a620610d9fabf7ce05310c648417ba168125aac2f4517580030e115921ac1a52"

generate() {
    local lang=$1
    local dir="$SDK_DIR/$lang"
    echo "→ Generating $lang SDK..."
    rm -rf "$dir"
    docker run --rm \
        -u "$(id -u):$(id -g)" \
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

echo "Done. SDKs in $SDK_DIR/"
