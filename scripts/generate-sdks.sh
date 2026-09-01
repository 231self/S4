#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_DIR="$PROJECT_DIR/sdks"
GATEWAY_PORT=19001
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
GATEWAY_KEYS_FILE="$SDK_DIR/.generator-keys-$GATEWAY_PORT.json"
GATEWAY_LOG="$SDK_DIR/.generator-gateway-$GATEWAY_PORT.log"
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
    rm -f "$GATEWAY_KEYS_FILE" "$GATEWAY_LOG"
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
(cd "$PROJECT_DIR" && AUTH_DISABLED=true MASKURA_KEYS_FILE="$KEYS_FILE" LISTEN_ADDR="127.0.0.1:$GATEWAY_PORT" cargo run --locked -p s4-gateway) >"$GATEWAY_LOG" 2>&1 &
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
    local properties
    case "$lang" in
        python)
            # Keep the shipped s4_client module as a permanent facade target;
            # the overlay adds the canonical maskura_client namespace.
            properties="packageName=s4_client,projectName=maskura-client,gitUserId=231self,gitRepoId=S4"
            ;;
        typescript)
            properties="npmName=maskura-client,npmVersion=1.0.0,gitUserId=231self,gitRepoId=S4"
            ;;
        *)
            echo "ERROR: unsupported SDK language: $lang" >&2
            exit 1
            ;;
    esac
    echo "→ Generating $lang SDK..."
    rm -rf "$dir"
    docker run --rm \
        -u "$(id -u):$(id -g)" \
        -v "$SDK_DIR:/local" \
        "$GENERATOR_IMAGE" generate \
        -i /local/openapi.json \
        -g "$lang" \
        -o "/local/$lang" \
        --additional-properties="$properties" \
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
cat >> "$SDK_DIR/python/s4_client/__init__.py" <<'PYTHON_EXPORTS'

# High-level canonical and compatibility exports maintained by the Maskura overlay.
from s4_client.highlevel import MaskuraClient as MaskuraClient
from s4_client.highlevel import S4Client as S4Client
__all__.extend(["MaskuraClient", "S4Client"])
PYTHON_EXPORTS
python3 - "$SDK_DIR/python" <<'PYTHON_PACKAGE'
from pathlib import Path
import sys

root = Path(sys.argv[1])
pyproject = root.joinpath("pyproject.toml").read_text()
pyproject = pyproject.replace('name = "s4_client"', 'name = "maskura_client"', 1)
pyproject = pyproject.replace(
    'Repository = "https://github.com/GIT_USER_ID/GIT_REPO_ID"',
    'Repository = "https://github.com/231self/S4"',
)
pyproject = pyproject.replace(
    '  "typing-extensions (>=4.7.1)"',
    '  "typing-extensions (>=4.7.1)",\n  "requests (>=2.31)",\n  "cryptography (>=42)"',
)
root.joinpath("pyproject.toml").write_text(pyproject)

readme = root.joinpath("README.md").read_text().replace("s4_client", "maskura_client")
readme = readme.replace(
    "https://github.com/GIT_USER_ID/GIT_REPO_ID.git",
    "https://github.com/231self/S4.git",
)
root.joinpath("README.md").write_text(readme)
for doc in root.joinpath("docs").glob("*.md"):
    doc.write_text(doc.read_text().replace("s4_client", "maskura_client"))

setup = root.joinpath("setup.py").read_text()
setup = setup.replace('NAME = "maskura-client"', 'NAME = "maskura_client"', 1)
setup = setup.replace('    url="",', '    url="https://github.com/231self/S4",')
setup = setup.replace(
    '    "typing-extensions >= 4.7.1",',
    '    "typing-extensions >= 4.7.1",\n    "requests >= 2.31",\n    "cryptography >= 42",',
)
setup = setup.replace(
    'package_data={"s4_client": ["py.typed"]}',
    'package_data={"s4_client": ["py.typed"], "maskura_client": ["py.typed"]}',
)
root.joinpath("setup.py").write_text(setup)

requirements = root.joinpath("requirements.txt")
requirements.write_text(requirements.read_text() + "requests >= 2.31\ncryptography >= 42\n")

git_push = root.joinpath("git_push.sh").read_text()
git_push = git_push.replace('git_user_id="GIT_USER_ID"', 'git_user_id="231self"')
git_push = git_push.replace('git_repo_id="GIT_REPO_ID"', 'git_repo_id="S4"')
root.joinpath("git_push.sh").write_text(git_push)
PYTHON_PACKAGE
generate typescript
apply_overlay typescript
printf '\nexport * from "./highlevel";\n' >> "$SDK_DIR/typescript/index.ts"
python3 - "$SDK_DIR/typescript/package.json" <<'TYPESCRIPT_PACKAGE'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
package = json.loads(path.read_text())
package["description"] = "OpenAPI client for the Maskura Gateway"
package["repository"] = {
    "type": "git",
    "url": "https://github.com/231self/S4.git",
}
package["license"] = "Apache-2.0"
path.write_text(json.dumps(package, indent=2) + "\n")

git_push = path.with_name("git_push.sh")
script = git_push.read_text()
script = script.replace('git_user_id="GIT_USER_ID"', 'git_user_id="231self"')
script = script.replace('git_repo_id="GIT_REPO_ID"', 'git_repo_id="S4"')
git_push.write_text(script)
TYPESCRIPT_PACKAGE

test -f "$SDK_DIR/python/maskura_client/__init__.py"
grep -q 'name = "maskura_client"' "$SDK_DIR/python/pyproject.toml"
grep -q 'class MaskuraClient' "$SDK_DIR/python/s4_client/highlevel.py"
grep -q '"name": "maskura-client"' "$SDK_DIR/typescript/package.json"
grep -q 'export class MaskuraClient' "$SDK_DIR/typescript/highlevel.ts"

echo "→ Generated SDKs:"
ls -la "$SDK_DIR/python/" "$SDK_DIR/typescript/" | head -5

echo "Done. SDKs in $SDK_DIR/"
