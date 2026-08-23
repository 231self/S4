#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <gateway-image-ref>" >&2
  exit 2
fi

IMAGE_REF="$1"
RUN_ID="${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-0}-${RANDOM}"
NETWORK="s4-release-smoke-${RUN_ID}"
MINIO_NAME="s4-minio-${RUN_ID}"
GATEWAY_NAME="s4-gateway-${RUN_ID}"
MINIO_IMAGE="minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
MC_IMAGE="minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
MC_CONF="s4-release-smoke-mc-${RUN_ID}"
GATEWAY_PORT="${S4_RELEASE_SMOKE_PORT:-18080}"

cleanup() {
  docker rm -f "$GATEWAY_NAME" "$MINIO_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$MC_CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$NETWORK" >/dev/null
docker volume create "$MC_CONF" >/dev/null
docker run -d --name "$MINIO_NAME" --network "$NETWORK" \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  "$MINIO_IMAGE" server /data >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker exec "$MINIO_NAME" curl --fail --silent \
      http://127.0.0.1:9000/minio/health/live >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$MINIO_NAME" || true
  echo "ERROR: release-smoke MinIO did not become ready" >&2
  exit 1
fi

docker run --rm --network "$NETWORK" -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color \
  alias set local "http://${MINIO_NAME}:9000" minioadmin minioadmin >/dev/null
docker run --rm --network "$NETWORK" -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color \
  mb "local/s4-release-smoke" --ignore-existing >/dev/null

docker run -d --name "$GATEWAY_NAME" --network "$NETWORK" \
  -p "127.0.0.1:${GATEWAY_PORT}:8080" \
  -e AUTH_DISABLED=true \
  -e S4_STREAMING_WRITE_MODE=all \
  -e S4_KEYS_FILE=/tmp/keys.json \
  -e S3_ENDPOINT="http://${MINIO_NAME}:9000" \
  -e S3_ACCESS_KEY_ID=minioadmin \
  -e S3_SECRET_ACCESS_KEY=minioadmin \
  -e S3_REGION=us-east-1 \
  "$IMAGE_REF" >/dev/null

ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${GATEWAY_PORT}/health" >/dev/null; then
    ready=1
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "$GATEWAY_NAME")" != "true" ]; then
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$GATEWAY_NAME" || true
  echo "ERROR: packaged gateway did not become ready" >&2
  exit 1
fi

INPUT='contact release-smoke@example.com card 4111111111111111'
curl --fail --silent --show-error \
  -X PUT \
  -H 'Content-Type: text/plain' \
  --data-binary "$INPUT" \
  "http://127.0.0.1:${GATEWAY_PORT}/s4-release-smoke/object.txt" >/dev/null

READBACK="$(docker run --rm --network "$NETWORK" -v "$MC_CONF:/root/.mc" "$MC_IMAGE" --no-color \
  cat 'local/s4-release-smoke/object.txt')"
case "$READBACK" in
  *'[REDACTED_EMAIL]'*'[REDACTED_CARD]'*) ;;
  *)
    echo "ERROR: packaged gateway did not persist expected transformed markers" >&2
    exit 1
    ;;
esac
if [[ "$READBACK" == *"release-smoke@example.com"* || "$READBACK" == *"4111111111111111"* ]]; then
  echo "ERROR: packaged gateway persisted raw PII" >&2
  exit 1
fi

echo "release image data-plane smoke passed"
