set shell := ["bash", "-euo", "pipefail", "-c"]

export RUSTFLAGS := "-D warnings"

_default:
  @just --list

# Fast format + clippy (used by pre-commit hook)
check-fast: check-fmt check-lint
  @echo "Fast checks passed"

# Full check: format, lint, build filters, tests
check: check-fmt check-lint build-filters test
  @echo "All checks passed"

check-fmt:
  cargo fmt --check

check-lint:
  cargo clippy --all-targets -- -D warnings

test:
  cargo test --workspace

build-filters:
  bash scripts/build-filters.sh

deny:
  cargo deny check

audit:
  cargo audit

# Meta-linter: runs all static checks + dependency audit (like ruff/golangci-lint)
lint: check-fmt check-lint deny
  @echo "Meta-lint passed"

# Full lint including security audit and tests
lint-full: lint audit test
  @echo "Full lint passed"

# End-to-end validation with MinIO (requires Docker)
e2e:
  bash scripts/e2e-local.sh

# Streaming data-plane focused suite (the gateway crate is the streaming plane)
test-streaming:
  cargo test -p s4-gateway

# Streaming end-to-end against MinIO (direct S3 sink; requires Docker)
e2e-streaming:
  bash scripts/e2e-local.sh

# Unmodified AWS CLI + boto3 interop (requires awscli/boto3 on PATH)
interop:
  cargo test -p s4-gateway --test s3_frontdoor_test available_aws_cli_and_boto3_interoperate

# Fault-injection suite: multipart staging fault matrix + streaming failure paths
fault-streaming:
  cargo test -p s4-gateway multipart_staging::tests
  cargo test -p s4-gateway --test s3_frontdoor_test streaming_put_limit_failure_has_no_partial_visibility
  cargo test -p s4-gateway --test s3_frontdoor_test unsafe_transformed_failures_never_disclose_early_late_or_finish_output
  cargo test -p s4-gateway --test s3_frontdoor_test valid_sigv4_seed_polls_then_rejects_payload_hash_mismatch

# Fixed-RSS memory bound (1 GiB source; asserts allocation is object-size-independent)
bench-rss:
  cargo test -p s4-gateway --test streaming_rss -- --nocapture

# Soak: high-case-count property tests + repeated streaming round-trips
soak-streaming:
  PROPTEST_CASES=10000 cargo test -p s4-gateway --test property --test record_decoder
  S4_SOAK_ITERATIONS=500 cargo test -p s4-gateway --test s3_frontdoor_test soak_streaming_roundtrip_holds_under_repetition -- --ignored

# Release image smoke (boot smoke against the built OCI image)
release-smoke:
  bash scripts/release-image-smoke.sh

# Run the CI workflow locally with act (no GitHub minutes)
ci-local:
  act -W .github/workflows/ci.yml

# Run the release workflow locally with act (tag event; GHCR push needs a
# token with packages scope)
release-local:
  act -W .github/workflows/release.yml -e act/event-tag.json

# Build + test in a dagger container (cargo registry + target cached)
build-local:
  dagger call ci

# Build the deploy image locally (dagger)
image-local:
  dagger call image

# Build + publish the deploy image to GHCR (needs: docker login ghcr.io once)
publish-local TAG='latest':
  dagger call publish --tag={{TAG}}

# Start local dev environment (Docker Compose + MinIO + gateway)
dev-up: build-filters
  docker compose -f local/docker-compose.yml up -d --build --wait minio gateway
  echo "Local dev environment ready:"
  echo "  MinIO:     http://localhost:9000 (API) / :9001 (Console)"
  echo "  Gateway:   http://localhost:8080/health"
  docker run --rm --network host minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727 --no-color mb local/s4-local --ignore-existing 2>/dev/null || true
  echo "  S3 bucket: s4-local (created)"

# Stop local dev environment
dev-down:
  docker compose -f local/docker-compose.yml down

# Full dev flow: start infra + run E2E test
dev: dev-up
  cargo run -p s4ctl -- test upload

# Generate client SDKs from OpenAPI spec (requires Docker)
# Produces sdks/python/ and sdks/typescript/
build-sdks: build-filters
  bash scripts/generate-sdks.sh
