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

# Start local dev environment (Docker Compose + MinIO + gateway)
dev-up: build-filters
  docker compose -f local/docker-compose.yml up -d --build --wait minio gateway
  echo "Local dev environment ready:"
  echo "  MinIO:     http://localhost:9000 (API) / :9001 (Console)"
  echo "  Gateway:   http://localhost:8080/health"
  docker run --rm --network host minio/mc --no-color mb local/s4-local --ignore-existing 2>/dev/null || true
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
