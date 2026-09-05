# Local end-to-end suite

The gateway ships a local, no-secrets end-to-end suite that boots a real
MinIO S3 backend plus the gateway binary and exercises public HTTP features
against it. It runs in CI (`ci.yml`, `weekly.yml`, `nightly.yml`) and locally,
and needs no Supabase, Postgres, cloud credentials, or signed-in users.

```bash
just e2e                  # run the full suite
bash scripts/e2e-local.sh # same, without `just`
```

## How it is structured

- `scripts/e2e-local.sh` — the orchestrator. Boots the shared environment
  once, runs every feature script in `scripts/e2e/features/`, aggregates
  PASS/FAIL, and exits 0 only when all features pass.
- `scripts/e2e/lib.sh` — the shared harness contract and helpers
  (`pass`/`fail`, HTTP-status and content assertions, JSON field extraction).
- `scripts/e2e/features/NN-*.sh` — one discrete, independently-runnable
  feature script per concern. Feature order is lexicographic; stateful
  features (plugin management) run last.

A feature may also be run alone against a freshly booted environment:

```bash
bash scripts/e2e-local.sh 30-keys-s3-lifecycle
# accept a bare feature number/name or a path:
bash scripts/e2e-local.sh 30-keys-s3-lifecycle.sh
```

## Boot contract

The orchestrator starts (or reuses) one shared environment for every feature:

- **MinIO on `:9000`** — if a healthy MinIO is already listening there
  (`minioadmin`/`minioadmin`), it is reused instead of failing on the port
  clash (common when a dev/ad MinIO is running). Otherwise `docker compose -f
  local/docker-compose.yml up -d minio` starts one, torn down on exit.
- **Bucket `s4-local`** is created if missing.
- **Gateway (AUTH_DISABLED)** on `$MASKURA_E2E_GW_PORT` (default `9010`),
  single-tenant streaming against that MinIO, an isolated `keys.json`, the
  built `pii-default` component, and `MASKURA_STREAMING_WRITE_MODE=single` /
  `READ_MODE=passthrough`.
- Gateway, MinIO, and the filter/binaries are **built from the working tree**
  each run, so the suite validates the code you have checked out.

Requirements: `bash`, Docker + `docker compose`, `curl`, `python3`, and a Rust
toolchain with the WASM/WASI targets used by `scripts/build-filters.sh`. No
environment variables, secrets, or network access are required.

> Note: with `AUTH_DISABLED=true`, unauthenticated and unresolvable-credential
> requests are admitted as the demo user. Key expiry/revocation *rejection*
> therefore cannot be asserted against the shared gateway; the strict-auth
> feature (below) covers denial semantics on a second gateway instead.

## Features

| Script | Concern | What it proves |
| --- | --- | --- |
| `10-http-surface.sh` | HTTP surface | `/health`; `/` serves the dashboard HTML and is not an S3 `ListBuckets` XML response; `/openapi.json` is OpenAPI 3.1 and documents `/dashboard/api/keys` and `/dashboard/api/backend`; `/docs` serves Swagger UI (following the redirect); retired `/dashboard/api/demo/store` returns 410 for every method |
| `15-avro-gate.sh` | Avro gate | A PUT with `Content-Type: application/avro` is rejected (501) while `MASKURA_ENABLE_AVRO` is unset, and nothing is stored |
| `20-redaction-roundtrip.sh` | Core redaction | `maskura test upload` stores a PII fixture through the pipeline; the object read directly back from MinIO contains `[REDACTED_EMAIL]`/`[REDACTED_SSN]`/`[REDACTED_CARD]` and no plaintext |
| `25-strict-auth-denial.sh` | Auth enforcement | Boots a second, isolated gateway on `$MASKURA_STRICT_GW_PORT` (default `9011`) **without** `AUTH_DISABLED` and an empty keystore: unauthenticated S3 PUT/GET/List are denied 403 and the dashboard key API is denied 401 — no demo fallback |
| `30-keys-s3-lifecycle.sh` | Keys + S3 data plane | Dashboard key create / list / revoke happy paths (`s4_`/`s4s_` formats, revoke returns 204 and removes the key); header-authenticated S3 PUT → HEAD → GET byte-identical read-back → ListObjects v1 and v2 via the real MinIO backend → DELETE → 404 |
| `40-plugin-admin-http.sh` | Plugin management | Import a real `.wasm` component (201), catalog list, enable (200 + `enabled: true`), reorder, and remove (204) over the HTTP admin routes mounted in `AUTH_DISABLED` mode. Runs last because enabling an imported component can change the write pipeline |

Each feature prints `PASS:`/`FAIL:` lines and exits non-zero on failure, so a
feature can also be executed directly against an already-booted environment.

## What the suite covers beyond the old e2e

The original e2e only exercised `GET /health` and one demo-mode `test upload`.
The suite now also asserts previously untested public paths:

- S3-backend `ListObjects` v1 + v2 and byte-faithful authenticated
  PUT/HEAD/GET/DELETE against a real S3 backend (MinIO).
- `GET`/`DELETE /dashboard/api/keys` happy paths and the dashboard key format.
- Dashboard HTML, `/openapi.json` + `/docs` serving, and legacy tombstone 410s.
- Plugin import / list / enable / reorder / remove across the real HTTP router.
- Data-plane + dashboard denial on a non-`AUTH_DISABLED` boot (no demo fallback).
- The Avro enablement gate (negative path).

## Deferred scenarios (and why they are separate harnesses)

The following need a different gateway boot contract or extra tooling, so they
are deliberately not part of this suite yet. Each is a natural future
`NN-*.sh` with its own boot:

- **Positive Avro round trip and envelope/stable field encryption** —
  need `MASKURA_ENABLE_AVRO=true`, an authenticated public key, OCF fixtures,
  and an Avro codec (e.g. `fastavro`) on the runner to assert typed output.
  See `docs/avro.md`.
- **Managed service storage** — needs a multi-backend boot with
  `S4_SERVICE_BUCKETS` and no `S3_ENDPOINT` (the two are mutually exclusive at
  startup).
- **Staged multipart** — needs Postgres and a durable KEK
  (`MULTIPART_MODE=staged` + `DATABASE_URL`); covered today by the
  Postgres-gated `db_keys_test` CI job.
- **Key expiry/revocation rejection on the data plane** — needs an
  auth-enabled boot that can create keys (with `AUTH_DISABLED` unset, the
  dashboard key API requires a real user session).
- **Presigned URL proxy** — needs a container-network harness: the host-run
  gateway cannot deterministically reach the local MinIO loopback over IPv4 on
  all Docker setups, and the SSRF allowlist rejects IP-literal hosts.
- **SDK / MCP live round trips** — need the Python/TypeScript SDK or MCP
  runtime dependencies on the runner.

## Adding a feature

1. Create `scripts/e2e/features/NN-short-name.sh` that sources
   `../lib.sh`, calls `begin_feature`, asserts with `expect_status` /
   `assert_contains` / `assert_absent`, and ends with `end_feature "<name>"`.
2. Use unique object keys and, when mutating the gateway state, place the
   feature last (as `40-plugin-admin-http.sh` does).
3. If the feature needs its own gateway, boot it on its own port and keys file
   and stop it on `EXIT` (see `25-strict-auth-denial.sh`).
4. Keep it deterministic in CI: only `bash`, `curl`, `python3`, Docker, and
   the artifacts the orchestrator already builds. Remember `curl
   --data-binary` implies **POST** unless `-X PUT` is given.

## Troubleshooting

- If MinIO is already running on `:9000` the orchestrator reuses it; give it a
  moment or confirm `curl http://127.0.0.1:9000/minio/health/live` succeeds.
- The gateway log is written to the isolated run directory
  (`$E2E_KEYS_DIR/gateway.log`) and removed on exit; run a single feature and
  check the `FAIL:` lines for the exact assertion that broke.
