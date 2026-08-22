# Security Policy

S4 is a processing gateway for object storage: it exists so that sensitive data
(PII, credentials, regulated fields) is transformed before it reaches a storage
backend. We take security reports seriously and publish this policy so
reporters know exactly what is supported, how to report privately, and what we
commit to in return.

## Supported versions

We support the **latest stable minor release** of S4. Security fixes are
backported to that release line and shipped as a new patch release.

- Current stable line: **0.3.x** (this repository is at 0.3.5).
- Older minor releases receive security fixes on a best-effort basis only.
- Pre-release and `-dev` builds are not supported; move to the latest stable
  release before reporting.

If you are running a self-hosted gateway, upgrade to the latest release before
engaging with a report — we cannot validate or fix against a version we no
longer ship.

## Reporting a vulnerability

Please report security issues **privately**. Do **not** open a public issue,
pull request, or discussion.

Two equivalent private channels:

1. **GitHub private vulnerability reporting** — Security → Report a
   vulnerability on this repository.
2. **security@231self.com** — for reports that cannot go through GitHub, or
   for incidents already in progress.

### What to include in a report

A good report lets us reproduce and triage quickly:

- **Affected version or commit** — the release tag or commit hash you are
  running.
- **A minimal reproduction** — the smallest request, configuration, or plugin
  input that triggers the issue. Include the `S3` endpoint, headers, and
  body shape, but **never** live credentials.
- **Impact** — what an attacker can actually do (read, write, bypass, crash,
  data exposure) and under which feature gates the issue is reachable.
- **Suggested fix** — optional, but always welcome.

### What never belongs in a report

- **Live credentials** — do not include API key secrets, backend credentials,
  KEKs, wrapped or unwrapped data-encryption keys, or anything that could be
  used to authenticate to a live system. Redact them and describe the shape
  instead.
- **Live ciphertext or staging artifacts** — do not paste real encrypted
  objects, staging blobs, or ciphertext from a production tenant.
- **Signed URLs** — presigned URLs are bearer credentials; never include them.

If you are unsure whether a detail is sensitive, leave it out and tell us in
the report that you can share more under a confidentiality agreement.

## What happens next

1. **Acknowledgement within 48 hours.** We will confirm receipt, ask for any
   missing details, and assign an internal tracker.
2. **Assessment.** We determine severity, affected feature gates, and whether
   a fix requires a coordinated release.
3. **Fix and disclosure, proportional to severity.** We will publish a fix and
   a coordinated disclosure on a timeline proportional to the severity of the
   issue — faster for remotely exploitable, unauthenticated issues; more
   measured for configuration-dependent or low-severity findings.
4. **Credit.** With your consent, we will credit you in the advisory and
   release notes.

We ask that reporters coordinate disclosure with us and do not publicly
disclose the issue before we ship a fix (or before we confirm, in writing, that
we will not be fixing it).

## Scope

In scope:

- The gateway (`crates/gateway`) — authentication (SigV4, API keys), the
  transformation pipeline, transactional storage paths, and staging.
- The Wasm filter runtime and plugins (`crates/wasm-runtime`, `filters/`).
- The SDKs (`sdks/`) and the CLI (`crates/s4ctl`).
- The cryptographic designs described in `docs/adr/` and `docs/security.md`.

Out of scope:

- The security posture of the third-party storage backends S4 is pointed at
  (S3, R2, B2, MinIO, and similar). S4 transforms and forwards; it does not
  secure the destination.
- Supabase or other identity providers used for dashboard sessions.
- Vulnerabilities in upstream dependencies that have no S4-specific impact.

## Key handling note

S4 stores only envelopes and hashes of API key secrets, never plaintext. If you
suspect a key compromise, revoke the key immediately (`s4ctl key revoke`) and
rotate any backend credentials it could reach before reporting.
