# Security Policy

S4 processes potentially sensitive data (it exists to keep PII out of storage), so we
take security reports seriously.

## Reporting a vulnerability

- **Do not** open a public issue.
- Email **security@231self.com** or use GitHub's private vulnerability reporting on
  this repository (Security → Report a vulnerability).
- Include: affected version/commit, a minimal reproduction, impact, and any suggested
  fix if you have one.

We will acknowledge within 48 hours and aim for a fix and disclosure timeline
proportional to severity.

## Scope

- The gateway (`crates/gateway`) — auth, key handling, storage forwarding.
- The Wasm filter runtime and plugins (`crates/wasm-runtime`, `filters/`).
- The envelope-encryption design (see `docs/adr/`).
- SDKs (`sdks/`) and the CLI (`crates/s4ctl`).

Out of scope: third-party services you point S4 at (S3 providers, Supabase).

## Key rotation

- S4 stores only SHA-256 hashes of API key secrets, never plaintext.
- If you suspect a key compromise, revoke it immediately (`s4ctl key revoke`) and
  rotate your backend credentials.
