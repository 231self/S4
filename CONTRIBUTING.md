# Contributing

Thanks for considering a contribution to S4.

## Getting started

1. Fork the repo and clone it.
2. Install Rust (see `rust-toolchain.toml`) with the `wasm32-unknown-unknown` target:
   `rustup target add wasm32-unknown-unknown`
3. Install `wasm-tools` (`cargo install --locked wasm-tools`) and `just`.
4. Run `just check` — it must pass locally before opening a PR.

## Conventions

- Rust 2024 edition. No warnings allowed: production code builds with
  `RUSTFLAGS=-D warnings`.
- Every functional change ships with tests. S4 favors unit tests in the crate plus
  end-to-end coverage (`just e2e`).
- No raw SQL strings inline; use `sqlx` (runtime-checked queries) and migrations in
  `migrations/`. Never apply schema changes by hand.
- Keep the Wasm filter boundary clean: plugins are pure byte-in/byte-out, no host
  imports.
- Match the surrounding code style; do not add comments unless they earn their place.

## Commit messages

- Concise, imperative summary line (≤ ~72 chars), then a body explaining the *why*.
- Reference the issue/PR number when applicable.

## Pull requests

- Target `main`. CI runs format, clippy, tests, filter builds, and a MinIO
  end-to-end pass on every PR.
- Keep changes scoped; split unrelated work into separate PRs.
- Update `docs/` or `AGENTS.md` when behavior or architecture changes.

## Testing

```bash
just check        # full gate
just e2e          # MinIO end-to-end (Docker)
cargo test --workspace
```

Integration tests that need `DATABASE_URL` skip themselves when it is unset, so local
runs and CI stay green without a database.

## Security

Do not open an issue for a security vulnerability — see `SECURITY.md`.
