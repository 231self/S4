# Contributing

Thanks for considering a contribution to Maskura.

## Getting started

1. Fork [Maskura on GitHub](https://github.com/231self/S4/fork) and clone your fork.
2. Install Rust 1.97.0 (see `rust-toolchain.toml`) with the `wasm32-wasip1` target:
   `rustup target add wasm32-wasip1`
3. Install `wasm-tools` (`cargo install --locked wasm-tools --version 1.255.0`) and `just`.
4. Run `just check` — it must pass locally before opening a PR.

## Conventions

- Rust 2024 edition. No warnings allowed: production code builds with
  `RUSTFLAGS=-D warnings`.
- Every functional change ships with tests. Maskura favors unit tests in the crate plus
  end-to-end coverage (`just e2e`, broken down feature-by-feature in `docs/e2e.md`).
- No raw SQL strings inline; use `sqlx` (runtime-checked queries) and migrations in
  `migrations/`. Never apply schema changes by hand.
- Keep the Wasm filter boundary clean: plugins are pure byte-in/byte-out, no host
  imports.
- Match the surrounding code style; do not add comments unless they earn their place.

- Architectural changes (interfaces, trust boundaries, storage, security,
  deployment) create or update an ADR in `docs/adr/` — see the rules in
  `OWNERS.md` under "Architecture Decision Records".

## Commit messages

- Concise, imperative summary line (≤ ~72 chars), then a body explaining the *why*.
- Reference the issue/PR number when applicable.

## Pull requests

- Target `main`. CI runs format, clippy, tests, filter builds, and a MinIO
  end-to-end pass on every PR.
- Use the PR template (`.github/pull_request_template.md`): summary, linked
  issue, and a test plan.
- Keep changes scoped; split unrelated work into separate PRs.
- Update `docs/` or `AGENTS.md` when behavior or architecture changes.
- `main` is protected: the aggregate `check` CI status must pass and the
  branch must be up to date.

## Testing

```bash
just check        # full gate
just e2e          # MinIO end-to-end (Docker)
cargo test --workspace
```

Integration tests that need `DATABASE_URL` skip themselves when it is unset. CI provides
Postgres and requires these tests to run successfully.

## Author identity

- Commit with your real GitHub identity (for the maintainer:
  `amit231self <amit@231self.com>`). The repo keeps a `.mailmap` so `git log`
  and stats show one canonical author.
- Do **not** append AI `Co-Authored-By` / `Generated with <tool>` trailers
  (Claude, Codex, and similar) to commit messages. They create phantom entries
  on GitHub's contributors graph. If you want to credit assistance, say it in
  the PR description instead.
- If you ever commit with the wrong email, say so in the PR — the maintainers
  prefer correcting attribution before merge over rewriting history later.

## Docs site

The docs are an mdBook site in `docs/` (chapters listed in `docs/SUMMARY.md`,
config in `docs/book.toml`), published to GitHub Pages from `main`. When you
change a chapter, run `mdbook build docs` locally (`brew install mdbook`) and
keep out-of-tree links as `https://github.com/231self/maskura/blob/main/...`
URLs rather than relative `../` paths.

## Maintainers and ownership

See `OWNERS.md` for the maintainer list, decision process, and branch
protection notes.

## Security

Do not open an issue for a security vulnerability — see `SECURITY.md`.
