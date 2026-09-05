# Owners

## Maintainers

| Role | GitHub | Scope |
| --- | --- | --- |
| Owner / maintainer | [@amit231self](https://github.com/amit231self) | all areas, releases, CI, Pages/docs |

The single-owner status is intentional today. As contributors join, add them
here, extend `CODEOWNERS`, and then enable required CODEOWNERS reviews on
`main` (see the "Branch protection" notes below).

## Decision process

- Proposals start as a GitHub issue or discussion.
- Substantive architecture or security decisions are recorded as
  Architecture Decision Records in `docs/adr/` and merged with their change.
- Releases are cut from `main` by the release workflow and published as
  GitHub Releases with prebuilt binaries and the canonical/legacy container
  images.

## Commit identity policy

- Every commit is authored by a real human with their **GitHub identity**
  (for the maintainer: `amit231self <amit@231self.com>`).
- Do **not** append AI `Co-Authored-By` / `Generated with` trailers
  (Claude, Codex, etc.) to commit messages — they create phantom entries on
  the contributors graph. See `CONTRIBUTING.md`.

## Branch protection (admin)

`main` currently uses classic branch protection:

- required status check: `check` (aggregate CI), strict, admin-enforced
- required linear history / force pushes / deletions: off

Keep force-pushes to `main` an exceptional, coordinated action. History has
been rewritten once to remove a wrong author email and AI co-author trailers;
do not rewrite again without a documented reason.
