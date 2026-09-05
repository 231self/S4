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

## Architecture Decision Records

ADRs live in `docs/adr/NNNN-short-name.md` and render as a chapter on the
docs site. Write one when a change is architectural — a lasting choice about
interfaces, trust boundaries, storage, security, or deployment — not for
routine bug fixes or refactors.

Structure each ADR as:

```markdown
# ADR NNNN: Title

- Status: Accepted | Superseded by ADR-XXXX | Proposed
- Date: YYYY-MM-DD

## Context     -- the problem and options considered
## Decision    -- what was chosen and why
## Consequences -- what it costs and enables
```

Rules:

- Number sequentially; use the next free `NNNN` when adding a record.
- Keep `Status` honest: flip it to `Superseded by ADR-XXXX` (linking the
  replacement) when a later decision changes the earlier one — never rewrite
  or delete a superseded ADR's history.
- ADRs are written by the humans and agents making the decision, in the same
  PR/change as the work they describe.
- If an ADR no longer matches the code, updating or superseding it is part of
  the architectural change — not a separate docs chore.

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
