# Pull request template

Thank you for contributing to Maskura. Fill in what applies; delete the
sections that do not.

## Summary

<!-- What this PR changes and why, in a few sentences. -->

## Motivation / related issue

<!-- "Closes #NN" when an issue exists. -->

## Test plan

- [ ] `just check` (fmt + clippy + build filters + tests)
- [ ] `just e2e` (if gateway/data-plane behavior changed)
- [ ] `cargo check -p s4-gateway` (dashboard/HTML changes — embedded via include_str!)
- [ ] `mdbook build docs` (if `docs/` chapters changed)

## Docs & UI

<!-- README/docs changes, dashboard snippets affected, screenshots if any. -->

## Checklist

- [ ] Committed with a real author identity (no AI `Co-Authored-By` trailers)
- [ ] Behavior changes ship with tests
- [ ] `docs/` or `AGENTS.md` updated when behavior/architecture changed
