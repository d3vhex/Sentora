<!--
Thanks for the PR! Please tick the boxes that apply.
Squash-merge style: keep the PR title short and imperative
(e.g. "agent: trim disk_usage state to 64 chars").
-->

## What does this change?

<!-- 1-3 sentences describing what the patch does and why. -->

Fixes # / Refs #

## Type

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / tech-debt
- [ ] Documentation only
- [ ] CI / tooling

## Which surface?

- [ ] Frontend (React)
- [ ] Sanic API (`app.py`)
- [ ] Ingest server (`server.py`)
- [ ] AI worker (`ai_worker.py`, `ai/`)
- [ ] Vuln scanner (`scanners/`)
- [ ] Agent (Windows)
- [ ] Agent (Linux)
- [ ] Docs / templates / CI

## Testing checklist

- [ ] `pytest` passes locally
- [ ] `cd frontend && npx tsc --noEmit` passes
- [ ] Manually verified the happy path described above
- [ ] Manually verified at least one failure path / edge case
- [ ] Added or updated unit tests if the change is non-trivial

## Compatibility

- [ ] No breaking REST/API changes
  (or) I bumped the response envelope appropriately and updated the UI.
- [ ] No breaking agent-protocol changes
  (or) I bumped `Sentora/VERSION` and called this out below.
- [ ] No new env vars
  (or) I added them to `.env.example` with documentation.

## Screenshots / logs

<!-- For UI changes, before/after screenshots help. For bug fixes,
     paste relevant log lines showing the bug and its fix. -->

## Anything reviewers should pay extra attention to?

<!-- Hairy edge cases, alternatives you considered and dropped,
     follow-up work you'd file separately, etc. -->

---

By submitting this PR, I certify that I have the right to make this
contribution and agree to the
[Developer Certificate of Origin](https://developercertificate.org/).
