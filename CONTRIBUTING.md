# Contributing to Sentora Community Edition

Thanks for thinking about contributing. This document covers what you'll
want to know before opening an issue or a pull request.

## Quick links

- [Report a bug](https://github.com/0giv/Sentora-Community-Edition/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/0giv/Sentora-Community-Edition/issues/new?template=feature_request.yml)
- [Architecture deep dive](docs/Sentora_Architecture.md)
- [Development setup](#development-setup)

---

## Code of conduct

Be respectful, assume good intent, and keep discussion on-topic.
Security-sensitive issues should go through the process in
[SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities.

---

## How to contribute

### Reporting bugs

Use the Bug report issue template. Include:

- The exact version (commit SHA or release tag)
- Stack: OS, Docker / Compose version
- Reproduction steps. The more minimal, the faster the fix
- Relevant logs (`docker compose logs app`, agent stderr/stdout)
- Expected vs. observed behaviour

### Requesting features

Use the Feature request template. State the problem first, then the
proposed solution. Mention alternatives you've considered. Anything
adjacent to the paid Pro / Enterprise tier (multi-tenancy, SAML, SLA
support, compliance reporting) belongs in the commercial roadmap. Open
an issue tagged `enterprise-fit` and we'll route it.

### Pull requests

1. Open an issue first for non-trivial changes so we can agree on
   direction before you spend time coding.
2. Fork, feature branch, PR against `main`.
3. Make sure the test suite passes locally (`pytest`) and the frontend
   type-checks (`cd frontend && npx tsc --noEmit`).
4. Follow the conventions in [docs/Sentora_Architecture.md](docs/Sentora_Architecture.md):
   - New REST routes go behind `@require_permission(...)`. No exceptions.
   - New encrypted columns must be registered in `ENCRYPTED_FIELDS_MAP`.
   - AI worker outputs must be strict JSON (use `_extract_json` for parsing).
5. Fill in the Pull request template, especially the testing checklist.
6. Sign off your commits (`git commit -s`). By signing you confirm
   [Developer Certificate of Origin](https://developercertificate.org/)
   compliance.

PRs that change agent code must also bump `Sentora/VERSION` if the
on-the-wire protocol or auth changes.

---

## Development setup

```bash
git clone https://github.com/0giv/Sentora-Community-Edition.git
cd Sentora-Community-Edition
cp .env.example .env
# Edit .env. Set DB_PASSWORD and OPENSEARCH_PASSWORD at minimum.

docker compose up --build -d
```

Open <http://localhost:8000>. Default UI login is `admin / admin123`
(change it on first boot).

For tighter feedback loops you can run pieces outside Docker:

```bash
# Backend with hot reload
pip install -r requirements.lock

# requirements.lock pins every direct and transitive version, so a build of
# this commit installs the same code next month as it does today. Adding a
# dependency means editing requirements.txt and regenerating the lock — the
# command is in the lock's own header, and CI fails if the two disagree.
python app.py --debug

# Frontend with Vite HMR
cd frontend && npm install && npm run dev
```

The frontend dev server proxies `/api` to `http://localhost:8000`.

### Running the test suite

```bash
pip install -r requirements-dev.txt
pytest                                      # all tests
pytest -k auth                              # only auth tests
pytest --cov=ai --cov=core --cov=scanners   # with coverage
```

Frontend has type-checking only right now, no Jest suite yet:

```bash
cd frontend
npx tsc --noEmit
```

PRs adding meaningful test coverage in either layer get fast-tracked.

---

## Coding conventions

### Backend (Python)

- Python 3.10+. No breaking deps in `requirements.txt` without an
  in-PR justification.
- Sanic routes return `sanic_json(...)` not raw `dict`. Keeps the
  response envelope consistent.
- Long-running blocking calls go in `asyncio.to_thread(...)`. Do not call
  `requests.*` from the event loop.
- Keep `app.py` route handlers thin. Push real work into `ai/`, `core/`,
  `scanners/`.
- New files belong in the matching package: AI work in `ai/`, generic
  infrastructure in `core/`, scanners in `scanners/`. Don't drop new
  modules at the repository root.
- English in user-facing strings (UI labels, REST responses, log lines).
  Comments can be any language but English is preferred for shared code paths.

### Frontend (TypeScript / React)

- Avoid runtime style libraries. Inline styles plus CSS variables match the
  existing pattern.
- Lucide icons only (we already depend on it). Don't add another icon set
  unless you replace `lucide-react` outright.
- New API surface goes through `frontend/src/services/api.ts`. Never call
  `axios` / `fetch` from a component.

### Agent (`Sentora/`)

- Anything that can fail on Windows must be guarded with a try/except
  (the agent runs without admin in dev/WSL).
- `enc_db` is the sole interface to the local DB. Don't bypass it.
- Encrypted-field declarations must match `ENCRYPTED_FIELDS_MAP` on the
  server, otherwise telemetry won't decrypt.

---

## Commit messages

Format:

```
area: short imperative summary

Optional longer body explaining why, wrapping at ~72 chars.
Reference issues like #123 in either subject or body.

Signed-off-by: Your Name <you@example.com>
```

Common prefixes used in the repo:

- `app:` Sanic API
- `agent:` Sentora/ agent
- `frontend:` React UI
- `ai:` AI workers / triage
- `scanner:` Vulnerability scanner
- `docs:` Documentation only
- `ci:` CI config

---

## Releasing (maintainers)

1. Bump version in `frontend/package.json` and `Sentora/VERSION` if applicable.
2. Update `docs/Sentora_Architecture.md` if architecture changed.
3. Tag: `git tag -a vX.Y.Z -m "..."`, then `git push --tags`.
4. Draft a GitHub release with the changelog auto-generated from commits.
