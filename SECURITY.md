# Security Policy

Thanks for helping keep Sentora and its users safe.

## Supported versions

Only the latest tagged release on `main` receives security updates.

| Version | Supported |
| :--- | :---: |
| `main` (latest) | yes |
| older tags | no |

## Reporting a vulnerability

Please do not file public GitHub issues for security problems.

Use one of the following instead:

1. GitHub Private Vulnerability Reporting (preferred):
   <https://github.com/0giv/Sentora-Community-Edition/security/advisories/new>
2. Open an issue tagged `security-contact` asking for a private channel.
   Do not include exploit details in that issue.

A maintainer will reply within 5 working days to confirm receipt and
agree on a disclosure timeline.

## What to include

The faster the report can be reproduced, the faster it gets fixed.
Helpful detail:

- The affected commit SHA or release tag.
- A minimal reproduction (HTTP request, agent payload, config snippet).
- The observed impact (RCE, auth bypass, data exposure, DoS, etc.).
- Any logs, stack traces or screenshots that make the issue concrete.
- Your suggested fix, if you have one.

If a CVE is appropriate we will request one through GitHub Security
Advisories.

## Disclosure policy

- We aim to ship a fix within 90 days of a confirmed report.
- Critical issues (unauthenticated RCE, auth bypass, secret disclosure)
  get an out-of-band release; other severities ride the next normal
  release.
- You will be credited in the advisory unless you ask to stay anonymous.

## Scope

In scope:

- Server (`app.py`, `server.py`, `ai_worker.py`, `ai/`, `core/`,
  `scanners/`).
- Agent (`Sentora/`) and its bundled binaries.
- Frontend (`frontend/`).
- Default Docker Compose deployment.

Out of scope:

- Vulnerabilities in third-party dependencies. Report those upstream.
- Self-inflicted issues from intentionally weakening the default
  configuration (for example exposing `:8000` to the public internet
  without TLS, leaving `admin / admin123`, disabling `@require_permission`
  guards, etc.). Document them in an issue instead.
- The ship-with self-signed development certificates in `certs/`. They
  exist for `localhost` demos and are documented as not-secret.
