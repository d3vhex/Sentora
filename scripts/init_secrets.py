#!/usr/bin/env python3
"""Fill in the generated secrets in .env.

Run once after `cp .env.example .env`:

    python scripts/init_secrets.py

Safe to re-run: a key that already holds a real value is never touched, so
this cannot rotate FERNET_KEY out from under a database full of values
encrypted with the old one. Only empty values and `<PLACEHOLDER>` markers are
filled in.

Values are generated with the `secrets` module (the OS CSPRNG). Do not
hand-write these — an at-rest encryption key is exactly the value that has to
come from a real random source.
"""

from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# A value is considered unset if it is empty or still a <PLACEHOLDER>.
PLACEHOLDER = re.compile(r"^\s*$|^<.*>$")


def _url_safe_password() -> str:
    """URL-safe alphabet only.

    docker-compose interpolates the broker password into
    `amqp://user:pass@rabbitmq/` without escaping, so a ':' '@' or '/' would
    silently produce a broken connection string rather than an error.
    """
    return secrets.token_urlsafe(24)


GENERATORS = {
    "FERNET_KEY": (
        lambda: Fernet.generate_key().decode(),
        "server-side at-rest encryption key",
    ),
    "RABBITMQ_PASSWORD": (
        _url_safe_password,
        "message broker password",
    ),
    "AGENT_SHARED_SECRET": (
        # app.py generates an ephemeral one at import when this is unset, so
        # every server restart invalidated the fallback key and any agent
        # relying on it started getting 401s until it re-enrolled.
        lambda: secrets.token_urlsafe(32),
        "agent X-Agent-Key fallback, pinned across restarts",
    ),
    "OPENSEARCH_PASSWORD": (
        # Not load-bearing today — the cluster runs with
        # DISABLE_SECURITY_PLUGIN and ignores the Basic auth header
        # core/opensearch.py sends. Generated anyway so it is not shared with
        # DB_PASSWORD on the day the security plugin gets switched on.
        _url_safe_password,
        "OpenSearch credential (inert until the security plugin is enabled)",
    ),
}

# Deliberately NOT generated here: DB_PASSWORD. MySQL fixes the root password
# when the data volume is first initialised, so rewriting the env value alone
# does not change the account — it just stops the app from connecting. Use
# scripts/rotate_db_password.py, which alters the live account first.


def main() -> int:
    if not ENV_PATH.exists():
        print(f"[!] {ENV_PATH} not found. Run `cp .env.example .env` first.")
        return 1

    lines = ENV_PATH.read_text(encoding="utf-8").splitlines(keepends=True)

    present: dict[str, int] = {}
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in GENERATORS:
            present[key] = i

    filled, kept, appended = [], [], []

    for key, (generate, description) in GENERATORS.items():
        if key in present:
            idx = present[key]
            current = lines[idx].strip().split("=", 1)[1]
            if not PLACEHOLDER.match(current):
                kept.append(key)
                continue
            ending = "\n" if lines[idx].endswith("\n") else ""
            lines[idx] = f"{key}={generate()}{ending}"
            filled.append((key, description))
        else:
            if lines and not lines[-1].endswith("\n"):
                lines.append("\n")
            lines.append(f"{key}={generate()}\n")
            appended.append((key, description))

    if not filled and not appended:
        print("[=] Nothing to do — every generated secret already has a value.")
        for key in kept:
            print(f"    kept {key}")
        return 0

    ENV_PATH.write_text("".join(lines), encoding="utf-8")

    # The values themselves are deliberately not printed: this runs in a
    # terminal whose scrollback outlives the process.
    for key, description in filled:
        print(f"[+] Generated {key}  ({description})")
    for key, description in appended:
        print(f"[+] Appended  {key}  ({description})")
    for key in kept:
        print(f"[=] Kept existing {key}")

    print(
        "\n    Back up .env — FERNET_KEY has no rotation path, and losing it\n"
        "    makes every value encrypted with it unreadable."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
