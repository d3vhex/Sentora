"""Locate the key that agent telemetry is encrypted with.

There are two Fernet keys in this system and they are not interchangeable:

- **`FERNET_KEY`** (environment, from `.env`) protects server-side secrets -
  the stored SMTP and LDAP passwords. `load_or_create_fernet_from_env`.
- **`data/fernet.key`** (the `sentora_data` volume) protects agent telemetry.
  It is what `/api/agents/bootstrap` hands to each agent, and what
  `app.ctx.fernet_key` holds. `load_or_create_fernet_key`.

The names are close enough that host-side tooling reached for the wrong one:
`build_eval_corpus.py` and `rule_hit_report.py` both read `FERNET_KEY` from
`.env`, decrypted nothing, and reported "no events" rather than "every row
failed to decrypt". A corpus built that way would have been empty, and a rule
report would have declared the ruleset silent.
"""

from __future__ import annotations

import os
import pathlib
import subprocess

DEFAULT_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "fernet.key"


class KeyNotFound(RuntimeError):
    """Raised with the places that were tried, so the message is actionable."""


def find_agent_key(container: str = "sentora-server") -> str:
    """Return the agent telemetry key, or raise KeyNotFound listing the tries.

    Order: explicit override, local file (works in-container and for a
    bare-metal run), then the running container - which is the usual case for
    a script run on the host against a compose deployment.
    """
    tried: list[str] = []

    override = os.getenv("AGENT_FERNET_KEY")
    if override and override.strip():
        return override.strip()
    tried.append("AGENT_FERNET_KEY (unset)")

    path = pathlib.Path(os.getenv("FERNET_KEY_PATH", str(DEFAULT_PATH)))
    if path.exists():
        key = path.read_text(encoding="utf-8").strip()
        if key:
            return key
    tried.append(f"{path} (absent or empty)")

    # The volume is not visible from the host, so ask the container that
    # mounts it. Failing softly here keeps the script usable without docker.
    try:
        r = subprocess.run(
            ["docker", "exec", container, "cat", "/app/data/fernet.key"],
            capture_output=True, text=True, timeout=15,
        )
        key = (r.stdout or "").strip()
        if r.returncode == 0 and key:
            return key
        tried.append(f"docker exec {container} (rc={r.returncode})")
    except (OSError, subprocess.SubprocessError) as e:
        tried.append(f"docker exec {container} ({type(e).__name__})")

    raise KeyNotFound(
        "Could not find the agent telemetry key. Tried:\n  - "
        + "\n  - ".join(tried)
        + "\n\nNote this is NOT the FERNET_KEY in .env - that one protects "
          "server-side secrets (SMTP, LDAP), not agent telemetry.\n"
          "Set AGENT_FERNET_KEY, or run where data/fernet.key is readable."
    )


def decrypt_stats(rows, fernet, prefix: str = "enc::") -> tuple[list[str], dict]:
    """Decrypt what can be decrypted and count what cannot.

    Returns `(plaintexts, stats)`. Undecryptable rows are counted rather than
    skipped in silence: "0 events" and "9 events with the wrong key" need
    different actions, and reporting the second as the first sends you looking
    at the wrong thing.
    """
    from cryptography.fernet import InvalidToken

    out: list[str] = []
    stats = {"total": 0, "plaintext": 0, "decrypted": 0, "undecryptable": 0}
    for raw in rows:
        stats["total"] += 1
        if not isinstance(raw, str) or not raw.startswith(prefix):
            stats["plaintext"] += 1
            out.append(str(raw or ""))
            continue
        try:
            out.append(fernet.decrypt(raw[len(prefix):].encode()).decode())
            stats["decrypted"] += 1
        except InvalidToken:
            stats["undecryptable"] += 1
    return out, stats


def report_decrypt_stats(stats: dict) -> None:
    """Print the counts, and say what an all-undecryptable run means."""
    print(f"[*] {stats['total']} row(s): {stats['decrypted']} decrypted, "
          f"{stats['plaintext']} plaintext, {stats['undecryptable']} undecryptable")
    if stats["undecryptable"] and not stats["decrypted"]:
        print("[!] Nothing decrypted. The key does not match what wrote these "
              "rows -\n    check that data/fernet.key is the one the agent "
              "bootstrapped with.")
