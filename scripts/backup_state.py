#!/usr/bin/env python3
"""Back up the state that only exists inside Docker.

    python scripts/backup_state.py            # write a dated backup
    python scripts/backup_state.py --list
    python scripts/backup_state.py --restore backups/2026-08-25T1300

Why this exists
---------------
Docker Desktop was reset and every named volume went with it. `mysql_data`
held every SIEM event, every agent database, users and sessions, and nothing
else had a copy. `opensearch_data` is derived from MySQL and would rebuild.

`sentora_data` held `data/fernet.key`, the **agent** telemetry key, which was
regenerated on the next boot - so telemetry encrypted under the old one is
unreadable for good. There is no rotation path.

There are two Fernet keys and they are not interchangeable:

    .env FERNET_KEY          the *server* key, on the host filesystem, so it
                             survived
    data/fernet.key          the *agent* key, inside the volume. Did not.

A backup covering only the first protects the half that was never at risk, and
only one of them belongs in a `backups/` directory - see the end of
`backup()`.

What is backed up
-----------------
Both, because they fail differently: `mysqldump --all-databases` survives a
MySQL version change and can be read by a human, and a tar of each volume
restores byte-for-byte including OpenSearch's on-disk format.

`.env` is **not** copied. It holds `FERNET_KEY`, `DB_PASSWORD` and the agent
shared secret, and writing those into a directory people tar up and move
around is how secrets end up somewhere nobody tracks. The script checks it
exists and tells you to back it up separately.
"""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BACKUPS = ROOT / "backups"

# The volumes compose declares. Read from the file rather than hard-coded, so
# a volume added later is not silently left out of every backup taken after.
COMPOSE = ROOT / "docker-compose.yaml"


def project_name() -> str:
    """Compose prefixes volume names with the project, which is the directory
    name unless COMPOSE_PROJECT_NAME says otherwise."""
    import os
    return os.getenv("COMPOSE_PROJECT_NAME") or ROOT.name.lower().replace(" ", "")


def declared_volumes() -> list[str]:
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML not installed; falling back to the known volumes")
        return ["mysql_data", "opensearch_data", "sentora_data"]

    doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8")) or {}
    return sorted((doc.get("volumes") or {}).keys())


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def volume_exists(name: str) -> bool:
    return run(["docker", "volume", "inspect", name]).returncode == 0


def backup(destination: pathlib.Path) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    prefix = project_name()
    problems = 0

    # --- the logical dump ---------------------------------------------------
    # Taken first and while the stack is up, because it needs a running MySQL.
    dump = destination / "all-databases.sql"
    print(f"[*] mysqldump -> {dump.name}")
    result = run(["docker", "compose", "exec", "-T", "db", "sh", "-c",
                  'exec mysqldump --all-databases --single-transaction '
                  '--routines --events -u root -p"$MYSQL_ROOT_PASSWORD"'],
                 cwd=ROOT)
    if result.returncode == 0 and result.stdout.strip():
        dump.write_text(result.stdout, encoding="utf-8")
        print(f"    {len(result.stdout):,} bytes")
    else:
        problems += 1
        print("[!] mysqldump failed - is the stack running?")
        print(f"    {(result.stderr or '').strip()[:300]}")

    # --- the raw volumes ----------------------------------------------------
    for short in declared_volumes():
        name = f"{prefix}_{short}"
        if not volume_exists(name):
            print(f"[!] volume {name} does not exist; skipping")
            problems += 1
            continue
        archive = destination / f"{short}.tar.gz"
        print(f"[*] {name} -> {archive.name}")
        result = run([
            "docker", "run", "--rm",
            "-v", f"{name}:/from:ro",
            "-v", f"{destination.as_posix()}:/to",
            "alpine", "tar", "czf", f"/to/{archive.name}", "-C", "/from", ".",
        ])
        if result.returncode != 0:
            problems += 1
            print(f"[!] {(result.stderr or '').strip()[:300]}")
        else:
            print(f"    {archive.stat().st_size:,} bytes")

    # --- the part that is deliberately not automated ------------------------
    env = ROOT / ".env"
    print()
    if env.exists():
        print("[!] .env is NOT included in this backup, on purpose.")
        print("    It holds FERNET_KEY, DB_PASSWORD and AGENT_SHARED_SECRET.")
        print("    A restored database without FERNET_KEY cannot be decrypted,")
        print("    so back it up separately, somewhere secrets belong.")
    else:
        problems += 1
        print("[!] No .env found. Without FERNET_KEY nothing here decrypts.")

    print()
    print(f"[+] Backup at {destination}" if not problems
          else f"[!] Backup at {destination} with {problems} problem(s)")
    return 1 if problems else 0


def restore(source: pathlib.Path) -> int:
    # Absolute: `docker -v` reads a relative path as a *named volume*, and
    # reports the drive letter as an invalid character - which looks like a
    # quoting bug and is not one.
    source = source.expanduser().resolve()
    if not source.is_dir():
        print(f"[!] {source} is not a directory")
        return 2

    archives = sorted(source.glob("*.tar.gz"))
    if not archives:
        print(f"[!] No archives in {source}. Nothing to restore.")
        return 2

    prefix = project_name()
    print("[*] Restoring is destructive: it overwrites the current volumes.")
    print("    Stop the stack first (docker compose down), then re-run.")
    print()

    running = run(["docker", "compose", "ps", "-q"], cwd=ROOT).stdout.strip()
    if running:
        print("[!] Containers are still running. Refusing.")
        print("    Restoring underneath a live MySQL corrupts what it is")
        print("    holding in memory, which is a worse state than the one")
        print("    you are restoring from.")
        return 2

    problems = 0
    for archive in archives:
        name = f"{prefix}_{archive.stem.replace('.tar', '')}"
        print(f"[*] {archive.name} -> {name}")
        run(["docker", "volume", "create", name])
        result = run([
            "docker", "run", "--rm",
            "-v", f"{name}:/to",
            "-v", f"{source.as_posix()}:/from:ro",
            "alpine", "sh", "-c",
            f"rm -rf /to/* /to/..?* /to/.[!.]* 2>/dev/null; "
            f"tar xzf /from/{archive.name} -C /to",
        ])
        if result.returncode != 0:
            problems += 1
            print(f"[!] {(result.stderr or '').strip()[:300]}")

    print()
    if problems:
        # This printed "[+] Restored" even on a run where every archive
        # failed. A restore reporting success it did not have is noticed the
        # next time somebody needs the data.
        print(f"[!] {problems} of {len(archives)} archive(s) FAILED to restore.")
        print("    Do not bring the stack up expecting this data to be there.")
        return 1

    print("[+] Restored. Bring the stack up with docker compose up -d")
    print("    The SQL dump beside these archives is the fallback if a volume")
    print("    will not mount - MySQL's on-disk format is version-specific.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--restore", metavar="DIR",
                    help="restore from a backup directory (stack must be down)")
    ap.add_argument("--list", action="store_true", help="list existing backups")
    ap.add_argument("--out", help="write to this directory instead of a dated one")
    args = ap.parse_args()

    if shutil.which("docker") is None:
        print("[!] docker is not on PATH")
        return 2

    if args.list:
        if not BACKUPS.exists():
            print("No backups yet.")
            return 0
        for entry in sorted(BACKUPS.iterdir()):
            if entry.is_dir():
                size = sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())
                print(f"{entry.name}   {size / 1e6:,.1f} MB")
        return 0

    if args.restore:
        return restore(pathlib.Path(args.restore))

    stamp = dt.datetime.now().strftime("%Y-%m-%dT%H%M")
    return backup(pathlib.Path(args.out) if args.out else BACKUPS / stamp)


if __name__ == "__main__":
    sys.exit(main())
