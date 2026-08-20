#!/usr/bin/env python3
"""Rotate the MySQL root password and update .env to match.

    python scripts/rotate_db_password.py --yes

Why this is not part of init_secrets.py: MySQL fixes the root password when
the data volume is first initialised. `MYSQL_ROOT_PASSWORD` is read once, at
that moment, and never again. Editing DB_PASSWORD in .env afterwards does not
change the account — it only stops the app from being able to connect. The
account has to be altered first, and only then does the env value get updated
to match.

Order of operations, and why:

  1. connect with the current password        (proves we can roll back)
  2. ALTER USER for every root host entry
  3. reconnect from scratch with the new one  (proves the change took)
  4. only then write .env

If step 3 or 4 fails after the ALTER has landed, the new password is printed
so the deployment is recoverable by hand. That is the one case where printing
a secret to the terminal beats losing access to the database.

Connects to the *published* port, not DB_HOST: `db` only resolves inside the
compose network, while the host sees 127.0.0.1:3307.
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path

try:
    import mysql.connector
except ImportError:
    print("[!] mysql-connector-python is required: pip install -r requirements.txt")
    sys.exit(1)

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def write_env_value(path: Path, key: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")

    for i, line in enumerate(lines):
        if pattern.match(line):
            ending = "\n" if line.endswith("\n") else ""
            lines[i] = f"{key}={value}{ending}"
            break
    else:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(f"{key}={value}\n")

    path.write_text("".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1",
                        help="MySQL host as seen from this machine (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3307,
                        help="Published MySQL port (default: 3307)")
    parser.add_argument("--yes", action="store_true",
                        help="Required. Confirms you intend to alter the live account.")
    args = parser.parse_args()

    if not args.yes:
        print(__doc__)
        print("[!] Refusing to run without --yes. This alters the live database account.")
        return 1

    if not ENV_PATH.exists():
        print(f"[!] {ENV_PATH} not found.")
        return 1

    env = read_env(ENV_PATH)
    user = env.get("DB_USER", "root")
    current = env.get("DB_PASSWORD", "")
    if not current or current.startswith("<"):
        print("[!] DB_PASSWORD is not set in .env — nothing to rotate from.")
        return 1

    # No ':' '@' '/' — the value ends up in connection strings elsewhere.
    new_password = secrets.token_urlsafe(24)

    print(f"[*] Connecting to {args.host}:{args.port} as {user}...")
    try:
        conn = mysql.connector.connect(
            host=args.host, port=args.port, user=user, password=current
        )
    except mysql.connector.Error as e:
        print(f"[!] Could not connect with the current DB_PASSWORD: {e}")
        print("    Is the stack up, and does .env hold the password actually in use?")
        return 1

    altered = False
    try:
        cur = conn.cursor()
        cur.execute("SELECT host FROM mysql.user WHERE user = %s", (user,))
        hosts = [row[0] for row in cur.fetchall()]
        if not hosts:
            print(f"[!] No account rows found for user '{user}'.")
            return 1

        print(f"[*] Altering {user}@{{{', '.join(hosts)}}}...")
        for host in hosts:
            cur.execute(f"ALTER USER '{user}'@'{host}' IDENTIFIED BY %s", (new_password,))
        cur.execute("FLUSH PRIVILEGES")
        altered = True
        cur.close()
        conn.close()

        # A fresh connection — the existing one stays authenticated after the
        # ALTER, so reusing it would prove nothing.
        print("[*] Verifying with a new connection...")
        verify = mysql.connector.connect(
            host=args.host, port=args.port, user=user, password=new_password
        )
        verify.close()

        write_env_value(ENV_PATH, "DB_PASSWORD", new_password)
        print("[+] Rotated. DB_PASSWORD updated in .env.")

    except Exception as e:
        if altered:
            print("\n" + "=" * 68)
            print("[!] The password WAS changed, but the step after it failed:")
            print(f"    {e}")
            print("\n    Save this now — .env may not have been updated:")
            print(f"      DB_PASSWORD={new_password}")
            print("=" * 68)
        else:
            print(f"[!] Failed before altering anything, password unchanged: {e}")
        return 1

    print(
        "\n    The db container still holds the old MYSQL_ROOT_PASSWORD in its\n"
        "    environment, so its healthcheck will report unhealthy until it is\n"
        "    recreated. Do that now:\n"
        "\n      docker compose up -d\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
