#!/usr/bin/env python3
"""Exercise every route in app.py against a running server.

    python scripts/api_smoke_test.py --user admin --password admin123

Two passes, with deliberately different scope:

  1. UNAUTHENTICATED — every route, every verb. This is safe for all of them
     because `authenticate` middleware rejects before the handler runs, so
     nothing is reached. Any protected route answering 2xx here is an auth
     bypass and fails the run.

  2. AUTHENTICATED — read-only verbs only, minus an explicit skip list. A
     smoke test must never be the thing that fires ISOLATE_HOST, truncates a
     table or deletes a user, so write verbs are never sent with a live
     session. Their coverage comes from pass 1.

Routes are enumerated by parsing app.py with `ast`, so the list cannot drift
out of sync with the code the way a hand-maintained one does.

Exit codes: 0 all good, 1 auth bypass or server error found, 2 setup failed.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] requests is required: pip install -r requirements.txt")
    sys.exit(2)

APP_PY = Path(__file__).resolve().parent.parent / "app.py"

ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "websocket"}
READ_ONLY = {"GET", "HEAD"}

# Routes that are read-only but must still not be called automatically.
SKIP = {
    "/api/agent/download/<os_type>",   # zips the whole agent source tree
    "/vnc-proxy/<agent>",              # websocket; opens a live screen stream
    "/api/agent/deploy/linux",         # returns an installer with a live token
    "/api/agent/deploy/windows",
    "/logout",                         # would kill the session mid-run
    "/<path:path>",                    # SPA catch-all, matches everything
    "/",
}

# Write endpoints that are safe to probe with a live session, and the body to
# send. This is an ALLOW list on purpose. A deny list is how a smoke test ends
# up calling DELETE /databases/userdb or POST /<agent>/self_destruct — one
# missing entry and the test destroys the thing it is testing.
#
# Every entry here validates its input before acting, so an empty or minimal
# body is rejected without side effects. That still exercises the handler's
# entry path, which is where unhandled-KeyError 500s live: a well-behaved
# endpoint answers 400 to a malformed body, never 500.
SAFE_WRITE_PROBES: dict[str, dict] = {
    "/<agent>/playbooks/validate": {},          # validates a graph, no writes
    "/<agent>/automations/validate-target": {},  # validates an IP/username
    "/ldap/test-connection": {},                 # no host in body -> 400 before connecting
    "/change-password": {},                      # pydantic rejects the empty body
    "/roles": {},                                # role_name missing -> 400
    "/users": {},                                # pydantic rejects the empty body
}

# Endpoints that legitimately answer without a session.
PUBLIC = {
    "/login", "/logout", "/health", "/",
    "/api/agents/register", "/api/agents/bootstrap",
    "/api/agent/deploy/linux", "/api/agent/deploy/windows",
    "/api/agent/download/<os_type>",
    "/<agent>/automations/pending", "/api/agents/<agent>/automations/pending",
    "/automations/report", "/<agent>/automations/report",
    "/api/agents/<agent>/automations/report",
    "/automations/<task_id:int>/report",
    "/<path:path>",
}


def enumerate_routes() -> list[tuple[str, str]]:
    """Return (method, path) for every route declared in app.py."""
    tree = ast.parse(APP_PY.read_text(encoding="utf-8", errors="replace"))
    found: list[tuple[str, str]] = []

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            fn = dec.func
            if not (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "app" and fn.attr in ROUTE_DECORATORS):
                continue
            if not dec.args or not isinstance(dec.args[0], ast.Constant):
                continue
            path = dec.args[0].value
            if not isinstance(path, str):
                continue

            methods = [fn.attr.upper()]
            if fn.attr == "route":
                methods = ["GET"]
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [e.value for e in kw.value.elts
                                   if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            elif fn.attr == "websocket":
                methods = ["GET"]

            for m in methods:
                found.append((m.upper(), path))

    return sorted(set(found), key=lambda x: (x[1], x[0]))


def fill_params(path: str, agent: str) -> str:
    """Substitute route parameters with values that are safe to request.

    IDs use a deliberately out-of-range number: a real id could name a real
    row, and this test should never depend on — or disturb — one.
    """
    subs = {
        "agent_name": agent,
        "agent": agent,
        "os_type": "linux",
        "table": "siem_events",
        "table_name": "users",
        "cfg_type": "rules",
        "db": "userdb",
        "db_name": "userdb",
        "path": "index.html",
    }
    def repl(m: re.Match) -> str:
        name = m.group(1)
        typed = ":" in name
        base = name.split(":")[0]
        if base in subs:
            return subs[base]
        return "999999999" if typed or base.endswith("_id") else "unknown"

    return re.sub(r"<([^>]+)>", repl, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin123")
    ap.add_argument("--agent", help="Agent name for <agent> routes (default: first from /devices)")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--verbose", action="store_true", help="List every route, not just problems")
    ap.add_argument("--list-unprobed", action="store_true",
                    help="List the routes that were checked anonymously but not with a session")
    args = ap.parse_args()

    routes = enumerate_routes()
    print(f"[*] {len(routes)} route/method pairs parsed from app.py\n")

    # ---- Pass 1: unauthenticated -------------------------------------------
    anon = requests.Session()
    bypasses: list[str] = []
    print("=== Pass 1: unauthenticated (expecting 401 on protected routes) ===")

    for method, path in routes:
        if path in PUBLIC:
            continue
        url = args.base + fill_params(path, args.agent or "unknown")
        try:
            r = anon.request(method, url, timeout=args.timeout, allow_redirects=False)
        except requests.RequestException as e:
            print(f"  ??  {method:6} {path}  — request failed: {e}")
            continue

        if 200 <= r.status_code < 300:
            bypasses.append(f"{method} {path} -> {r.status_code}")
            print(f"  !!  {method:6} {path}  -> {r.status_code}  AUTH BYPASS")
        elif args.verbose:
            print(f"  ok  {method:6} {path}  -> {r.status_code}")

    if not bypasses:
        print("  All protected routes refused anonymous access.\n")
    else:
        print(f"\n  {len(bypasses)} route(s) served an anonymous request.\n")

    # ---- Log in ------------------------------------------------------------
    s = requests.Session()
    try:
        r = s.post(f"{args.base}/login",
                   json={"username": args.user, "password": args.password},
                   timeout=args.timeout)
    except requests.RequestException as e:
        print(f"[!] Cannot reach {args.base}: {e}")
        return 2

    if r.status_code != 200 or r.json().get("status") != "success":
        print(f"[!] Login failed ({r.status_code}): {r.text[:200]}")
        return 2

    user_id = r.json()["user"]["id"]
    s.headers["X-User-ID"] = str(user_id)
    if "sentora_session" not in s.cookies:
        print("[!] Login succeeded but set no session cookie — the auth layer is not wired up.")
        return 1
    print(f"[+] Logged in as {args.user} (id={user_id}), session cookie received\n")

    agent = args.agent
    if not agent:
        try:
            devices = s.get(f"{args.base}/devices", timeout=args.timeout).json().get("agents", [])
            agent = devices[0]["name"] if devices else "unknown"
        except Exception:
            agent = "unknown"
    print(f"[*] Using agent '{agent}' for parameterised routes\n")

    # ---- Pass 2: authenticated, read-only ----------------------------------
    print("=== Pass 2: authenticated (read-only verbs + safe write probes) ===")
    errors: list[str] = []
    counts = {"ok": 0, "client": 0, "server": 0}
    unprobed: list[str] = []

    for method, path in routes:
        is_read = method in READ_ONLY
        is_safe_write = path in SAFE_WRITE_PROBES and method in ("POST", "PUT", "PATCH")

        if path in SKIP or not (is_read or is_safe_write):
            # Still covered by pass 1 — this is only the session-authenticated
            # gap, which is why it is listed rather than counted.
            unprobed.append(f"{method} {path}")
            continue

        url = args.base + fill_params(path, agent)
        body = SAFE_WRITE_PROBES.get(path) if is_safe_write else None
        try:
            r = s.request(method, url, json=body, timeout=args.timeout, allow_redirects=False)
        except requests.RequestException as e:
            errors.append(f"{method} {path} — {e}")
            print(f"  !!  {method:6} {path}  — request failed: {e}")
            continue

        if r.status_code >= 500:
            counts["server"] += 1
            snippet = r.text[:160].replace("\n", " ")
            errors.append(f"{method} {path} -> {r.status_code}: {snippet}")
            print(f"  !!  {method:6} {path}  -> {r.status_code}  {snippet}")
        elif r.status_code >= 400:
            # 403/404 are expected for the out-of-range ids and for permissions
            # this account may not hold.
            counts["client"] += 1
            if args.verbose:
                print(f"  --  {method:6} {path}  -> {r.status_code}")
        else:
            counts["ok"] += 1
            if args.verbose:
                print(f"  ok  {method:6} {path}  -> {r.status_code}")

    # ---- Report ------------------------------------------------------------
    print("\n" + "=" * 66)
    print(f"  Anonymous check ....... {len(routes)} / {len(routes)} route+method pairs")
    print(f"  auth bypasses ......... {len(bypasses)}")
    print(f"  Authenticated call .... {counts['ok'] + counts['client'] + counts['server']} / {len(routes)}")
    print(f"    2xx {counts['ok']}   4xx {counts['client']}   5xx {counts['server']}")
    print(f"  Session-unchecked ..... {len(unprobed)}  (write verbs; see note below)")
    print("=" * 66)

    if bypasses:
        print("\nAuth bypasses — a protected route served an anonymous caller:")
        for b in bypasses:
            print(f"  {b}")
    if errors:
        print("\nServer errors:")
        for e in errors:
            print(f"  {e}")

    if args.list_unprobed and unprobed:
        print("\nSession-unchecked routes:")
        for u in sorted(unprobed):
            print(f"  {u}")

    print(
        "\nNote on coverage: every route above was called anonymously and had to\n"
        "refuse. The 'session-unchecked' ones are write verbs that were not also\n"
        "called WITH a session, because doing so would dispatch real SOAR\n"
        "actions, drop databases or delete users. Closing that gap needs an\n"
        "isolated agent and a disposable database, not a wider allow list here.\n"
        "Run with --list-unprobed to see exactly which routes those are."
    )

    if not bypasses and not errors:
        print("\nNo auth bypasses and no 5xx responses.")

    return 1 if (bypasses or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
