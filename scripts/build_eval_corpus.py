#!/usr/bin/env python3
"""Sample real events into an unlabelled evaluation corpus.

    python scripts/build_eval_corpus.py --agent DESKTOP_ABC --limit 200
    python scripts/build_eval_corpus.py --agent DESKTOP_ABC --below-floor

Writes JSONL to `evals/corpus.jsonl` with `expected` left empty for a human to
fill in. Labelling is the part that cannot be automated: the whole value of
the corpus is that a person decided what the right answer was, independently
of what any model said.

Why real events and not synthetic ones
-------------------------------------
A corpus of invented log lines measures how well the model handles invented
log lines. The failures worth catching are the ones this deployment actually
produces: the truncated Windows event, the service that logs a warning every
minute, the field that arrives empty. Those are not things anybody thinks to
write by hand.

The `--below-floor` mode
------------------------
Samples events the severity gate is currently discarding. This is the only
way to find out what AI_MIN_SEVERITY costs: label a batch of what it drops,
run the eval, and see whether the model would have escalated any of them. Any
CRITICAL in that sample is a detection the floor is losing.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import mysql.connector                                    # noqa: E402
from cryptography.fernet import Fernet, InvalidToken      # noqa: E402
from dotenv import load_dotenv                            # noqa: E402

load_dotenv()

ENC_PREFIX = "enc::"
CORPUS = pathlib.Path(__file__).resolve().parent.parent / "evals" / "corpus.jsonl"

# Mirrors the agent's map. Events are stored encrypted, and an eval corpus of
# ciphertext would measure nothing.
ENCRYPTED = {
    "siem_events": ["message"],
    "events_alert": ["source", "message"],
}


def decrypt_row(row: dict, fields: list, fernet) -> dict:
    out = dict(row)
    for f in fields:
        v = out.get(f)
        if isinstance(v, str) and v.startswith(ENC_PREFIX):
            try:
                out[f] = fernet.decrypt(v[len(ENC_PREFIX):].encode()).decode()
            except InvalidToken:
                out[f] = "<undecryptable>"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--table", default="siem_events",
                    choices=["siem_events", "events_alert"])
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--below-floor", action="store_true",
                    help="sample only what the severity gate is discarding")
    ap.add_argument("--out", default=str(CORPUS))
    # DB_HOST in .env is `db`, the compose service name. That resolves inside
    # the Docker network and nowhere else, so running this from the host needs
    # the published address instead. Defaulted rather than required, because
    # the common case is exactly this one.
    ap.add_argument("--host", default=None,
                    help="MySQL host (default: 127.0.0.1 from the host, "
                         "or DB_HOST when it is not a compose service name)")
    ap.add_argument("--port", type=int, default=None,
                    help="MySQL port (default: 3307, the published port)")
    args = ap.parse_args()

    # NOT os.getenv("FERNET_KEY"): that key protects server-side secrets. The
    # one agent telemetry is encrypted with lives in data/fernet.key and is
    # what /api/agents/bootstrap hands out. Reading the wrong one produced a
    # corpus of "<undecryptable>" strings that still looked like a corpus.
    from core.agent_key import KeyNotFound, find_agent_key
    try:
        key = find_agent_key()
    except KeyNotFound as e:
        print(f"[!] {e}")
        return 2
    fernet = Fernet(key.encode() if isinstance(key, str) else key)

    from core import triage
    floor_idx = triage.SEVERITY_LADDER.index(triage.MIN_SEVERITY) \
        if triage.MIN_SEVERITY in triage.SEVERITY_LADDER else 0

    where = ""
    if args.below_floor:
        below = triage.SEVERITY_LADDER[:floor_idx]
        if not below:
            print(f"[!] AI_MIN_SEVERITY={triage.MIN_SEVERITY} drops nothing; "
                  f"there is no below-floor sample to take.")
            return 1
        placeholders = ", ".join(["%s"] * len(below))
        where = f"WHERE severity IN ({placeholders})"
        params = tuple(below)
    else:
        params = ()

    env_host = os.getenv("DB_HOST", "127.0.0.1")
    # `db` is only resolvable from inside the compose network. Treating it as
    # a hostname here produces "Unknown MySQL server host 'db'", which does
    # not hint at the actual problem.
    in_container = pathlib.Path("/.dockerenv").exists()
    host = args.host or (env_host if (in_container or env_host != "db") else "127.0.0.1")
    port = args.port or (int(os.getenv("DB_PORT", "3306")) if in_container else 3307)

    try:
        conn = mysql.connector.connect(
            host=host, port=port,
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=f"{args.agent}_db",
        )
    except mysql.connector.Error as e:
        print(f"[!] Could not connect to {host}:{port} - {e}")
        print("    From the host, MySQL is published on 127.0.0.1:3307.")
        print("    Override with --host / --port if your compose file differs.")
        return 2

    cur = conn.cursor(dictionary=True)
    # Ordered by id rather than randomly so a re-run of the same command
    # produces the same corpus; an eval set that shifts under you cannot be
    # used to compare two prompts.
    cur.execute(
        f"SELECT * FROM {args.table} {where} ORDER BY id DESC LIMIT %s",
        (*params, args.limit),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    existing_ids = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    existing_ids.add(json.loads(line)["id"])
                except Exception:
                    pass

    written = 0
    with out_path.open("a", encoding="utf-8") as fh:
        for row in rows:
            case_id = f"{args.agent}:{args.table}:{row['id']}"
            if case_id in existing_ids:
                continue    # appending must not duplicate work already labelled
            event = decrypt_row(row, ENCRYPTED.get(args.table, []), fernet)
            event.pop("sent", None)
            event.pop("dup_fp", None)
            fh.write(json.dumps({
                "id": case_id,
                "table": args.table,
                "event": event,
                # Left blank on purpose. A label copied from the model is not
                # a label; it is the model grading its own homework.
                "expected": "",
                "note": "",
                "recorded_severity": event.get("severity"),
                "below_floor": bool(args.below_floor),
            }, ensure_ascii=False, default=str) + "\n")
            written += 1

    print(f"[+] {written} new case(s) appended to {out_path}")
    print(f"    {len(existing_ids)} already present and left untouched.")
    if written:
        print()
        print("Next: open the file and set \"expected\" on each case to one of")
        print("  CRITICAL | SUSPICIOUS | NOT_CRITICAL | INSUFFICIENT_DATA")
        print("Label what YOU think the right answer is, without looking at")
        print("what the model said. Then: python scripts/run_eval.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
