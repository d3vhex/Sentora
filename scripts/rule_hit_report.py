#!/usr/bin/env python3
"""Report which detection rules fire, on what, and how selectively.

    python scripts/rule_hit_report.py --agent DESKTOP_ABC --limit 2000
    python scripts/rule_hit_report.py --corpus evals/corpus.jsonl
    python scripts/rule_hit_report.py --agent DESKTOP_ABC --pattern '\\|(?:\\s*|)(\\w+)'

rules.yaml is 2113 lines of mostly web-application attack patterns applied to
operating-system telemetry. Some of them match constantly: a sample of 100
real events had 89 flagged CRITICAL / COMMAND INJECTION by a single regex
that matched the agent's own field separator.

Pruning a ruleset that size by reading it is not realistic, and pruning it by
guesswork removes detections. This measures instead.

What to look at
---------------
**Hit rate.** A rule matching most of the corpus is not detecting anything -
it is describing the log format. Those are the ones to fix first.

**Sole reason.** How often a rule is the *only* thing that flagged an event.
A noisy rule that always fires alongside a specific one costs little; a rule
that is single-handedly escalating thousands of events is the whole problem.

**Zero hits is not evidence of anything.** A rule can be silent because it is
precise or because the attack has not happened. This tool cannot tell those
apart, so it never recommends deleting a quiet rule.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import yaml                                       # noqa: E402
from dotenv import load_dotenv                    # noqa: E402

load_dotenv()

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "Sentora" / "conf" / "rules.yaml"


def load_rules(path: pathlib.Path):
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    flags = 0
    for name in cfg.get("flags") or []:
        flags |= getattr(re, str(name).upper(), 0)

    rules, broken = [], []
    for category, spec in (cfg.get("categories") or {}).items():
        severity = (spec or {}).get("severity", "?")
        for line in ((spec or {}).get("patterns") or "").splitlines():
            pat = line.strip()
            if not pat or pat.startswith("#"):
                continue
            try:
                rules.append((category, severity, pat, re.compile(pat, flags)))
            except re.error as e:
                # An invalid regex is a category that silently never fires.
                broken.append((category, pat, str(e)))
    return rules, broken


def messages_from_corpus(path: pathlib.Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        body = row.get("event", {}).get("message")
        yield extract_text(body)


def messages_from_db(agent: str, table: str, limit: int, host, port):
    import mysql.connector
    from cryptography.fernet import Fernet

    from core.agent_key import KeyNotFound, decrypt_stats, find_agent_key, report_decrypt_stats

    # NOT os.getenv("FERNET_KEY"): that key protects server-side secrets, not
    # agent telemetry. Reading it here decrypted nothing and the script then
    # reported "no events to measure" - which reads as an empty table rather
    # than a wrong key.
    try:
        key = find_agent_key()
    except KeyNotFound as e:
        raise SystemExit(f"[!] {e}")
    fernet = Fernet(key.encode() if isinstance(key, str) else key)

    in_container = pathlib.Path("/.dockerenv").exists()
    env_host = os.getenv("DB_HOST", "127.0.0.1")
    host = host or (env_host if (in_container or env_host != "db") else "127.0.0.1")
    port = port or (int(os.getenv("DB_PORT", "3306")) if in_container else 3307)

    conn = mysql.connector.connect(
        host=host, port=port, user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""), database=f"{agent}_db",
    )
    cur = conn.cursor()
    cur.execute(f"SELECT message FROM {table} ORDER BY id DESC LIMIT %s", (limit,))
    raws = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    bodies, stats = decrypt_stats(raws, fernet)
    report_decrypt_stats(stats)
    return [extract_text(b) for b in bodies]


def extract_text(body):
    """The text the rules are actually run against.

    log_extractor matches against the assembled event line, not the stored
    row, so the report has to look at the same string or its hit rates would
    not describe what the agent does.
    """
    if isinstance(body, str) and body.lstrip().startswith("{"):
        try:
            inner = json.loads(body)
            if isinstance(inner, dict):
                return str(inner.get("message", ""))
        except ValueError:
            pass
    return str(body or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(RULES))
    ap.add_argument("--agent")
    ap.add_argument("--table", default="siem_events")
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--corpus", help="read events from a corpus file instead of the DB")
    ap.add_argument("--host"); ap.add_argument("--port", type=int)
    ap.add_argument("--pattern", help="show sample text matched by one specific pattern")
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    rules, broken = load_rules(pathlib.Path(args.rules))
    print(f"[*] {len(rules)} usable pattern(s) across "
          f"{len({c for c, *_ in rules})} categories")
    if broken:
        # A pattern that will not compile is a category that can never fire,
        # and nothing else reports it.
        print(f"\n[!] {len(broken)} pattern(s) do not compile and can never match:")
        for cat, pat, err in broken[:10]:
            print(f"      {cat}: {pat[:60]}  ({err})")

    if args.corpus:
        texts = list(messages_from_corpus(pathlib.Path(args.corpus)))
        source = args.corpus
    elif args.agent:
        texts = list(messages_from_db(args.agent, args.table, args.limit,
                                      args.host, args.port))
        source = f"{args.agent}.{args.table}"
    else:
        print("[!] Give either --agent or --corpus.")
        return 2

    if not texts:
        print("[!] No events to measure.")
        return 1
    print(f"[*] {len(texts)} event(s) from {source}\n")

    if args.pattern:
        rx = re.compile(args.pattern, re.IGNORECASE | re.DOTALL)
        shown = 0
        print(f"Events matched by {args.pattern!r}:\n")
        for t in texts:
            if rx.search(t):
                shown += 1
                if shown <= 15:
                    print(f"  {' '.join(t.split())[:150]}")
        print(f"\n  {shown}/{len(texts)} matched.")
        return 0

    hits = collections.Counter()
    sole = collections.Counter()
    flagged = 0
    for text in texts:
        matched = [(c, s, p) for c, s, p, rx in rules if rx.search(text)]
        if matched:
            flagged += 1
        for c, s, p in matched:
            hits[(c, s, p)] += 1
        if len(matched) == 1:
            sole[matched[0]] += 1

    print(f"  {flagged}/{len(texts)} event(s) matched at least one rule "
          f"({flagged / len(texts):.0%})\n")
    print(f"  {'hit%':>6} {'sole':>6}  {'severity':<9} category / pattern")
    print("  " + "-" * 88)
    for (cat, sev, pat), n in hits.most_common(args.top):
        rate = n / len(texts)
        mark = "  <-- describes the log format, not an attack" if rate > 0.5 else ""
        print(f"  {rate:>5.0%} {sole[(cat, sev, pat)]:>6}  {sev:<9} "
              f"{cat}: {pat[:52]}{mark}")

    silent = len(rules) - len(hits)
    print(f"\n  {silent} rule(s) matched nothing here. That is not evidence "
          f"either way -\n  a rule can be quiet because it is precise or "
          f"because the attack\n  has not happened. Leave them alone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
