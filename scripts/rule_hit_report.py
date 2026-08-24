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


def load_rules(path: pathlib.Path, scope: str = "endpoint"):
    """Compile the rules the agent would compile, for the same scope.

    Honouring `applies_to` matters: without it this reports on 1575 patterns
    while the agent runs 740, and every hit rate below describes a ruleset
    nobody is using.
    """
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    flags = 0
    for name in cfg.get("flags") or []:
        flags |= getattr(re, str(name).upper(), 0)

    scope = (scope or "endpoint").strip().lower()
    rules, broken, skipped = [], [], []
    for category, spec in (cfg.get("categories") or {}).items():
        severity = (spec or {}).get("severity", "?")
        applies_to = (spec or {}).get("applies_to")
        if applies_to and scope != "all":
            if scope not in {str(s).strip().lower() for s in applies_to}:
                skipped.append(category)
                continue
        for line in ((spec or {}).get("patterns") or "").splitlines():
            pat = line.strip()
            if not pat or pat.startswith("#"):
                continue
            try:
                rules.append((category, severity, pat, re.compile(pat, flags)))
            except re.error as e:
                # An invalid regex is a category that silently never fires.
                broken.append((category, pat, str(e)))
    return rules, broken, skipped


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

    # See core/netloc.py: `db` resolves on the compose network only, and the
    # DNS error it produces on the host does not hint at that.
    from core.netloc import resolve_host
    env_host, env_port = resolve_host(os.getenv("DB_HOST", "127.0.0.1"),
                                      int(os.getenv("DB_PORT", "3306")))
    host = host or env_host
    port = port or env_port

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



def score_against_labels(rules, path: pathlib.Path) -> int:
    """Score the ruleset against a labelled corpus.

    Hit rates say how *often* rules fire. They do not say whether the rules
    catch attacks, which is the question the ruleset exists to answer, and a
    ruleset can have a low hit rate because it is precise or because it is
    aimed at the wrong data.

    Run against evals/corpus_attacks.jsonl this gives the baseline the AI
    layer has to beat. The first run scored recall 30%, precision 60%: the
    rules missed a cleared Security log, shadow-copy deletion, a SYSTEM
    scheduled task and a PsExec service install, while firing on a signed
    management-agent script and the backup account's scheduled SMB logon.
    """
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    labelled = [r for r in rows if (r.get("expected") or "").strip()]
    if not labelled:
        print(f"[!] {path} has no labelled cases to score against.")
        return 1

    tp = fn = fp = tn = 0
    misses, false_alarms = [], []
    for row in labelled:
        text = extract_text(row.get("event", {}).get("message"))
        # A rule "escalates" when it fires at CRITICAL or HIGH; those are the
        # severities that reach an analyst.
        escalated = any(sev in ("CRITICAL", "HIGH")
                        for _c, sev, _p, rx in rules if rx.search(text))
        positive = row["expected"] in ("CRITICAL", "SUSPICIOUS")
        if positive and escalated:
            tp += 1
        elif positive:
            fn += 1
            misses.append(row["id"])
        elif escalated:
            fp += 1
            false_alarms.append(row["id"])
        else:
            tn += 1

    print()
    print(f"  Scored against {len(labelled)} labelled case(s)")
    print()
    recall = tp / (tp + fn) if tp + fn else None
    precision = tp / (tp + fp) if tp + fp else None
    print(f"    recall    {f'{recall:.0%}' if recall is not None else 'n/a':>5}"
          f"   ({tp}/{tp + fn} attacks escalated)")
    print(f"    precision {f'{precision:.0%}' if precision is not None else 'n/a':>5}"
          f"   ({tp}/{tp + fp} escalations deserved)")

    if misses:
        print()
        print("  Missed - these are the expensive errors:")
        for m in misses:
            print(f"    {m}")
    if false_alarms:
        print()
        print("  False alarms on benign activity:")
        for f in false_alarms:
            print(f"    {f}")
    if any(r.get("constructed") for r in labelled):
        print()
        print("  Some cases are CONSTRUCTED, not observed. A miss is real")
        print("  evidence; a hit is weak, because these are the loud version")
        print("  of each technique. Read recall as an upper bound.")
    return 0


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
    ap.add_argument("--score", action="store_true",
                    help="score against a labelled corpus (recall/precision) "
                         "instead of reporting hit rates")
    ap.add_argument("--scope", default=os.getenv("RULES_SCOPE", "endpoint"),
                    help="rule scope to load, matching the agent's RULES_SCOPE "
                         "(endpoint, web, or all)")
    args = ap.parse_args()

    rules, broken, skipped = load_rules(pathlib.Path(args.rules), args.scope)
    print(f"[*] {len(rules)} usable pattern(s) across "
          f"{len({c for c, *_ in rules})} categories  (scope={args.scope})")
    if skipped:
        print(f"    {len(skipped)} category(ies) not in scope and not loaded: "
              f"{', '.join(sorted(skipped))}")
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

    if args.score:
        if not args.corpus:
            print("[!] --score needs --corpus (it reads the labels).")
            return 2
        return score_against_labels(rules, pathlib.Path(args.corpus))

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
