#!/usr/bin/env python3
"""Replay a labelled corpus through the model and score the result.

    python scripts/run_eval.py
    python scripts/run_eval.py --save evals/runs/baseline.json
    python scripts/run_eval.py --compare evals/runs/baseline.json

This is what makes a prompt change reviewable. Before it, the only way to
judge an edit was to read a few insight cards and form an impression, which
cannot distinguish "better" from "different".

Exit codes: 0 clean, 1 a regression against the compared baseline, 2 setup
failure. The regression case is deliberately loud - a change that catches
three new detections and loses three others leaves recall flat, and that
should not read as neutral.

A run where the model answered nothing also exits non-zero. The first live
run scored 10/10 NO_VERDICT because the endpoint was unreachable, printed a
scoreboard of zeroes, and exited 0. An eval that cannot reach the model has
not measured the model, and must not be reportable as a result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv                     # noqa: E402
load_dotenv()

from core.evaluation import (                      # noqa: E402
    NO_VERDICT, Case, compare, summarise,
)
from core.netloc import resolve_url                # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "evals" / "corpus.jsonl"

VALID = {"CRITICAL", "SUSPICIOUS", "NOT_CRITICAL", "INSUFFICIENT_DATA"}


def load_corpus(path: pathlib.Path) -> tuple[list[dict], list[str]]:
    """Return (labelled cases, complaints about the rest)."""
    if not path.exists():
        return [], [f"{path} does not exist. Run build_eval_corpus.py first."]

    cases, problems, unlabelled = [], [], 0
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            problems.append(f"line {n}: not valid JSON ({e})")
            continue
        label = (row.get("expected") or "").strip().upper()
        if not label:
            unlabelled += 1
            continue
        if label not in VALID:
            problems.append(f"line {n} ({row.get('id')}): "
                            f"expected={label!r} is not one of {sorted(VALID)}")
            continue
        row["expected"] = label
        cases.append(row)

    if unlabelled:
        # Reported, not silently skipped: "40 cases" reads very differently
        # when 160 more are sitting there unlabelled.
        problems.append(f"{unlabelled} case(s) have no label and were skipped.")
    return cases, problems



# ---------------------------------------------------------------------------
# Replay cache
# ---------------------------------------------------------------------------
#
# 29 cases at up to 140s each is twenty minutes, and most re-runs change
# nothing the model sees.
#
# Keyed on the model *and the prompt text*, which is what makes it safe:
# `ai.utils`' production cache is keyed on the log alone, so a reply from an
# older prompt would make a rewritten one look identical to it. Keying on the
# prompt means editing it invalidates everything.
#
# What is cached is the raw reply, before `criteria.apply` and the gate, so
# criterion and gating changes are scored fresh - the common case.

CACHE_DIR = ROOT / "evals" / "cache"


def _cache_key(model: str, prompt: str, log_text: str) -> str:
    digest = hashlib.sha256()
    for part in (model, prompt, log_text):
        digest.update(part.encode("utf-8", "replace"))
        digest.update(b"\x00")
    return digest.hexdigest()


def cache_read(key: str):
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


_cache_warned = False


def cache_write(key: str, payload: dict) -> None:
    """Best effort. A cache that cannot be written is not a failed run.

    But it is not nothing either, so it is said once rather than swallowed:
    silently failing to write means every run pays the full twenty minutes
    and the reason is invisible - which is the exact experience the cache was
    added to remove.
    """
    global _cache_warned
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / f"{key}.json").write_text(
            json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
    except OSError as e:
        if not _cache_warned:
            _cache_warned = True
            print(f"  ! replay cache is not writable ({e}); every run will "
                  f"re-query the model")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--agent", default=None,
                    help="agent whose AI config to use; defaults to env settings")
    ap.add_argument("--save", default=None, help="write this run to a JSON file")
    ap.add_argument("--compare", default=None, help="baseline run to compare against")
    ap.add_argument(
        "--no-cache", action="store_true",
        help="ignore the replay cache in both directions. Use when the "
             "question is whether the model still behaves this way, "
             "rather than whether the scoring around it does.")
    ap.add_argument(
        "--refresh", action="store_true",
        help="re-query the model and overwrite the cached replies")
    ap.add_argument("--limit", type=int, default=0, help="stop after N cases")
    ap.add_argument("--endpoint", default=None,
                    help="Ollama base URL (default: OLLAMA_BASE_URL, with "
                         "compose service names mapped to their published port)")
    args = ap.parse_args()

    cases, problems = load_corpus(pathlib.Path(args.corpus))
    for p in problems:
        print(f"  ! {p}")
    if not cases:
        print("\n[!] Nothing labelled to evaluate.")
        return 2

    from ai import criteria
    from ai.gating import describe as describe_gate, surfaces
    from ai.prompts import PROMPTS
    from ai.schemas import TriageVerdict
    from ai.utils import AITransientError, analyze_structured

    if args.limit:
        cases = cases[:args.limit]

    # `.env` points at http://ollama:11434, which resolves on the compose
    # network only. Run from the host, every case failed to connect and the
    # error blamed DNS. See core/netloc.py.
    endpoint = args.endpoint or resolve_url(os.getenv("OLLAMA_BASE_URL", ""))

    print(f"\n[*] Replaying {len(cases)} labelled case(s) through the model...")
    print(f"    endpoint: {endpoint or '(ai.utils default)'}\n")

    results: list[Case] = []
    cache_hits = 0
    for i, row in enumerate(cases, 1):
        log_text = json.dumps(row["event"], indent=2, default=str)
        started = time.monotonic()
        key = _cache_key(os.getenv("OLLAMA_MODEL", "default"),
                         PROMPTS["automation"], log_text)
        cached = None if (args.no_cache or args.refresh) else cache_read(key)
        try:
            if cached is not None:
                cache_hits += 1
                error = cached.get("error")
                verdict = (TriageVerdict.model_validate(cached["verdict"])
                           if cached.get("verdict") else None)
            else:
                verdict, _raw, error = analyze_structured(
                    PROMPTS["automation"], log_text, TriageVerdict,
                    # agent=None: never touch the *production* response cache.
                    # It is keyed on the log alone, so a reply from an older
                    # prompt would make a rewritten one look identical to it.
                    # The harness cache above keys on the prompt too.
                    agent=None,
                    endpoint=endpoint or None,
                )
                if not args.no_cache:
                    cache_write(key, {
                        "verdict": (verdict.model_dump() if verdict else None),
                        "error": error,
                    })
            # The same adjustment production makes, so the score describes
            # what the platform does rather than what the model said.
            if verdict is not None:
                criteria.apply(verdict, log_text)
            actual = verdict.verdict if verdict else NO_VERDICT
            shown = surfaces(verdict)
            sev = verdict.severity if verdict else None
            conf = verdict.confidence if verdict else None
            if error:
                actual = NO_VERDICT
                shown = False
        except AITransientError as e:
            print(f"  !! {row['id']}: model unreachable ({e})")
            actual = NO_VERDICT
            shown = False
            sev = conf = None
        elapsed = time.monotonic() - started

        results.append(Case(
            id=row["id"], expected=row["expected"], actual=actual,
            latency_s=elapsed, note=row.get("note", ""), surfaced=shown,
            severity=sev, confidence=conf, constructed=row.get("constructed"),
        ))
        mark = "ok " if row["expected"] == actual else "MISS"
        print(f"  [{i:>3}/{len(cases)}] {mark} {row['id']}  "
              f"expected={row['expected']:<18} got={actual:<18} {elapsed:.1f}s")

    report = summarise(results)
    print("\n" + "=" * 70)
    print(f"  Cases ................. {report.total}")
    print(f"  No usable verdict ..... {report.no_verdict}"
          f"{'  <-- the model failed to answer these' if report.no_verdict else ''}")
    if report.median_latency is not None:
        print(f"  Median latency ........ {report.median_latency:.1f}s")
    constant = report.constant_verdict
    if constant:
        # Before the metrics, because when this is true they are all
        # descriptions of the same fact and easy to read past.
        print()
        print(f"  !! THE MODEL ANSWERED {constant} TO EVERY CASE.")
        print( "     Its output is a constant function: it carries no")
        print( "     information and cannot be a detection capability,")
        print( "     whatever the figures below say.")

    print()
    er, ep = report.escalation_recall, report.escalation_precision
    print(f"  Escalation recall ..... {f'{er:.1%}' if er is not None else 'n/a'}"
          f"   (of events that should be escalated, how many were)")
    print(f"  Escalation precision .. {f'{ep:.1%}' if ep is not None else 'n/a'}"
          f"   (of escalations, how many deserved it)")

    # The number that describes the product rather than the model. These came
    # apart once already: a prompt rewrite took escalation recall from 0% to
    # 40% while every detection landed just under the confidence the worker
    # requires, so an analyst saw exactly as much as before.
    sr = report.surfaced_recall
    print(f"  Reaches an analyst .... {f'{sr:.1%}' if sr is not None else 'n/a'}"
          f"   (of those, how many production would show)")
    if sr is not None and er is not None and sr < er:
        print(f"     {er:.0%} of attacks were flagged; {sr:.0%} would be seen.")
        print(f"     Gate: {describe_gate()}")

    if cache_hits:
        print()
        print(f"  Replayed from cache ... {cache_hits}/{len(cases)} case(s)")
        if cache_hits == len(cases):
            print("     No model call was made. This scores the code around")
            print("     the model - criteria, the gate, the metrics - and is")
            print("     not evidence the model still answers this way.")
            print("     Use --no-cache for that.")

    alarms = report.surfaced_false_alarms
    if alarms:
        shown, total = alarms
        print(f"  False alarms shown .... {shown}/{total} benign events"
              f"   (what the gate lets through)")
        flagged = sum(1 for c in report.cases
                      if c.expected not in ("CRITICAL", "SUSPICIOUS")
                      and c.actual in ("CRITICAL", "SUSPICIOUS"))
        if flagged > shown:
            print(f"     The model over-escalated {flagged}; the gate stopped"
                  f" {flagged - shown}.")
            print("     Escalation precision above scores the verdict. This"
                  " scores")
            print("     the console, and it is the one that costs attention.")

    built, real, unknown = report.provenance
    if built or unknown:
        print()
        total_pos = built + real + unknown
        print(f"  Positives ............. {built} constructed, {real} real"
              + (f", {unknown} unknown" if unknown else ""))
        if built + unknown == total_pos:
            print( "     Every positive was written by hand from documented")
            print( "     technique behaviour - nobody has run mimikatz here.")
            print( "     These are the loud versions, so read recall as an")
            print( "     upper bound: a miss is real evidence, a hit is weak.")
            print( "     Watching this number fall is meaningful. The number")
            print( "     itself is not a safety claim.")

    res = report.resolution
    if res is not None:
        print()
        print(f"  Resolution ............ {res:.0%} per case")
        print(f"     One case flipping moves recall by {res:.0%}. Two runs of this")
        print("     corpus, same prompt, temperature 0, returned 50% and 60%:")
        print("     CPU inference reduces across threads in a non-deterministic")
        print("     order and a near-tie flips. Treat a difference smaller than")
        print(f"     {2 * res:.0%} as noise, not as a result.")

    anchored = report.confidence_is_anchored
    if anchored is not None:
        print()
        print(f"  !! Every verdict came back at confidence {anchored:.2f}.")
        print( "     The model is not computing a confidence, it is emitting a")
        print( "     constant. Do not tune the gate against it.")
    print()
    print("  Per class:")
    for label, sc in sorted(report.by_class.items()):
        p = f"{sc.precision:.2f}" if sc.precision is not None else " n/a"
        r = f"{sc.recall:.2f}" if sc.recall is not None else " n/a"
        print(f"    {label:<20} precision {p}  recall {r}  support {sc.support}")
    print("=" * 70)

    if report.missed:
        print("\nMissed escalations - these are the expensive errors:")
        for c in report.missed:
            print(f"  {c.id}  expected {c.expected}, model said {c.actual}"
                  + (f"   ({c.note})" if c.note else ""))

    if report.spurious:
        print("\nUnwarranted escalations - the cost of the recall above:")
        for c in report.spurious[:10]:
            print(f"  {c.id}  expected {c.expected}, model said {c.actual}")

    # A run that reached the model for nothing has measured nothing. Saving it
    # would be worse than useless: `--compare` against a baseline of all
    # NO_VERDICT makes any working run look like a huge improvement.
    if report.no_verdict == report.total and report.total:
        print("\n[!] Every case failed to produce a verdict, so this run "
              "measured nothing.")
        print(f"    Endpoint tried: {endpoint or '(ai.utils default)'}")
        print("    Check the model is reachable from here - from the host,")
        print("    Ollama is published on 127.0.0.1:11434, not http://ollama.")
        print("    Not saved, and not comparable.")
        return 2

    if args.save:
        out = pathlib.Path(args.save)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(
            {"cases": [vars(c) for c in results]}, indent=2), encoding="utf-8")
        print(f"\n[+] Run saved to {out}")

    exit_code = 0
    if args.compare:
        base_path = pathlib.Path(args.compare)
        if not base_path.exists():
            print(f"\n[!] Baseline {base_path} not found.")
            return 2
        base_raw = json.loads(base_path.read_text(encoding="utf-8"))
        baseline = summarise([Case(**c) for c in base_raw["cases"]])
        diff = compare(baseline, report)

        print("\n" + "=" * 70)
        print(f"  vs {base_path.name}")
        for k in ("escalation_recall", "escalation_precision"):
            v = diff[k]
            print(f"    {k:<22} {'n/a' if v is None else f'{v:+.1%}'}")
        print(f"    {'no_verdict':<22} {diff['no_verdict']:+d}")
        if diff["newly_caught"]:
            print(f"    newly caught ......... {', '.join(diff['newly_caught'])}")
        if diff["newly_missed"]:
            print(f"    NEWLY MISSED ......... {', '.join(diff['newly_missed'])}")
        print("=" * 70)

        if diff["regression"]:
            print("\nREGRESSION: this change lost detections it previously made.")
            print("Recall alone can hide this - three caught and three lost")
            print("leaves the headline flat.")
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
