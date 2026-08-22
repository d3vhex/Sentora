#!/usr/bin/env python3
"""Replay a labelled corpus through the model and score the result.

    python scripts/run_eval.py
    python scripts/run_eval.py --save evals/runs/baseline.json
    python scripts/run_eval.py --compare evals/runs/baseline.json

This is what makes a prompt change reviewable. Before it, the only way to
judge an edit was to read a few insight cards and form an impression, which
cannot distinguish "better" from "different".

Exit codes: 0 clean, 1 a regression against the compared baseline, 2 setup
failure. The regression case is deliberately loud — a change that catches
three new detections and loses three others leaves recall flat, and that
should not read as neutral.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv                     # noqa: E402
load_dotenv()

from core.evaluation import (                      # noqa: E402
    NO_VERDICT, Case, compare, summarise,
)

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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--agent", default=None,
                    help="agent whose AI config to use; defaults to env settings")
    ap.add_argument("--save", default=None, help="write this run to a JSON file")
    ap.add_argument("--compare", default=None, help="baseline run to compare against")
    ap.add_argument("--limit", type=int, default=0, help="stop after N cases")
    args = ap.parse_args()

    cases, problems = load_corpus(pathlib.Path(args.corpus))
    for p in problems:
        print(f"  ! {p}")
    if not cases:
        print("\n[!] Nothing labelled to evaluate.")
        return 2

    from ai.schemas import TriageVerdict
    from ai.utils import AITransientError, analyze_structured
    from ai_worker import PROMPTS

    if args.limit:
        cases = cases[:args.limit]

    print(f"\n[*] Replaying {len(cases)} labelled case(s) through the model...\n")

    results: list[Case] = []
    for i, row in enumerate(cases, 1):
        log_text = json.dumps(row["event"], indent=2, default=str)
        started = time.monotonic()
        try:
            verdict, _raw, error = analyze_structured(
                PROMPTS["automation"], log_text, TriageVerdict,
                # agent=None: never read or write the response cache during an
                # eval. A cached answer from a previous prompt would make the
                # new one look identical to it.
                agent=None,
            )
            actual = verdict.verdict if verdict else NO_VERDICT
            if error:
                actual = NO_VERDICT
        except AITransientError as e:
            print(f"  !! {row['id']}: model unreachable ({e})")
            actual = NO_VERDICT
        elapsed = time.monotonic() - started

        results.append(Case(
            id=row["id"], expected=row["expected"], actual=actual,
            latency_s=elapsed, note=row.get("note", ""),
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
    print()
    er, ep = report.escalation_recall, report.escalation_precision
    print(f"  Escalation recall ..... {f'{er:.1%}' if er is not None else 'n/a'}"
          f"   (of events that should be escalated, how many were)")
    print(f"  Escalation precision .. {f'{ep:.1%}' if ep is not None else 'n/a'}"
          f"   (of escalations, how many deserved it)")
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
