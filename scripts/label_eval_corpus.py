#!/usr/bin/env python3
"""Label the evaluation corpus one case at a time.

    python scripts/label_eval_corpus.py

Editing 100 raw JSONL lines by hand is miserable enough that the corpus
would not get labelled, and an unlabelled corpus measures nothing. This shows
one event at a time and takes a single keypress.

Resumable: already-labelled cases are skipped, and the file is rewritten
after every answer, so stopping halfway loses nothing.

It deliberately does not show what the model said about a case. A label
influenced by the model's answer is not an independent judgement, and the
whole point of the corpus is to have one.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "evals" / "corpus.jsonl"

CHOICES = {
    "c": "CRITICAL",
    "s": "SUSPICIOUS",
    "n": "NOT_CRITICAL",
    "i": "INSUFFICIENT_DATA",
}

HELP = """
  [c] CRITICAL          a real threat: someone should act now
  [s] SUSPICIOUS        worth an analyst's eyes, not obviously an incident
  [n] NOT_CRITICAL      routine noise
  [i] INSUFFICIENT_DATA the log genuinely does not say enough to judge
  [ENTER] skip this one   [b] back   [q] save and quit
"""


def readable(case: dict) -> str:
    """The event as a person would want to read it.

    The stored row nests the real event inside `message` as JSON, so showing
    the raw row is mostly noise. Falls back to the raw text when it is not
    the expected shape - guessing at a structure that is not there would hide
    the parts of the event that matter.
    """
    event = case.get("event", {})
    body = event.get("message")
    inner = None
    if isinstance(body, str) and body.lstrip().startswith("{"):
        try:
            inner = json.loads(body)
        except ValueError:
            inner = None

    if not isinstance(inner, dict):
        return f"  (raw) {str(body)[:900]}"

    lines = []
    for key in ("source", "severity", "event_type", "user", "ip_address"):
        val = inner.get(key)
        if val not in (None, "", "None"):
            lines.append(f"  {key:<12} {val}")
    msg = str(inner.get("message", "")).strip()
    if msg:
        lines.append("")
        lines.append("  " + msg[:900].replace("\n", "\n  "))
    return "\n".join(lines) if lines else f"  (empty event) {str(body)[:400]}"


def save(path: pathlib.Path, rows: list[dict]) -> None:
    """Rewrite atomically. A crash mid-write would otherwise destroy every
    label collected so far."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in rows) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--relabel", action="store_true",
                    help="revisit cases that already carry a label")
    args = ap.parse_args()

    path = pathlib.Path(args.corpus)
    if not path.exists():
        print(f"[!] {path} does not exist. Run build_eval_corpus.py first.")
        return 2

    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    todo = [i for i, r in enumerate(rows)
            if args.relabel or not (r.get("expected") or "").strip()]

    if not todo:
        done = sum(1 for r in rows if (r.get("expected") or "").strip())
        print(f"[+] All {done} case(s) already labelled. "
              f"Use --relabel to revisit them.")
        return 0

    print(f"\n{len(todo)} case(s) to label, {len(rows) - len(todo)} already done.")
    print(HELP)

    pos = 0
    while 0 <= pos < len(todo):
        idx = todo[pos]
        case = rows[idx]
        print("=" * 72)
        print(f"  [{pos + 1}/{len(todo)}]  {case['id']}")
        print("=" * 72)
        print(readable(case))
        current = (case.get("expected") or "").strip()
        if current:
            print(f"\n  currently: {current}")

        try:
            answer = input("\n  c/s/n/i, ENTER skip, b back, q quit > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if answer == "q":
            break
        if answer == "b":
            pos = max(0, pos - 1)
            continue
        if answer == "":
            pos += 1
            continue
        if answer not in CHOICES:
            print(f"  ? '{answer}' is not one of c/s/n/i. Try again.")
            continue

        case["expected"] = CHOICES[answer]
        save(path, rows)          # after every answer, so quitting loses nothing
        pos += 1

    labelled = sum(1 for r in rows if (r.get("expected") or "").strip())
    save(path, rows)
    print(f"\n[+] {labelled}/{len(rows)} case(s) labelled. Saved to {path}")
    if labelled:
        print("\nNext:  python scripts/run_eval.py --save evals/runs/baseline.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
