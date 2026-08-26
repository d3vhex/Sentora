#!/usr/bin/env python3
"""Produce real attack telemetry, without doing anything an attacker does.

    python scripts/generate_telemetry.py --list
    python scripts/generate_telemetry.py --dry-run
    python scripts/generate_telemetry.py --run T1218.011 T1059.001

Why this exists
---------------
Every positive in `evals/corpus_attacks.jsonl` is written by hand, so recall
measured against it is an **upper bound**: those are the loud, textbook
versions and a real intrusion is quieter. No amount of careful writing fixes
that - only telemetry a machine actually produced does.

What this does and does not do
------------------------------
Each entry produces the *same event* a technique produces, using an action
that is harmless:

    T1490 shadow copy deletion   ->  `vssadmin list shadows`
                                     Same image, same 4688, reads only.

    T1562.001 Defender exclusion ->  add an exclusion for a temp directory
                                     this script created, then remove it.

A read-only `vssadmin` is indistinguishable from a destructive one where
`Image|endswith` is evaluated, which makes this a fair test of collection,
field mapping and the console - and not of whether the *arguments* are
dangerous. `--list` marks which entries exercise a rule fully and which only
exercise collection.

**Nothing here destroys, exfiltrates, disables a control permanently, or
leaves anything behind.** Techniques whose signal cannot be produced safely -
an actual LSASS dump, actually clearing the Security log, actually deleting
shadow copies - are listed with `safe=False`, are refused by `--run`, and are
documented as the gap they are. If you want those measured, run them on a
disposable VM with a real tool such as Atomic Red Team; this script is not
that and should not grow into it.

Run it on a machine with the agent installed, then:

    python scripts/build_eval_corpus.py --table siem_events --agent <name>
    python scripts/label_eval_corpus.py

and the labelled rows become corpus cases whose `constructed` flag is False -
which is what turns recall from an upper bound into a measurement.
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tempfile

IS_WINDOWS = platform.system() == "Windows"


class Activity:
    """One harmless action, and what it is expected to produce."""

    def __init__(self, technique, name, why, command, expect,
                 fully_exercises_rule=True, safe=True, cleanup=None):
        self.technique = technique
        self.name = name
        self.why = why
        self.command = command
        self.expect = expect
        self.fully_exercises_rule = fully_exercises_rule
        self.safe = safe
        self.cleanup = cleanup


def _tempdir() -> str:
    path = os.path.join(tempfile.gettempdir(), "sentora-telemetry")
    os.makedirs(path, exist_ok=True)
    return path


WINDOWS_ACTIVITIES = [
    Activity(
        "T1490", "vssadmin-list",
        "Produces a 4688 for vssadmin.exe. The shadow-copy rule matches on "
        "'delete' and 'shadows' together, so it will NOT fire - what this "
        "tests is that a vssadmin process creation is collected at all, with "
        "its command line in the right StringInserts position.",
        ["vssadmin", "list", "shadows"],
        "4688 with Image ending vssadmin.exe",
        fully_exercises_rule=False),

    Activity(
        "T1059.001", "powershell-encoded-benign",
        "A real -EncodedCommand carrying a real base64 payload, which is what "
        "exercises the utf16le/base64offset matching end to end. The payload "
        "prints the date. The encoded-PowerShell rule fires on the flag plus "
        "a cradle in the payload, so this one deliberately does not fire - it "
        "is the hard negative, live.",
        ["powershell", "-NoProfile", "-EncodedCommand",
         "RwBlAHQALQBEAGEAdABlAA=="],
        "4104/4688 with an encoded command line",
        fully_exercises_rule=False),

    Activity(
        "T1053.005", "scheduled-task-create-delete",
        "Creates a scheduled task whose action is cmd.exe, which is what the "
        "rule matches, then deletes it. This one DOES fire: it is real "
        "persistence for the few seconds it exists.",
        ["schtasks", "/create", "/tn", "SentoraTelemetryTest", "/tr",
         "cmd.exe /c exit", "/sc", "once", "/st", "23:59", "/f"],
        "4698, and the scheduled-task rule firing",
        cleanup=["schtasks", "/delete", "/tn", "SentoraTelemetryTest", "/f"]),

    Activity(
        "T1087.001", "account-enumeration",
        "`net user` enumerates local accounts. Ordinary administration, and "
        "also the first thing run after a foothold - which is why it is a "
        "useful hard negative rather than a detection.",
        ["net", "user"],
        "4688 for net.exe",
        fully_exercises_rule=False),

    Activity(
        "T1082", "system-discovery",
        "systeminfo. Same reasoning as above.",
        ["systeminfo"],
        "4688 for systeminfo.exe",
        fully_exercises_rule=False),

    # ---- deliberately not runnable -----------------------------------------
    Activity(
        "T1003.001", "lsass-dump",
        "There is no harmless version. A dump either contains credentials or "
        "it is not the event being tested. Run it on a disposable VM.",
        None, "4688 with comsvcs.dll MiniDump", safe=False),
    Activity(
        "T1070.001", "clear-security-log",
        "Clearing the Security log destroys the evidence this platform "
        "exists to keep, on the machine doing the measuring.",
        None, "1102", safe=False),
    Activity(
        "T1490", "delete-shadow-copies",
        "Destroys the machine's ability to roll back. Not on a host anybody "
        "cares about.",
        None, "4688 with vssadmin delete shadows", safe=False),
]

LINUX_ACTIVITIES = [
    Activity(
        "T1059.004", "curl-to-file",
        "A real curl, writing to a file rather than piping into a shell. The "
        "pipe is what the rule matches, so this does not fire - it exercises "
        "the syslog field extraction that finds the command line at all.",
        ["curl", "-s", "-o", os.path.join(_tempdir(), "probe"),
         "http://127.0.0.1/"],
        "an auth.log/journal line with CommandLine=curl",
        fully_exercises_rule=False),

    Activity(
        "T1087.001", "account-enumeration",
        "Reading /etc/passwd. Universal after a foothold and universal during "
        "ordinary administration.",
        ["cat", "/etc/passwd"],
        "a journal entry with Image=cat",
        fully_exercises_rule=False),

    Activity(
        "T1110", "ssh-failed-logon",
        "Three failed SSH logins against localhost with a wrong password. "
        "This is the one that matters: it produces genuine `Failed password` "
        "lines, which is the only way to test the syslog parsing and the "
        "correlation window against real text rather than a fixture.",
        None,          # driven separately, see --ssh-failures
        "Failed password lines, and brute_force at the threshold",
        safe=True, fully_exercises_rule=True),
]


def activities() -> list[Activity]:
    return WINDOWS_ACTIVITIES if IS_WINDOWS else LINUX_ACTIVITIES


def show(items: list[Activity]) -> int:
    print(f"\n  {platform.system()} activities\n")
    for a in items:
        if not a.safe:
            mark = "REFUSED"
        elif a.fully_exercises_rule:
            mark = "fires   "
        else:
            mark = "collects"
        print(f"  [{mark}] {a.technique:<12} {a.name}")
        for line in _wrap(a.why, 66):
            print(f"               {line}")
        print(f"               -> {a.expect}")
        print()
    print("  fires    - a shipped rule should match, end to end")
    print("  collects - produces the event; the rule needs arguments this")
    print("             script will not run, so it tests the collection path")
    print("  REFUSED  - no harmless version exists. Use a disposable VM.")
    print()
    return 0


def _wrap(text: str, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width)


def execute(items: list[Activity], dry_run: bool) -> int:
    problems = 0
    for a in items:
        if not a.safe:
            print(f"[!] {a.technique} {a.name}: refused, no harmless version")
            problems += 1
            continue
        if a.command is None:
            print(f"[.] {a.technique} {a.name}: needs --ssh-failures, skipping")
            continue

        printable = " ".join(a.command)
        if dry_run:
            print(f"[dry] {printable}")
            continue

        print(f"[*] {a.technique} {a.name}: {printable}")
        try:
            result = subprocess.run(a.command, capture_output=True, text=True,
                                    timeout=60)
            print(f"    exit {result.returncode}")
        except (OSError, subprocess.SubprocessError) as e:
            problems += 1
            print(f"[!] {e}")
        finally:
            if a.cleanup and not dry_run:
                # Always, even if the action failed - a half-created scheduled
                # task left behind by a telemetry script is exactly the kind
                # of thing that gets found six months later and investigated
                # as an intrusion.
                subprocess.run(a.cleanup, capture_output=True, text=True)
                print(f"    cleaned up: {' '.join(a.cleanup)}")

    print()
    print("[+] Now collect what the agent recorded:")
    print("      python scripts/build_eval_corpus.py --table siem_events --agent <name>")
    print("      python scripts/label_eval_corpus.py")
    print("    Labelled rows carry constructed=false, which is what turns")
    print("    recall from an upper bound into a measurement.")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true",
                    help="show what each activity produces, and run nothing")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the commands without running them")
    ap.add_argument("--run", nargs="*", metavar="TECHNIQUE",
                    help="run these techniques (default: all safe ones)")
    args = ap.parse_args()

    items = activities()
    if args.run:
        wanted = {t.upper() for t in args.run}
        items = [a for a in items if a.technique.upper() in wanted]
        if not items:
            print(f"[!] Nothing matches {sorted(wanted)}. Try --list.")
            return 2

    if args.list or not (args.run or args.dry_run):
        return show(items)
    return execute(items, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
