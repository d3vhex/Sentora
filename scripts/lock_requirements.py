#!/usr/bin/env python3
"""Regenerate requirements.lock, keeping the preamble that explains it.

    python scripts/lock_requirements.py

Why this is a script and not a command in a comment
---------------------------------------------------
It was a command in a comment, and the comment did not survive being followed.
`pip-compile --no-header` suppresses pip-compile's own banner, and the
explanatory preamble had been added by hand on top of it - so regenerating
wrote a lock with no explanation of what it is, why it exists, or how to
regenerate it. The test that checks the instructions are present is what
noticed.

Anything a person has to remember to re-add after running a tool will
eventually not be re-added. So the preamble lives here, and gets written back
every time.

Resolution happens inside `python:3.10-slim`, not on a developer machine:
dependency resolution is platform-specific and a lock produced on Windows or
macOS describes a build that never happens.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements.lock"

PREAMBLE = """\
# Generated - do not edit by hand.
#
# requirements.txt names what we depend on; this file records the exact
# versions an image is built from. Without it "the dependency set" was
# whatever PyPI served on the day of the build, so two builds of the same
# commit installed different code - and a Trivy result was a statement about
# one particular afternoon rather than about this repository.
#
# Regenerate inside the image Python, not on a developer machine: resolution
# is platform-specific and a lock produced on Windows describes a build that
# never happens.
#
#     python scripts/lock_requirements.py
#
# That runs pip-compile inside python:3.10-slim and restores this preamble
# afterwards. Running pip-compile directly works too, but --no-header strips
# these lines and the next reader is left with a wall of pins.
#
# To take a new version of something, change requirements.txt (add a bound if
# the change is deliberate) and regenerate. Editing a pin here alone means the
# lock no longer describes what requirements.txt resolves to.
"""


def main() -> int:
    if shutil.which("docker") is None:
        print("[!] docker is not on PATH.")
        print("    The lock has to be resolved inside python:3.10-slim; a lock")
        print("    produced on this machine describes a build that never runs.")
        return 2

    print("[*] Resolving inside python:3.10-slim...")
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{ROOT.as_posix()}:/w", "-w", "/w",
         "python:3.10-slim", "sh", "-c",
         "pip install --quiet pip-tools && "
         "pip-compile --quiet --no-header --strip-extras "
         "--output-file requirements.lock requirements.txt"],
        capture_output=True, text=True)

    if result.returncode != 0:
        print("[x] pip-compile failed:")
        print((result.stderr or result.stdout).strip()[:2000])
        return 1

    body = LOCK.read_text(encoding="utf-8")
    # Idempotent: running twice must not stack two preambles.
    if body.lstrip().startswith("# Generated - do not edit by hand."):
        print("[+] Preamble already present.")
    else:
        LOCK.write_text(PREAMBLE + "#\n" + body, encoding="utf-8")
        print("[+] Preamble restored.")

    pins = sum(1 for line in LOCK.read_text(encoding="utf-8").splitlines()
               if "==" in line and not line.startswith("#"))
    print(f"[+] requirements.lock written, {pins} pinned package(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
