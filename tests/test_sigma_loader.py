r"""Loading Sigma rules, and giving events the field names those rules address.

These two fail together, which is why they live together. Sigma rules match on
`CommandLine` and `Image`; the Windows event log supplies `StringInserts`, a
positional array whose meaning depends on the event ID. A rule that loads
cleanly and never matches because the names differ looks, from the console,
exactly like a rule nobody wrote.
"""
from __future__ import annotations

import pytest

from core import sigma, sigma_loader

# A real 4688, in the shape the event log delivers: positions, not names.
PROCESS_CREATION_4688 = [
    "S-1-5-21-1-2-3", "svc_backup", "CORP", "0x3e7", "0x1a4",
    r"C:\Windows\System32\rundll32.exe", "%%1936", "0x2b0",
    r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 lsass.dmp full",
    "S-1-0-0", "-", "-", "0x0", r"C:\Windows\System32\cmd.exe",
]

LSASS_RULE = r"""
title: LSASS dump via comsvcs
id: 11111111-1111-1111-1111-111111111111
level: critical
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection
tags: [attack.credential_access, attack.t1003.001]
"""


# --------------------------------------------------------------------------
# Field mapping
# --------------------------------------------------------------------------

def test_positional_inserts_become_named_fields():
    fields = sigma_loader.windows_event_fields(4688, PROCESS_CREATION_4688)
    assert fields["CommandLine"].startswith("rundll32.exe")
    assert fields["SubjectUserName"] == "svc_backup"
    assert fields["EventID"] == "4688"


def test_sigma_names_are_aliased_to_the_windows_ones():
    """Sigma calls it `Image`; the 4688 schema calls it `NewProcessName`. A
    rule written either way has to match, so both names are present."""
    fields = sigma_loader.windows_event_fields(4688, PROCESS_CREATION_4688)
    assert fields["Image"] == fields["NewProcessName"]
    assert fields["ParentImage"] == fields["ParentProcessName"]


def test_a_rule_matches_a_real_event_end_to_end():
    """The whole chain: positional event, named fields, community-shaped
    rule, technique out the other end."""
    fields = sigma_loader.windows_event_fields(
        4688, PROCESS_CREATION_4688, channel="Security",
        provider="Microsoft-Windows-Security-Auditing")
    rule = sigma.parse(LSASS_RULE)
    assert rule.matches(fields)
    assert rule.techniques == ["T1003.001"]


def test_the_benign_neighbour_does_not_match():
    """EID 4672 for SYSTEM - the event that fooled the model into calling a
    privilege list credential dumping."""
    fields = sigma_loader.windows_event_fields(
        4672, ["S-1-5-18", "SYSTEM", "NT AUTHORITY", "0x3e7",
               "SeDebugPrivilege SeBackupPrivilege"])
    assert not sigma.parse(LSASS_RULE).matches(fields)
    assert fields["PrivilegeList"] == "SeDebugPrivilege SeBackupPrivilege"


def test_an_unmapped_event_is_still_addressable():
    """Not dropped: the inserts stay reachable by position and the assembled
    text under `Message`, so a rule matching on Message|contains still works.
    Weaker than a field match, and better than nothing."""
    fields = sigma_loader.windows_event_fields(31337, ["alpha", "beta"])
    assert fields["Insert0"] == "alpha"
    assert "alpha" in fields["Message"]


def test_unmapped_event_ids_are_reported_not_hidden():
    """The size of the gap, rather than a reassuring silence. Rules that match
    on named fields cannot fire for these."""
    sigma_loader._unmapped.clear()
    for _ in range(3):
        sigma_loader.windows_event_fields(31337, ["x"])
    sigma_loader.windows_event_fields(4688, PROCESS_CREATION_4688)
    assert sigma_loader.unmapped_event_ids() == {31337: 3}


def test_a_short_insert_list_does_not_invent_fields():
    """Windows versions add fields; a truncated list must leave the later
    names absent rather than shifting values into the wrong ones."""
    fields = sigma_loader.windows_event_fields(4688, ["sid", "user"])
    assert fields["SubjectUserName"] == "user"
    assert "CommandLine" not in fields


# --------------------------------------------------------------------------
# Loading a directory
# --------------------------------------------------------------------------

def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_rules_load_from_a_directory(tmp_path):
    _write(tmp_path, "lsass.yml", LSASS_RULE)
    result = sigma_loader.load_dir(tmp_path)
    assert len(result.rules) == 1
    assert result.techniques == {"T1003.001"}


def test_a_bad_rule_does_not_stop_the_others(tmp_path):
    _write(tmp_path, "good.yml", LSASS_RULE)
    _write(tmp_path, "bad.yml", "title: t\ndetection:\n  selection:\n    F|nope: 'x'\n  condition: selection\n")
    result = sigma_loader.load_dir(tmp_path)
    assert len(result.rules) == 1
    assert len(result.rejected) == 1


def test_a_rejected_rule_says_why():
    """`rejected` is what tells an operator the rule they installed is not
    running. A silent skip means they believe they have a detection."""
    import pathlib
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "bad.yml").write_text(
            "title: t\ndetection:\n  selection:\n    F|nope: 'x'\n  condition: selection\n",
            encoding="utf-8")
        result = sigma_loader.load_dir(d)
    path, reason = result.rejected[0]
    assert "bad.yml" in path
    assert "nope" in reason


def test_a_missing_directory_is_not_an_error(tmp_path):
    """No rules installed is a valid state, not a crash at boot."""
    result = sigma_loader.load_dir(tmp_path / "does-not-exist")
    assert result.rules == [] and result.rejected == []


def test_the_summary_reports_coverage_and_rejections(tmp_path):
    _write(tmp_path, "good.yml", LSASS_RULE)
    _write(tmp_path, "bad.yml", "not: a rule\n")
    summary = sigma_loader.load_dir(tmp_path).summary()
    assert "1 Sigma rule" in summary
    assert "1 ATT&CK technique" in summary
    assert "1 rejected" in summary


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def test_every_matching_rule_is_returned_not_the_first(tmp_path):
    """conf/rules.yaml stops at the first regex that matches, which is how one
    broad pattern labelled every event COMMAND INJECTION and hid everything
    behind it. Techniques accumulate across rules, so stopping early loses the
    coverage that makes this worth having."""
    _write(tmp_path, "a.yml", LSASS_RULE)
    _write(tmp_path, "b.yml", LSASS_RULE.replace(
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        .replace("attack.t1003.001", "attack.t1055"))
    rules = sigma_loader.load_dir(tmp_path).rules
    fields = sigma_loader.windows_event_fields(4688, PROCESS_CREATION_4688)
    matched = sigma_loader.match_all(rules, fields)
    assert len(matched) == 2
    assert {t for r in matched for t in r.techniques} == {"T1003.001", "T1055"}


def test_no_match_returns_nothing(tmp_path):
    _write(tmp_path, "a.yml", LSASS_RULE)
    rules = sigma_loader.load_dir(tmp_path).rules
    fields = sigma_loader.windows_event_fields(4672, ["S-1-5-18", "SYSTEM"])
    assert sigma_loader.match_all(rules, fields) == []
