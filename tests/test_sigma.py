"""Sigma rules compiled to a predicate.

Supporting the format detection engineers already write in means the community
rules become available and nobody has to trust a rule list that exists only in
this repository. `conf/rules.yaml` is 1575 regexes with no provenance; a Sigma
rule has an author, an id and a history.

The property that matters most here is the refusal. A detection rule that
silently never fires is worse than one that fails to load: the second is
visible on the next start, the first is discovered after an intrusion. Most of
what follows checks that an unsupported construct raises rather than compiling
to something that happens to be false.
"""
from __future__ import annotations

import pytest

from core import sigma

# A rule in the shape the community ruleset actually uses.
LSASS_DUMP = """
title: LSASS Memory Dump via comsvcs.dll
id: a1b2c3d4-0000-0000-0000-000000000001
status: stable
description: Detects credential dumping using the MiniDump export of comsvcs.dll
author: test
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains|all:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003.001
"""


def rule(text=LSASS_DUMP):
    return sigma.parse(text)


# --------------------------------------------------------------------------
# It matches what it should
# --------------------------------------------------------------------------

def test_a_matching_event_matches():
    event = {
        "Image": r"C:\Windows\System32\rundll32.exe",
        "CommandLine": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 lsass.dmp full",
    }
    assert rule().matches(event)


def test_a_partial_match_does_not():
    """`|all` means every value, not any of them - the whole point of that
    modifier. rundll32 loading comsvcs.dll without MiniDump is ordinary."""
    event = {
        "Image": r"C:\Windows\System32\rundll32.exe",
        "CommandLine": r"rundll32.exe C:\Windows\System32\comsvcs.dll, LaunchTask",
    }
    assert not rule().matches(event)


def test_a_missing_field_is_not_a_match():
    """A rule asking about a field the event does not have must not fire.
    Treating absence as a match makes every rule fire on every event from a
    producer that names its fields differently."""
    assert not rule().matches({"CommandLine": "comsvcs.dll MiniDump"})


def test_field_names_are_matched_case_and_underscore_insensitively():
    """Sigma writes `CommandLine`; producers write `commandline` or
    `command_line`. A rule that silently matches nothing because of
    capitalisation is exactly the failure this module exists to avoid."""
    event = {
        "image": r"c:\windows\system32\rundll32.exe",
        "command_line": "comsvcs.dll MiniDump 704 out.dmp",
    }
    assert rule().matches(event)


# --------------------------------------------------------------------------
# Modifiers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("modifier,value,event_value,expected", [
    ("contains",   "shadow",   "vssadmin delete shadows", True),
    ("contains",   "shadow",   "vssadmin list",           False),
    ("startswith", "powershell", "powershell.exe -enc x", True),
    ("startswith", "powershell", "cmd /c powershell",     False),
    ("endswith",   ".exe",     r"C:\x\y.exe",             True),
    ("endswith",   ".exe",     r"C:\x\y.dll",             False),
    ("re",         r"vss\w+",  "vssadmin",                True),
    ("re",         r"vss\d+",  "vssadmin",                False),
])
def test_value_modifiers(modifier, value, event_value, expected):
    text = f"""
title: t
logsource: {{product: windows}}
detection:
    selection:
        Field|{modifier}: '{value}'
    condition: selection
"""
    assert sigma.parse(text).matches({"Field": event_value}) is expected


def test_a_bare_value_is_an_exact_match_not_a_substring():
    """`CommandLine: whoami` must not fire on `whoami-not-really`."""
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        Field: 'whoami'
    condition: selection
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"Field": "whoami"})
    assert not compiled.matches({"Field": "whoami.exe extra"})


def test_a_wildcard_in_a_bare_value_still_globs():
    # Raw string: YAML single quotes do not process escapes, so the rule text
    # has to contain the single backslash a real Sigma rule writes.
    text = r"""
title: t
logsource: {product: windows}
detection:
    selection:
        Field: '*\temp\*'
    condition: selection
"""
    assert sigma.parse(text).matches({"Field": r"C:\Windows\Temp\x.exe"})


def test_a_list_of_values_is_or():
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        Field:
            - 'alpha'
            - 'beta'
    condition: selection
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"Field": "alpha"})
    assert compiled.matches({"Field": "beta"})
    assert not compiled.matches({"Field": "gamma"})


def test_windash_covers_the_other_switch_characters():
    """`-enc`, `/enc` and an en dash all work in a Windows shell, and an
    attacker uses whichever the parser accepts."""
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        Field|windash|contains: '-enc'
    condition: selection
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"Field": "powershell -enc SQBFAFgA"})
    assert compiled.matches({"Field": "powershell /enc SQBFAFgA"})


def test_cidr_matches_by_network_not_by_string():
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        SourceIp|cidr: '10.0.0.0/8'
    condition: selection
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"SourceIp": "10.20.30.41"})
    assert not compiled.matches({"SourceIp": "192.168.1.1"})
    assert not compiled.matches({"SourceIp": "not-an-ip"})


# --------------------------------------------------------------------------
# Conditions
# --------------------------------------------------------------------------

FILTERED = r"""
title: t
logsource: {product: windows}
detection:
    selection:
        Image|endswith: '\vssadmin.exe'
    filter:
        ParentImage|contains: 'BackupAgent'
    condition: selection and not filter
"""


def test_and_not_excludes():
    compiled = sigma.parse(FILTERED)
    assert compiled.matches({"Image": r"C:\x\vssadmin.exe", "ParentImage": "cmd.exe"})
    assert not compiled.matches({"Image": r"C:\x\vssadmin.exe",
                                 "ParentImage": r"C:\BackupAgent\svc.exe"})


def test_one_of_expands_to_or():
    text = """
title: t
logsource: {product: windows}
detection:
    selection_a:
        Field: 'a'
    selection_b:
        Field: 'b'
    condition: 1 of selection*
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"Field": "a"})
    assert compiled.matches({"Field": "b"})
    assert not compiled.matches({"Field": "c"})


def test_all_of_them_expands_to_and():
    text = """
title: t
logsource: {product: windows}
detection:
    sel_one:
        A: '1'
    sel_two:
        B: '2'
    condition: all of them
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"A": "1", "B": "2"})
    assert not compiled.matches({"A": "1"})


def test_parentheses_group():
    text = """
title: t
logsource: {product: windows}
detection:
    a:
        F: '1'
    b:
        F: '2'
    c:
        G: '3'
    condition: (a or b) and c
"""
    compiled = sigma.parse(text)
    assert compiled.matches({"F": "1", "G": "3"})
    assert not compiled.matches({"F": "1"})


# --------------------------------------------------------------------------
# Refusing rather than silently never firing
# --------------------------------------------------------------------------

def test_an_unknown_modifier_raises():
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        Field|expandsomething: 'x'
    condition: selection
"""
    with pytest.raises(sigma.UnsupportedRule):
        sigma.parse(text)


def test_a_condition_naming_an_unknown_selection_raises():
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        Field: 'x'
    condition: selection and missing
"""
    with pytest.raises(sigma.UnsupportedRule):
        sigma.parse(text)


def test_a_quantifier_matching_nothing_raises():
    """`1 of filter*` with no filter selections would otherwise compile to a
    rule that can never fire."""
    text = """
title: t
logsource: {product: windows}
detection:
    selection:
        Field: 'x'
    condition: 1 of filter*
"""
    with pytest.raises(sigma.UnsupportedRule):
        sigma.parse(text)


def test_a_rule_with_no_detection_raises():
    with pytest.raises(sigma.SigmaError):
        sigma.parse("title: t\nlogsource: {product: windows}\n")


def test_a_rule_with_no_condition_raises():
    with pytest.raises(sigma.SigmaError):
        sigma.parse("title: t\ndetection:\n    selection:\n        F: 'x'\n")


def test_malformed_yaml_raises_sigma_error_not_yaml_error():
    """Callers catch SigmaError; a YAMLError escaping would take the loader
    down instead of skipping one bad file."""
    with pytest.raises(sigma.SigmaError):
        sigma.parse("title: [unclosed\n")


# --------------------------------------------------------------------------
# ATT&CK, which is why this is worth having
# --------------------------------------------------------------------------

def test_techniques_come_out_of_the_tags():
    """Sigma rules already carry them, so MITRE coverage costs nothing extra
    once the rules load - no mapping table to write or keep current."""
    assert rule().techniques == ["T1003.001"]


def test_tactics_are_separated_from_techniques():
    parsed = rule()
    assert parsed.tactics == ["credential-access"]
    assert "T1003.001" in parsed.techniques


def test_a_bare_technique_without_a_subtechnique_parses():
    text = """
title: t
logsource: {product: windows}
detection:
    selection: {F: 'x'}
    condition: selection
tags: [attack.t1059, attack.execution]
"""
    parsed = sigma.parse(text)
    assert parsed.techniques == ["T1059"]
    assert parsed.tactics == ["execution"]


def test_a_rule_with_no_tags_has_no_techniques():
    text = """
title: t
logsource: {product: windows}
detection:
    selection: {F: 'x'}
    condition: selection
"""
    assert sigma.parse(text).techniques == []


@pytest.mark.parametrize("level,severity", [
    ("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"),
    ("low", "LOW"), ("informational", "INFO"),
])
def test_levels_map_to_the_severities_already_in_use(level, severity):
    text = f"""
title: t
level: {level}
logsource: {{product: windows}}
detection:
    selection: {{F: 'x'}}
    condition: selection
"""
    assert sigma.severity_of(sigma.parse(text)) == severity


def test_an_unknown_level_defaults_to_medium_rather_than_failing():
    """A level nobody recognises is not a reason to drop a detection."""
    text = """
title: t
level: apocalyptic
logsource: {product: windows}
detection:
    selection: {F: 'x'}
    condition: selection
"""
    assert sigma.severity_of(sigma.parse(text)) == "MEDIUM"


def test_the_rule_keeps_its_identity():
    """Author, id and title are what make a community rule reviewable, and
    they have to survive into whatever the console shows."""
    parsed = rule()
    assert parsed.id == "a1b2c3d4-0000-0000-0000-000000000001"
    assert parsed.title == "LSASS Memory Dump via comsvcs.dll"
    assert parsed.logsource.get("category") == "process_creation"


# --------------------------------------------------------------------------
# A rule nobody here wrote
# --------------------------------------------------------------------------

# Verbatim from SigmaHQ:
# rules/windows/process_creation/proc_creation_win_vssadmin_delete_shadowcopies.yml
#
# The tests above use rules written alongside the evaluator, which makes them
# a check on the evaluator and not on whether it handles Sigma. This one was
# written by other people for another tool, and exercises constructs the
# hand-written cases do not: a selection that is a list of maps, the
# `all of selection_*` quantifier, and two techniques on one rule.
COMMUNITY_RULE = r"""
title: Shadow Copies Deletion Using Operating Systems Utilities
id: c947b146-0abc-4c87-9c64-b17e9d7274a2
status: stable
description: Shadow Copies deletion using operating systems utilities
author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov
tags:
    - attack.defense_evasion
    - attack.impact
    - attack.t1070
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\wmic.exe'
              - '\vssadmin.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'wmic.exe'
              - 'VSSADMIN.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'shadow'
            - 'delete'
    condition: all of selection_*
level: high
"""


def community():
    return sigma.parse(COMMUNITY_RULE)


def test_a_real_community_rule_parses():
    parsed = community()
    assert parsed.id == "c947b146-0abc-4c87-9c64-b17e9d7274a2"
    assert sigma.severity_of(parsed) == "HIGH"


def test_it_carries_both_of_its_techniques():
    assert set(community().techniques) == {"T1070", "T1490"}


def test_it_fires_on_the_attack():
    assert community().matches({
        "Image": r"C:\Windows\System32\vssadmin.exe",
        "CommandLine": "vssadmin.exe delete shadows /all /quiet",
    })


def test_it_stays_quiet_on_the_benign_neighbour():
    """Listing shadow copies is what backup software does."""
    assert not community().matches({
        "Image": r"C:\Windows\System32\vssadmin.exe",
        "CommandLine": "vssadmin.exe list shadows",
    })


def test_it_catches_a_renamed_binary():
    """`OriginalFileName` survives a rename, and this is the thing a regex
    over the assembled message cannot do: conf/rules.yaml matches text, so
    copying vssadmin.exe to svchost.exe defeats it."""
    assert community().matches({
        "OriginalFileName": "VSSADMIN.EXE",
        "CommandLine": r"C:\Users\Public\svchost.exe delete shadows /all",
    })


def test_a_list_of_maps_is_or_between_them():
    """`selection_img` offers Image OR OriginalFileName; matching either is
    enough, and requiring both would miss every renamed binary."""
    parsed = community()
    assert parsed.matches({"Image": r"x\wmic.exe",
                           "CommandLine": "delete shadow"})
    assert parsed.matches({"OriginalFileName": "wmic.exe",
                           "CommandLine": "delete shadow"})
