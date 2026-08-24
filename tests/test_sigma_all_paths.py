"""Sigma on every collection path, not just Windows.

The bug this pins: Sigma was evaluated on the Windows event path only. The
file and journal followers still used the regex list, so a Linux endpoint got
no Sigma at all and no ATT&CK technique on anything it reported - and the
coverage page, reading techniques out of stored events, would have shown a
mixed estate as a Windows one.

The three paths do not have equal information and never will. A Windows event
and a journal entry carry named fields; a syslog line is text. What has to be
true is that all three *run* Sigma, and that the difference between them is a
property of the logs rather than an accident of which code path was updated.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXTRACTOR = ROOT / "Sentora" / "modules" / "log_extractor" / "log_extractor.py"
SOURCE = EXTRACTOR.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def _load_extractor():
    """Import the agent's extractor as a module.

    It imports `modules.enc_db` and friends by the name they have when the
    agent is the program being run, so the agent root has to be on the path
    first. Skipped rather than failed when an agent-only dependency is absent
    - the AST tests above still cover the wiring on a server-only checkout.
    """
    import importlib.util
    import sys

    agent_root = str(ROOT / "Sentora")
    if agent_root not in sys.path:
        sys.path.insert(0, agent_root)

    spec = importlib.util.spec_from_file_location("_log_extractor", EXTRACTOR)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ImportError as e:
        pytest.skip(f"agent dependency unavailable: {e}")
    return module


def _function(name: str):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


COLLECTORS = ["follow_windows_eventlog", "enhanced_follow_file",
              "enhanced_follow_journal"]


@pytest.mark.parametrize("collector", COLLECTORS)
def test_every_collector_classifies_through_the_shared_path(collector):
    """One implementation, not three. It was one and then two, and the second
    silently kept the old behaviour."""
    body = ast.unparse(_function(collector))
    assert "classify(" in body, f"{collector} does not run the classifier"


@pytest.mark.parametrize("collector", COLLECTORS)
def test_every_collector_accepts_the_rules(collector):
    """A collector that cannot be handed the rules cannot run them, however
    the body is written."""
    args = [a.arg for a in _function(collector).args.args]
    assert "sigma_rules" in args, f"{collector} takes no rules"


@pytest.mark.parametrize("collector", COLLECTORS)
def test_every_collector_records_the_techniques_it_matched(collector):
    """ATT&CK coverage is computed from stored events. A path that detects
    correctly but drops the technique reports as uncovered, which is the one
    direction that number must not be wrong in."""
    body = ast.unparse(_function(collector))
    assert "techniques" in body, f"{collector} drops the technique"


def test_the_rules_are_actually_passed_at_startup():
    """Every thread is spawned with them - the signature accepting the
    argument proves nothing about the call."""
    spawns = [n for n in ast.walk(TREE)
              if isinstance(n, ast.Call) and "Thread" in ast.unparse(n.func)]
    for collector in COLLECTORS:
        matching = [s for s in spawns if collector in ast.unparse(s)]
        assert matching, f"{collector} is never started"
        for call in matching:
            assert "sigma_rules" in ast.unparse(call), \
                f"{collector} is started without the rules"


# --------------------------------------------------------------------------
# The classifier itself
# --------------------------------------------------------------------------

def test_sigma_wins_over_the_regex_list():
    """Sigma matched a named field and carries a technique; the regex list
    matched text somewhere in the line. They are not equally strong evidence
    and the stronger one has to be preferred, or installing rules changes
    nothing."""
    body = ast.unparse(_function("classify"))
    sigma_at = body.index("sigma_rules")
    regex_at = body.index("rules_list")
    assert sigma_at < regex_at


def test_the_classifier_records_which_layer_decided():
    """A Sigma hit and a regex hit mean different things - one matched a named
    field and carries a technique, the other matched text somewhere in the
    line - and the console should not present them as the same thing.

    Exercised rather than grepped for: an earlier version of this test only
    checked that a `by` argument was written down, which it was, while nothing
    read it.
    """
    module = _load_extractor()

    from core.sigma import parse
    rule = parse("title: Shadow Copies Deleted\nlogsource: {product: windows}\n"
                 "detection:\n    sel:\n        CommandLine|contains: 'vssadmin'\n"
                 "    condition: sel\ntags: [attack.t1490]\n", "t")
    regex_list = [{"regex": __import__("re").compile("vssadmin"),
                   "category": "SUSPICIOUS_COMMAND", "severity": "MEDIUM"}]

    sigma_hit = module.classify("vssadmin delete shadows",
                                {"CommandLine": "vssadmin delete shadows"},
                                [rule], regex_list)
    assert sigma_hit.by == "sigma"
    assert sigma_hit.rule_title == "Shadow Copies Deleted"
    assert sigma_hit.techniques == ["T1490"]

    # Same text, no fields to match on: the regex list is what is left.
    regex_hit = module.classify("vssadmin delete shadows", {}, [rule], regex_list)
    assert regex_hit.by == "regex"
    assert regex_hit.rule_title is None
    assert regex_hit.techniques == []

    assert module.classify("nothing interesting", {}, [rule], regex_list) is None


def test_every_matching_rule_contributes_its_techniques():
    """`conf/rules.yaml` stops at the first match, which is how one broad
    pattern could label everything and hide the rest. Techniques accumulate
    across rules, so stopping early loses coverage as well as detections."""
    body = ast.unparse(_function("classify"))
    assert "for r in hits" in body or "for r in hits for" in body


def test_nothing_matching_is_not_an_event():
    """The loops used to `continue` on no regex match. That behaviour has to
    survive, or every line on the host becomes an event."""
    body = ast.unparse(_function("classify"))
    assert body.rstrip().endswith("return None")


# --------------------------------------------------------------------------
# What each path can offer a rule
# --------------------------------------------------------------------------

def test_a_journal_entry_supports_field_matching():
    """The journal carries the process and its command line as real fields,
    so a rule written for Windows behaves the same way here."""
    from core.sigma import parse
    from core.sigma_loader import journal_event_fields

    rule = parse("title: t\nlogsource: {product: linux}\n"
                 "detection:\n    sel:\n        Image|endswith: 'sshd'\n"
                 "    condition: sel\n", "t")
    assert rule.matches(journal_event_fields({"_COMM": "sshd", "MESSAGE": "x"}))


def test_a_text_line_cannot_support_field_matching_and_says_so():
    """Not a broken rule - a syslog line has no CommandLine to match. Pinned
    because the honest answer here is a limitation, and limitations are what
    quietly get papered over."""
    from core.sigma import parse
    from core.sigma_loader import text_event_fields

    rule = parse("title: t\nlogsource: {product: linux}\n"
                 "detection:\n    sel:\n        CommandLine|contains: 'curl'\n"
                 "    condition: sel\n", "t")
    assert not rule.matches(text_event_fields("something ran curl", "/var/log/syslog"))

    message_rule = parse("title: t\nlogsource: {product: linux}\n"
                         "detection:\n    sel:\n        Message|contains: 'curl'\n"
                         "    condition: sel\n", "t")
    assert message_rule.matches(text_event_fields("something ran curl", "/var/log/syslog"))


def test_bytes_from_the_journal_are_decoded():
    """python-systemd hands back bytes for some fields, and `str(b'sshd')`
    is `"b'sshd'"` - which matches nothing and looks like a missing field."""
    from core.sigma_loader import journal_event_fields
    fields = journal_event_fields({"_COMM": b"sshd", "MESSAGE": b"accepted key"})
    assert fields["Image"] == "sshd"
    assert fields["Message"] == "accepted key"


def test_an_empty_journal_entry_does_not_raise():
    """The follower runs this on every entry; one malformed entry must not
    end the thread and stop collection on the host."""
    from core.sigma_loader import journal_event_fields
    assert journal_event_fields({}) == {"Message": ""}
    assert journal_event_fields(None) == {"Message": ""}
