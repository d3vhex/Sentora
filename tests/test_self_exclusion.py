"""The agent must not detect itself.

The agent logs through syslog and reads syslog. Its own lines look like

    ip-172-31-42-49 main[28054]: 2026-08-27 07:34:25 [INFO] [root] [+] \
        resource_usage sent (1 rows)

and the KEYWORD ACCESS rule in `conf/rules.yaml` matches `\\b(?:sudo|ssh|root)\\b`.
The logger name is `root`, so every line the agent wrote matched a detection
rule - and each event it sent produced another "sent (N rows)" line, which
became another event. One host reached 60,015 rate-limited events.

The half of this worth testing is not "does it skip our lines" but "can
something else make itself look like our lines" - a text filter on a security
tool's own output is a hole with an invitation attached.
"""

import importlib.util
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "Sentora" / "modules" / "log_extractor" / "log_extractor.py"


@pytest.fixture(scope="module")
def extractor():
    """Load the agent module without its package's import-time side effects."""
    if not MODULE.exists():
        pytest.skip(f"{MODULE} not present")
    # The agent imports its siblings as `modules.*`, so its own root has to be
    # importable — otherwise every test here skips, and a skipped test proves
    # nothing about a filter whose whole job is to not have holes.
    agent_root = str(MODULE.parent.parent.parent)
    added = agent_root not in sys.path
    if added:
        sys.path.insert(0, agent_root)
    try:
        spec = importlib.util.spec_from_file_location("_sentora_log_extractor", MODULE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # pragma: no cover - agent deps are host-specific
            pytest.skip(f"agent module needs host dependencies: {exc}")
        return module
    finally:
        if added:
            sys.path.remove(agent_root)


def test_skips_a_line_this_process_wrote(extractor):
    pid = os.getpid()
    line = (
        f"ip-172-31-42-49 main[{pid}]: 2026-08-27 07:34:25 "
        "[INFO] [root] [+] resource_usage sent (1 rows)"
    )
    assert extractor.is_own_output(line=line) is True


def test_keeps_the_same_text_from_another_pid(extractor):
    """Identical text, different process — that is somebody else's event."""
    other = os.getpid() + 1
    line = (
        f"ip-172-31-42-49 main[{other}]: 2026-08-27 07:34:25 "
        "[INFO] [root] [+] resource_usage sent (1 rows)"
    )
    assert extractor.is_own_output(line=line) is False


def test_keeps_a_line_that_merely_mentions_us(extractor):
    """The filter is our PID, not our name.

    Otherwise anyone who can write the word `sentora` to syslog gets a free
    invisibility cloak - including an attacker who has read the source, which
    is public.
    """
    for line in (
        "Aug 27 07:34:25 host sshd[991]: Accepted password for root from 10.0.0.9",
        "Aug 27 07:34:25 host sudo: pam_unix(sudo:session): session opened for root",
        "Aug 27 07:34:25 host attacker[4242]: sentora-agent main[1]: [+] sent (1 rows)",
        "Aug 27 07:34:25 host cron[77]: (root) CMD (/usr/bin/sentora-agent --status)",
    ):
        assert extractor.is_own_output(line=line) is False, line


def test_journal_identity_beats_the_text(extractor):
    """On the journal path the kernel says who wrote it, and cannot be lied to."""
    # Our unit, text that looks like an attack: still ours.
    assert extractor.is_own_output(
        line="Accepted password for root from 10.0.0.9",
        entry={"_SYSTEMD_UNIT": "sentora-agent.service", "_PID": "999"},
    ) is True

    # Our PID, any text: still ours.
    assert extractor.is_own_output(
        line="anything at all",
        entry={"_PID": str(os.getpid()), "_SYSTEMD_UNIT": "sshd.service"},
    ) is True


def test_journal_does_not_hide_another_units_forgery(extractor):
    """A line claiming to be us, from a unit that is not us, stays visible."""
    forged = f"main[{os.getpid()}]: [INFO] [root] [+] nothing to see"
    assert extractor.is_own_output(
        line=forged,
        entry={"_SYSTEMD_UNIT": "attacker.service", "_PID": "31337"},
    ) is False


def test_empty_and_missing_input_is_not_ours(extractor):
    assert extractor.is_own_output() is False
    assert extractor.is_own_output(line="") is False
    assert extractor.is_own_output(line="", entry={}) is False
    assert extractor.is_own_output(line=None or "", entry=None) is False


def test_the_exclusion_count_is_reported(extractor):
    """The number that proves the loop is gone has to be printed somewhere.

    It was not. `excluded=` was missing from the stats line, so the only
    evidence that self-exclusion was working never reached an operator, and
    "did this fix anything?" could only be answered by guessing.
    """
    import inspect

    source = inspect.getsource(extractor.stats_reporter)
    assert "excluded=" in source
    assert "excluded_events" in source


def test_exclusions_alone_still_produce_a_report(extractor):
    """The better the fix works, the quieter the report used to get.

    `is_own_output` increments `excluded_events` and skips the line *before*
    `events_processed` is touched. The reporter only spoke when `processed`
    changed, so on the host where the agent's own output was the whole
    problem, a working fix meant total silence.
    """
    import inspect

    source = inspect.getsource(extractor.stats_reporter)
    assert "last_processed" not in source, \
        "the report still wakes only on events_processed"
    assert "moved" in source


def test_malformed_journal_entry_does_not_crash(extractor):
    """Journal fields arrive as bytes, ints, or absent depending on the reader."""
    for entry in (
        {"_PID": None, "_SYSTEMD_UNIT": None},
        {"_PID": os.getpid()},               # int, not str
        {"_SYSTEMD_UNIT": b"sshd.service"},  # bytes
    ):
        assert extractor.is_own_output(line="x", entry=entry) in (True, False)

    # An int PID matching ours is still ours.
    assert extractor.is_own_output(line="", entry={"_PID": os.getpid()}) is True
