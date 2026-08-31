r"""The Windows collector must not re-read what it has already read.

`follow_windows_eventlog` reopened the channel every three seconds and read
the newest batch *from the start* each time, with nothing remembering where it
had got to. The same events were processed again for as long as the agent ran.

On an idle Windows 11 host that came to roughly 155 events a second against a
limiter allowing 1000 a minute:

    SIEM stats: processed=28 output=28 duplicates=233 rate_limited=350246
                uptime=2522s

The waste was the smaller half. `rate_limiter.is_allowed()` is checked before
anything else, so re-read events spent the budget a genuinely new event
needed - a real detection could be dropped because the agent was busy
rereading the same logon for the hundredth time.

The collector needs `win32evtlog`, so what is exercised here is the shape of
the loop rather than the loop itself: that a cursor exists, that it is
compared before the limiter, and that it advances once per batch.
"""

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "Sentora" / "modules" / "log_extractor" / "log_extractor.py"
SOURCE = MODULE.read_text(encoding="utf-8")


def _function(name: str) -> ast.FunctionDef:
    tree = ast.parse(SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


@pytest.fixture(scope="module")
def collector() -> str:
    return ast.unparse(_function("follow_windows_eventlog"))


def test_the_channel_has_a_cursor(collector):
    assert "last_record" in collector
    assert "RecordNumber" in collector


def test_the_cursor_is_checked_before_the_rate_limiter(collector):
    """Order is the whole point. Checked afterwards, a re-read event still
    spends the budget - which is what starved real events."""
    assert collector.index("last_record is not None") < collector.index("is_allowed")


def test_an_already_seen_record_stops_the_scan(collector):
    """Backwards read means newest first, so the first familiar record means
    everything below it is familiar too."""
    assert "break" in collector
    assert "record <= last_record" in collector


def test_the_cursor_advances_once_per_batch(collector):
    """Not per event: a failure part-way through should leave the channel to
    be re-read rather than skip whatever was missed."""
    assert "newest_seen" in collector
    assert collector.index("newest_seen") < collector.index("last_record = newest_seen")


def test_a_record_without_a_number_is_still_processed(collector):
    """`RecordNumber` is read defensively. An event that does not carry one
    must not be silently dropped - losing events is the failure this whole
    module exists to avoid."""
    assert 'getattr(ev, \'RecordNumber\', None)' in collector \
        or 'getattr(ev, "RecordNumber", None)' in collector
    assert "if record is not None" in collector


def test_the_reader_still_sleeps_between_polls(collector):
    """Three seconds. Without the cursor this was a re-read cadence; with it,
    it is a poll interval."""
    assert "time.sleep(3)" in collector
