"""Tests for the pre-LLM triage funnel.

The severity gate is the part that can lose a detection: it drops events on a
label the agent's rule file assigned, so the model never gets to disagree.
Most of what is pinned here is therefore about *not* dropping — the failure
mode that matters is a silent one.
"""
from __future__ import annotations

import pytest

from core import triage


@pytest.fixture(autouse=True)
def _reset():
    triage.dropped_by_severity.clear()
    triage.suppressed_duplicates = 0
    original = triage.MIN_SEVERITY
    yield
    triage.MIN_SEVERITY = original


# --------------------------------------------------------------------------
# Severity gate — failing open
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", [None, "", "WARN", "sev-3", "unknown", 42, {}])
def test_unreadable_severity_is_kept(value):
    """The important one.

    Fields go missing in this pipeline — the Windows event `source` was being
    dropped entirely until recently. "We could not read the severity" must
    never resolve to "below the floor", because a dropped event is invisible
    to the entire AI pipeline.
    """
    triage.MIN_SEVERITY = "HIGH"
    send, why = triage.passes_severity({"severity": value})
    assert send is True
    assert "unreadable" in why or "kept" in why


def test_missing_severity_key_is_kept():
    triage.MIN_SEVERITY = "CRITICAL"
    assert triage.passes_severity({"message": "something happened"})[0] is True


def test_unparseable_floor_disables_the_gate():
    """A typo in AI_MIN_SEVERITY must not silently drop everything."""
    triage.MIN_SEVERITY = "HIHG"
    assert triage.passes_severity({"severity": "INFO"})[0] is True


def test_info_floor_means_the_gate_is_off():
    triage.MIN_SEVERITY = "INFO"
    for sev in triage.SEVERITY_LADDER:
        assert triage.passes_severity({"severity": sev})[0] is True


# --------------------------------------------------------------------------
# Severity gate — dropping what it should
# --------------------------------------------------------------------------

@pytest.mark.parametrize("floor,severity,expected", [
    ("LOW", "INFO", False),
    ("LOW", "LOW", True),
    ("LOW", "CRITICAL", True),
    ("MEDIUM", "LOW", False),
    ("MEDIUM", "MEDIUM", True),
    ("HIGH", "MEDIUM", False),
    ("CRITICAL", "HIGH", False),
    ("CRITICAL", "CRITICAL", True),
])
def test_floor_comparison(floor, severity, expected):
    triage.MIN_SEVERITY = floor
    assert triage.passes_severity({"severity": severity})[0] is expected


def test_severity_is_case_and_space_insensitive():
    triage.MIN_SEVERITY = "MEDIUM"
    assert triage.passes_severity({"severity": " critical "})[0] is True
    assert triage.passes_severity({"severity": "info"})[0] is False


def test_alternative_field_names_are_read():
    """log_extractor writes `severity`; some producers use `level`."""
    triage.MIN_SEVERITY = "HIGH"
    assert triage.passes_severity({"level": "INFO"})[0] is False
    assert triage.passes_severity({"level": "CRITICAL"})[0] is True


# --------------------------------------------------------------------------
# Visibility
# --------------------------------------------------------------------------

def test_drops_are_persisted_not_just_counted_in_memory():
    """The counter has to live in the database.

    Ingest runs in server.py; /api/ai/triage-stats is served by app.py. A
    tally held in module state reads as zero from the API no matter how many
    events were dropped — an answer-shaped number measuring nothing, which is
    worse than no number at all. This is exactly what the first version did.
    """
    cur = FakeCursor()
    triage.record_drop(cur, "INFO")
    triage.record_drop(cur, "info")     # normalised to the same key
    triage.record_drop(cur, " Low ")

    assert cur.drops == {"INFO": 2, "LOW": 1}


def test_recording_a_drop_never_raises():
    """Bookkeeping must not break ingest. The event is already dropped;
    losing the tally is bad, losing telemetry would be worse."""
    class Broken:
        def execute(self, *a, **k):
            raise RuntimeError("table is gone")

    triage.record_drop(Broken(), "INFO")   # must not propagate


def test_config_reports_whether_the_gate_is_on():
    triage.MIN_SEVERITY = "INFO"
    assert triage.config()["severity_gate_enabled"] is False
    triage.MIN_SEVERITY = "HIGH"
    assert triage.config()["severity_gate_enabled"] is True


# --------------------------------------------------------------------------
# Dedup counter
# --------------------------------------------------------------------------

class FakeCursor:
    """Mimics MySQL's rowcount convention: 1 for an INSERT, 2 for an
    ON DUPLICATE KEY UPDATE that changed a row."""

    def __init__(self):
        self.counts: dict[str, int] = {}
        self.drops: dict[str, int] = {}
        self.rowcount = 0
        self._last_fp = None

    def execute(self, sql, params=()):
        upper = sql.strip().upper()
        if upper.startswith("CREATE"):
            return
        if "AI_TRIAGE_DROPS" in upper and upper.startswith("INSERT"):
            sev = params[0]
            self.drops[sev] = self.drops.get(sev, 0) + 1
            return
        if upper.startswith("INSERT"):
            fp = params[0]
            if fp in self.counts:
                self.counts[fp] += 1
                self.rowcount = 2
            else:
                self.counts[fp] = 1
                self.rowcount = 1
        else:
            self._last_fp = params[0]

    def fetchone(self):
        return (self.counts[self._last_fp],)


def test_first_sighting_is_analysed():
    cur = FakeCursor()
    is_new, seen = triage.record_occurrence(cur, "siem_events", "a" * 64)
    assert is_new is True
    assert seen == 1


def test_repeats_are_suppressed_and_counted():
    """The point of the funnel: one inference, and the repeat count kept.

    A burst is itself signal — one failed logon and four hundred are
    different events — so collapsing them must not lose the number.
    """
    cur = FakeCursor()
    fp = "b" * 64
    triage.record_occurrence(cur, "siem_events", fp)
    for _ in range(4):
        is_new, seen = triage.record_occurrence(cur, "siem_events", fp)
        assert is_new is False
    # The count is what survives the collapse. It lives in ai_dedup, which is
    # what the stats endpoint reads — not a module counter, which would be in
    # the wrong process to ever be seen.
    assert seen == 5
    assert cur.counts[fp] == 5


def test_distinct_fingerprints_are_independent():
    cur = FakeCursor()
    assert triage.record_occurrence(cur, "siem_events", "c" * 64)[0] is True
    assert triage.record_occurrence(cur, "siem_events", "d" * 64)[0] is True
