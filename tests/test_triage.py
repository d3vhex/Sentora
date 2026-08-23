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


def test_severity_is_read_from_the_json_body_when_the_column_is_empty():
    """The bug the eval corpus exposed.

    log_extractor put the enriched event into `message` as JSON and left the
    severity column NULL, so reading only the column made this gate silently
    inert for every siem_events row. It found nothing to compare and kept
    everything, which is indistinguishable from a correctly-configured floor
    with nothing below it.
    """
    triage.MIN_SEVERITY = "HIGH"
    row = {"source": None, "severity": None,
           "message": '{"source": "Application", "severity": "INFO", '
                      '"message": "routine"}'}
    send, why = triage.passes_severity(row)
    assert send is False
    assert "INFO" in why


def test_json_body_severity_can_also_keep_an_event():
    triage.MIN_SEVERITY = "HIGH"
    row = {"message": '{"severity": "CRITICAL"}'}
    assert triage.passes_severity(row)[0] is True


@pytest.mark.parametrize("body", [
    "not json at all",
    '{"severity": ',          # truncated
    '["a", "list"]',
    '{"no_severity_here": 1}',
    None,
    123,
])
def test_unparseable_body_keeps_the_event(body):
    """A parse failure must not become a silent drop."""
    triage.MIN_SEVERITY = "CRITICAL"
    assert triage.passes_severity({"message": body})[0] is True


def test_the_column_wins_over_the_body():
    """Once the agent populates the column it is authoritative; the body is
    only the fallback for rows written before that."""
    triage.MIN_SEVERITY = "HIGH"
    row = {"severity": "CRITICAL", "message": '{"severity": "INFO"}'}
    assert triage.passes_severity(row)[0] is True


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


# --------------------------------------------------------------------------
# Fingerprint agreement between the two paths that feed the AI queue
# --------------------------------------------------------------------------

class TestFingerprintAgreement:
    """The defensive sweep and ingest must agree on what "already seen" means.

    They read the same event from different places: ingest fingerprints the
    payload the agent posted, the sweep fingerprints the row it read back out
    of MySQL. MySQL has added `id`, `dup_fp`, `created_at`, `sent` and the
    `ai_analyzed*` flags by then. If those reach the hash, the two paths
    produce different fingerprints, the sweep treats every alert as new, and
    the dedup check runs without preventing anything - which is worse than no
    check, because the queue still runs away while the code looks correct.
    """

    def _ingest_payload(self):
        return {
            "source": "Security/Microsoft-Windows-Security-Auditing",
            "timestamp": "2026-08-22 21:27:18",
            "severity": "HIGH",
            "score": 7,
            "categories": "LOGON FAILURE",
            "message": "EventID=4625 | Account=svc_backup | Status=0xC000006D",
        }

    def _stored_row(self):
        row = self._ingest_payload()
        row.update({
            "id": 4711,
            "sent": 1,
            "dup_fp": "a" * 64,
            "created_at": "2026-08-22 21:27:20",
            "ai_analyzed": 1,
            "ai_analyzed_at": "2026-08-22 21:28:02",
        })
        return row

    def test_the_stored_row_and_the_posted_payload_agree(self):
        from core.triage import compute_ai_fingerprint
        assert compute_ai_fingerprint("events_alert", self._ingest_payload()) == \
            compute_ai_fingerprint("events_alert", self._stored_row())

    def test_a_later_sighting_of_the_same_event_agrees(self):
        """Same alert, different time and row id - one fingerprint."""
        from core.triage import compute_ai_fingerprint
        later = self._stored_row()
        later.update(id=9999, timestamp="2026-08-23 04:00:00",
                     created_at="2026-08-23 04:00:01", dup_fp="b" * 64)
        assert compute_ai_fingerprint("events_alert", self._stored_row()) == \
            compute_ai_fingerprint("events_alert", later)

    def test_a_genuinely_different_alert_does_not_collide(self):
        """The ignore list must not have eaten the content."""
        from core.triage import compute_ai_fingerprint
        other = self._stored_row()
        other["message"] = "EventID=4625 | Account=administrator | Status=0xC000006D"
        assert compute_ai_fingerprint("events_alert", self._stored_row()) != \
            compute_ai_fingerprint("events_alert", other)

    def test_severity_is_part_of_the_identity(self):
        from core.triage import compute_ai_fingerprint
        escalated = self._stored_row()
        escalated["severity"] = "CRITICAL"
        assert compute_ai_fingerprint("events_alert", self._stored_row()) != \
            compute_ai_fingerprint("events_alert", escalated)

    def test_the_same_event_in_two_tables_is_two_fingerprints(self):
        from core.triage import compute_ai_fingerprint
        assert compute_ai_fingerprint("events_alert", self._stored_row()) != \
            compute_ai_fingerprint("siem_events", self._stored_row())

    def test_there_is_only_one_implementation(self):
        """server.py must import it, not define its own.

        Two copies would drift, and the drift would show up as the queue
        filling with repeats rather than as a failing import.
        """
        import pathlib
        server = pathlib.Path(__file__).resolve().parent.parent / "server.py"
        text = server.read_text(encoding="utf-8")
        assert "from core.triage import compute_ai_fingerprint" in text
        assert "def compute_ai_fingerprint" not in text


class TestDefensiveSweepIsIdempotent:
    """The sweep must not re-queue alerts it has already queued.

    It re-reads the same "most recent N" rows every 300s. Publishing all of
    them each time put 4130 duplicate messages on ai_soar_queue and grew
    ai_analysis_results by ~1000 rows an hour, all describing the same handful
    of events.
    """

    def test_the_sweep_does_not_force(self):
        import ast
        import pathlib
        app_py = pathlib.Path(__file__).resolve().parent.parent / "app.py"
        tree = ast.parse(app_py.read_text(encoding="utf-8"))

        sweep = next(n for n in ast.walk(tree)
                     if isinstance(n, ast.AsyncFunctionDef)
                     and n.name == "_defensive_auto_sweep")
        calls = [n for n in ast.walk(sweep) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "_push_recent_alerts_to_defensive"]
        assert calls, "the sweep no longer calls _push_recent_alerts_to_defensive"
        for call in calls:
            forced = [k for k in call.keywords if k.arg == "force"]
            assert not forced, (
                "the timed sweep must never force re-analysis; only a person "
                "pressing the button may"
            )

    def test_the_sweep_runs_in_one_worker_only(self):
        """Otherwise each Sanic worker queues the same alerts."""
        import ast
        import pathlib
        app_py = pathlib.Path(__file__).resolve().parent.parent / "app.py"
        tree = ast.parse(app_py.read_text(encoding="utf-8"))
        starter = next(n for n in ast.walk(tree)
                       if isinstance(n, ast.AsyncFunctionDef)
                       and n.name == "start_defensive_sweep")
        src = ast.dump(starter)
        assert "SANIC_WORKER_NAME" in src, (
            "start_defensive_sweep has no worker guard, so the sweep runs once "
            "per worker"
        )


class TestClaimVersusRecord:
    """`claim_for_analysis` must not inflate the occurrence counter.

    The sweep calls it on the same rows every five minutes. If it counted
    those passes, `occurrences` would measure the sweep's loop rate rather
    than how often the event happened, and `inferences_avoided` - which is
    derived from it - would climb on its own with no events arriving.
    """

    class FakeCursor:
        """Enough MySQL to exercise the rowcount convention."""

        def __init__(self):
            self.rows = {}     # fingerprint -> occurrences
            self.rowcount = 0

        def execute(self, sql, params=()):
            s = " ".join(sql.split())
            if s.startswith("CREATE TABLE"):
                self.rowcount = 0
                return
            if s.startswith("INSERT INTO ai_dedup"):
                fp = params[0]
                if fp not in self.rows:
                    self.rows[fp] = 1
                    self.rowcount = 1          # inserted
                else:
                    if "occurrences = occurrences + 1" in s:
                        self.rows[fp] += 1
                    self.rowcount = 2          # updated
                return
            if s.startswith("SELECT occurrences"):
                self._selected = self.rows.get(params[0], 0)
                return
            raise AssertionError(f"unexpected SQL: {s}")

        def fetchone(self):
            return (self._selected,)

    def test_claim_is_true_once_then_false(self):
        from core.triage import claim_for_analysis
        cur = self.FakeCursor()
        assert claim_for_analysis(cur, "events_alert", "f" * 64) is True
        assert claim_for_analysis(cur, "events_alert", "f" * 64) is False

    def test_repeated_claims_do_not_move_the_counter(self):
        from core.triage import claim_for_analysis
        cur = self.FakeCursor()
        for _ in range(50):        # ~4 hours of sweeps over the same alert
            claim_for_analysis(cur, "events_alert", "f" * 64)
        assert cur.rows["f" * 64] == 1, (
            "the sweep inflated occurrences; inferences_avoided would climb "
            "with no events arriving"
        )

    def test_record_occurrence_does_count(self):
        """The contrast: ingest sightings are real and must be counted."""
        from core.triage import record_occurrence
        cur = self.FakeCursor()
        for _ in range(5):
            record_occurrence(cur, "events_alert", "f" * 64)
        assert cur.rows["f" * 64] == 5

    def test_a_claim_blocks_a_later_ingest_from_re_analysing(self):
        """Both paths share one table, which is the point."""
        from core.triage import claim_for_analysis, record_occurrence
        cur = self.FakeCursor()
        assert claim_for_analysis(cur, "events_alert", "f" * 64) is True
        is_new, _ = record_occurrence(cur, "events_alert", "f" * 64)
        assert is_new is False


def test_the_sweep_claims_rather_than_records():
    """Guard against someone swapping the call back."""
    import ast
    import pathlib
    app_py = pathlib.Path(__file__).resolve().parent.parent / "app.py"
    tree = ast.parse(app_py.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_filter_unseen_alerts")
    called = {getattr(n.func, "id", "") for n in ast.walk(fn) if isinstance(n, ast.Call)}
    assert "claim_for_analysis" in called
    assert "record_occurrence" not in called, (
        "the sweep must not count its own passes as event occurrences"
    )
