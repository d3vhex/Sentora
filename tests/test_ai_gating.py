"""One definition of "an analyst sees this".

The worker decides `Realtime_` vs `Reviewed_`; the eval harness scores the
model. They were separate, and the gap hid a result:

    eval   escalation recall 40%   (4 of 10 attacks flagged)
    live   0 of 542 events surfaced

A rewritten prompt genuinely improved the model - it went from calling an
LSASS dump "Routine logon event" to describing the comsvcs MiniDump command
line correctly. Every one of those detections came back SUSPICIOUS at
confidence 0.60, and SUSPICIOUS needs 0.75. The analyst saw exactly as much as
before, which was nothing, while the harness reported progress.
"""
from __future__ import annotations

import types

import pytest

from ai import gating


def v(verdict, severity="MEDIUM", confidence=0.9, criterion="none"):
    return types.SimpleNamespace(verdict=verdict, severity=severity,
                                 confidence=confidence,
                                 matched_criterion=criterion)


# --------------------------------------------------------------------------
# The case that was missed
# --------------------------------------------------------------------------

def test_suspicious_does_not_surface_at_any_confidence():
    """The model's SUSPICIOUS label scored precision 0.00 and recall 0.00 over
    29 cases: never applied to one that deserved it, never withheld from one
    that did not. It can use the top of the scale and not the middle.

    Both false alarms that reached an analyst were SUSPICIOUS at 0.80 - this
    platform's own Docker containers restarting.
    """
    for confidence in (0.0, 0.5, 0.6, 0.75, 0.8, 1.0):
        assert gating.surfaces(v("SUSPICIOUS", "HIGH", confidence)) is False


def test_the_middle_of_the_scale_is_not_gone_it_moved():
    """A criterion the log supports still surfaces whatever the verdict says,
    because that is a fact about the event. What is refused is the model
    volunteering uncertainty with nothing behind it."""
    assert gating.surfaces(
        v("SUSPICIOUS", "HIGH", 0.0, criterion="C2 remote execution")) is True


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

@pytest.mark.parametrize("verdict,severity,criterion,expected", [
    ("CRITICAL",     "CRITICAL", "C1",   True),
    ("CRITICAL",     "HIGH",     "C6",   True),
    ("CRITICAL",     "HIGH",     "none", False),  # no evidence in the log
    ("CRITICAL",     "MEDIUM",   "C1",   False),  # severity disagrees with itself
    ("SUSPICIOUS",   "LOW",      "C1",   False),
    ("NOT_CRITICAL", "CRITICAL", "C1",   False),
    ("INSUFFICIENT_DATA", "HIGH", "C1",  False),
])
def test_gate(verdict, severity, criterion, expected):
    assert gating.surfaces(v(verdict, severity, 0.9, criterion)) is expected


def test_no_verdict_does_not_surface():
    assert gating.surfaces(None) is False


def test_confidence_is_not_consulted_at_all():
    """Not "weighted less" - not read. A malformed one used to fail the gate
    closed; now it cannot fail it either way, which is the point."""
    assert gating.surfaces(v("CRITICAL", "HIGH", "not a number", "C1")) is True
    assert gating.surfaces(v("CRITICAL", "HIGH", None, "C1")) is True
    assert gating.surfaces(v("CRITICAL", "HIGH", 1.0, "none")) is False


# --------------------------------------------------------------------------
# One definition, two callers
# --------------------------------------------------------------------------

def test_the_worker_uses_the_shared_gate():
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parent.parent / "ai_worker.py"
    text = src.read_text(encoding="utf-8")
    assert "from ai.gating import surfaces" in text

    tree = ast.parse(text)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "handle_automation")
    called = {getattr(n.func, "id", "") for n in ast.walk(fn) if isinstance(n, ast.Call)}
    assert "surfaces" in called, "handle_automation reimplements the gate"


def test_the_harness_uses_the_shared_gate():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "scripts" / "run_eval.py").read_text(encoding="utf-8")
    assert "from ai.gating import" in src
    assert "surfaces(verdict)" in src


def test_the_report_shows_what_production_would_show():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "scripts" / "run_eval.py").read_text(encoding="utf-8")
    assert "surfaced_recall" in src
    assert "Reaches an analyst" in src


# --------------------------------------------------------------------------
# A verified criterion is not model output
# --------------------------------------------------------------------------

def vc(verdict="CRITICAL", severity="CRITICAL", confidence=0.5, criterion="none"):
    return types.SimpleNamespace(verdict=verdict, severity=severity,
                                 confidence=confidence, matched_criterion=criterion)


def test_a_verified_criterion_surfaces_regardless_of_confidence():
    """Measured on the attack corpus: six CRITICAL verdicts whose severity was
    also CRITICAL were blocked at confidence 0.50 - an LSASS dump, a SAM hive
    export, shadow copies being deleted. A seventh sat at 0.00.

    Every benign case also came back at 0.50. The number carries no signal in
    either direction, so gating a checked fact on it discards real detections
    and admits nothing.
    """
    assert gating.surfaces(vc(confidence=0.5, criterion="C1 credential access"))
    assert gating.surfaces(vc(confidence=0.0, severity="HIGH", criterion="C3"))


def test_without_a_criterion_nothing_surfaces():
    """Confidence used to rescue these. Measured over 29 cases, every attack
    that surfaced already had a verified criterion, so the confidence path
    caught nothing evidence had not - while admitting both of the false alarms
    that reached an analyst."""
    assert not gating.surfaces(vc(confidence=0.5, criterion="none"))
    assert not gating.surfaces(vc(confidence=0.9, criterion="none"))
    assert not gating.surfaces(vc(confidence=1.0, criterion="none"))


def test_severity_is_still_required():
    """A criterion match raises severity to at least HIGH in criteria.apply,
    so MEDIUM here means something overrode it and the verdict is incoherent."""
    assert not gating.surfaces(vc(severity="MEDIUM", confidence=0.9, criterion="C1"))


def test_suspicious_still_needs_a_qualifying_severity():
    """`criteria.apply` promotes a supported criterion to CRITICAL, so a
    SUSPICIOUS verdict carrying one at MEDIUM means something overrode the
    promotion and the verdict disagrees with itself."""
    assert not gating.surfaces(
        vc(verdict="SUSPICIOUS", severity="MEDIUM", confidence=0.5, criterion="C1"))


def test_the_threshold_history_is_recorded_where_the_next_person_looks():
    """Two rounds of measurement took the confidence gate apart. Both are
    written down in the module, so the next person to reach for a threshold
    sees that it was tried before reaching."""
    import inspect
    source = inspect.getsource(gating)
    assert "0.60 and 0.90" in source
    assert "Docker container lifecycle" in source


def test_configured_thresholds_that_no_longer_apply_are_not_silently_ignored():
    """Someone has AI_SUS_CONF in a .env. Reading it and doing nothing is the
    kind of quiet no-op that costs an afternoon."""
    import inspect
    source = inspect.getsource(gating)
    assert "AI_CRIT_CONF" in source
    assert "warning" in source


def test_the_description_matches_the_rule():
    """It is printed in the eval report, so a stale description would
    misdescribe every run."""
    described = gating.describe()
    assert "criterion" in described
    assert "confidence is not consulted" in described
