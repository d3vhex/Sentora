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


def v(verdict, severity="MEDIUM", confidence=0.9):
    return types.SimpleNamespace(verdict=verdict, severity=severity,
                                 confidence=confidence)


# --------------------------------------------------------------------------
# The case that was missed
# --------------------------------------------------------------------------

def test_suspicious_at_the_observed_confidence_does_not_surface():
    """0.60 is what llama3.2:3b returned for every attack it noticed."""
    assert gating.surfaces(v("SUSPICIOUS", "MEDIUM", 0.60)) is False


def test_suspicious_at_the_threshold_surfaces():
    assert gating.surfaces(v("SUSPICIOUS", "MEDIUM", 0.75)) is True


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

@pytest.mark.parametrize("verdict,severity,confidence,expected", [
    ("CRITICAL",     "CRITICAL", 0.9,  True),
    ("CRITICAL",     "HIGH",     0.6,  True),
    ("CRITICAL",     "HIGH",     0.59, False),   # below the confidence gate
    ("CRITICAL",     "MEDIUM",   0.99, False),   # severity does not qualify
    ("SUSPICIOUS",   "LOW",      0.8,  True),    # severity is not consulted
    ("NOT_CRITICAL", "CRITICAL", 1.0,  False),
    ("INSUFFICIENT_DATA", "HIGH", 1.0, False),
])
def test_gate(verdict, severity, confidence, expected):
    assert gating.surfaces(v(verdict, severity, confidence)) is expected


def test_no_verdict_does_not_surface():
    assert gating.surfaces(None) is False


def test_a_malformed_confidence_does_not_surface():
    """Fail closed here: an unreadable confidence is not evidence of one."""
    assert gating.surfaces(v("CRITICAL", "HIGH", "not a number")) is False
    assert gating.surfaces(v("CRITICAL", "HIGH", None)) is False


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


def test_without_a_criterion_the_confidence_gate_still_applies():
    """The bypass is for a fact about the log, not for CRITICAL in general."""
    assert not gating.surfaces(vc(confidence=0.5, criterion="none"))
    assert gating.surfaces(vc(confidence=0.9, criterion="none"))


def test_severity_is_still_required():
    """A criterion match raises severity to at least HIGH in criteria.apply,
    so MEDIUM here means something overrode it and the verdict is incoherent."""
    assert not gating.surfaces(vc(severity="MEDIUM", confidence=0.9, criterion="C1"))


def test_suspicious_gets_no_bypass():
    """`criteria.apply` clears the criterion when it is not supported, so a
    SUSPICIOUS verdict never carries a verified one - but if one ever appeared
    there it must not be enough on its own."""
    assert not gating.surfaces(
        vc(verdict="SUSPICIOUS", severity="MEDIUM", confidence=0.5, criterion="C1"))


def test_lowering_the_threshold_was_measured_and_rejected():
    """Between 0.60 and 0.90 the model's output is identical - it returns 0.50
    or 0.90 and nothing between - so moving the gate there changes nothing.
    Dropping to 0.50 gains one attack and admits six false alarms.

    Pinned so the next person to reach for the threshold sees that it was
    tried.
    """
    import inspect
    source = inspect.getsource(gating)
    assert "0.60 and 0.90 the output is identical" in source


def test_the_description_matches_the_rule():
    """It is printed in the eval report, so a stale description would
    misdescribe every run."""
    assert "verified criterion" in gating.describe()
