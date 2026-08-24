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
