"""Whether a verdict reaches an analyst.

One definition, used by the worker that files the row and by the eval harness
that scores the model. They had drifted apart, and the gap hid a result:

    eval   escalation recall 40%   (the model flagged 4 of 10 attacks)
    live   0 of 542 events surfaced

The eval scored the raw verdict. Production also requires a severity and a
confidence, and the model answered SUSPICIOUS / MEDIUM / 0.60 to every attack
it noticed - just under the 0.75 that SUSPICIOUS needs. Every one of those
detections was filed as a quiet `Reviewed_` row.

A harness that measures something the product does not do will report progress
that nobody experiences. So `surfaces()` lives here and both call it.

On the thresholds themselves: the model returned exactly 0.60 on all four
detections. That is not calibration, it is an anchor, and a gate built on a
number the model is not really computing will behave arbitrarily. Treat the
defaults as a placeholder until there is enough labelled data to choose them
from a curve.
"""

from __future__ import annotations

import os

CRITICAL_CONFIDENCE = float(os.getenv("AI_CRIT_CONF", "0.6"))
SUSPICIOUS_CONFIDENCE = float(os.getenv("AI_SUS_CONF", "0.75"))

ESCALATING_SEVERITIES = ("CRITICAL", "HIGH")


def surfaces(verdict) -> bool:
    """True if this verdict is shown to an analyst rather than filed quietly.

    Mirrors the `Realtime_` / `Reviewed_` split in ai_worker.handle_automation.
    Threat-intel matches surface regardless and are handled by the caller;
    this covers the model's own judgement only.
    """
    if verdict is None:
        return False

    outcome = str(getattr(verdict, "verdict", "") or "").upper()
    severity = str(getattr(verdict, "severity", "") or "").upper()
    try:
        confidence = float(getattr(verdict, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0

    if outcome == "CRITICAL":
        return severity in ESCALATING_SEVERITIES and confidence >= CRITICAL_CONFIDENCE
    if outcome == "SUSPICIOUS":
        return confidence >= SUSPICIOUS_CONFIDENCE
    return False


def describe() -> str:
    """The gate in words, for reports that need to say what they measured."""
    return (f"CRITICAL needs severity CRITICAL/HIGH and confidence "
            f">={CRITICAL_CONFIDENCE}; SUSPICIOUS needs confidence "
            f">={SUSPICIOUS_CONFIDENCE}")
