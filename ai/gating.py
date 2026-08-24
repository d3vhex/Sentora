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

    # A verified criterion is not model output. `ai/criteria.apply` only
    # leaves a criterion named here when the log itself contains that
    # criterion's markers, which is a fact about the event rather than the
    # model's opinion of it - so the confidence gate does not apply.
    #
    # This is not a loosening for its own sake. Measured on the attack corpus:
    # six CRITICAL verdicts whose severity was also CRITICAL were blocked at
    # confidence 0.50, including an LSASS dump, a SAM hive export and shadow
    # copies being deleted. A seventh sat at 0.00. Meanwhile every benign case
    # also came back at 0.50 - the number carries no signal in either
    # direction, so gating real detections on it discards them and admits
    # nothing.
    #
    # Lowering the threshold instead was measured and does not work: between
    # 0.60 and 0.90 the output is identical, because the model returns 0.50 or
    # 0.90 and nothing in between. Dropping to 0.50 gains one attack and adds
    # six false alarms.
    if outcome == "CRITICAL":
        if severity not in ESCALATING_SEVERITIES:
            return False
        if criterion_verified(verdict):
            return True
        return confidence >= CRITICAL_CONFIDENCE
    if outcome == "SUSPICIOUS":
        return confidence >= SUSPICIOUS_CONFIDENCE
    return False


def criterion_verified(verdict) -> bool:
    """True when the log was checked and found to contain the evidence.

    `matched_criterion` is whatever the model wrote until `criteria.apply`
    runs; afterwards it names a criterion only if the markers were found, and
    is "none" otherwise. So this is a question about the log, not the model.
    """
    from ai.criteria import claimed_criterion
    return claimed_criterion(getattr(verdict, "matched_criterion", "")) is not None


def describe() -> str:
    """The gate in words, for reports that need to say what they measured."""
    return (f"CRITICAL needs severity CRITICAL/HIGH, and either a verified "
            f"criterion or confidence >={CRITICAL_CONFIDENCE}; SUSPICIOUS "
            f"needs confidence >={SUSPICIOUS_CONFIDENCE}")
