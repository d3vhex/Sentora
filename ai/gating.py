"""Whether a verdict reaches an analyst.

One definition, used by the worker that files the row and by the eval harness
that scores the model. They had drifted apart, and the gap hid a result:

    eval   escalation recall 40%   (the model flagged 4 of 10 attacks)
    live   0 of 542 events surfaced

The eval scored the raw verdict. Production also applied a gate, and the model
answered just under it on every detection, so each one was filed as a quiet
`Reviewed_` row. A harness that measures something the product does not do
reports progress nobody experiences, so `surfaces()` lives here and both call
it.

Confidence is not consulted, and that is the whole design
---------------------------------------------------------
The gate used to be a confidence threshold. Two rounds of measurement took it
apart:

    Six CRITICAL verdicts were held at 0.50 - an LSASS dump, a SAM hive
    export, shadow copies being deleted - and a seventh at 0.00. Every benign
    case also came back at 0.50.

    Moving the threshold changes nothing between 0.60 and 0.90, because the
    model emits 0.50 or 0.90 and almost nothing in between.

Then, over 29 cases including ten real events:

    Every one of the nine attacks that surfaced had a verified criterion.
    The confidence path contributed no detection that evidence did not
    already carry.

    Both false alarms that reached an analyst got there on confidence alone -
    SUSPICIOUS / CRITICAL / 0.80 on two Docker container lifecycle events,
    this platform restarting its own containers.

So the number was admitting noise and catching nothing. The gate now asks one
question: does the log contain the evidence? `ai/criteria` answers it by
looking, not by judging, and `AI_CRIT_CONF` / `AI_SUS_CONF` are read only to
warn that they no longer do anything.

On SUSPICIOUS
-------------
The model's SUSPICIOUS label scored precision 0.00 and recall 0.00 on that
corpus - it never applied it to a case that deserved it, and never withheld it
from one that did not. It can use the top of the scale and not the middle.

`criteria.apply` promotes a supported criterion to CRITICAL, so in practice a
SUSPICIOUS verdict never carries verified evidence and never surfaces. That is
deliberate rather than incidental: the middle of the scale is real, and it
comes from the layers that can be checked - a Sigma rule at MEDIUM, or a
correlation window - not from asking a 3B model to feel uncertain.
"""

from __future__ import annotations

import logging
import os

ESCALATING_SEVERITIES = ("CRITICAL", "HIGH")

# Read, compared, and otherwise unused. Silently ignoring configuration
# somebody deliberately set is its own bug class, so a non-default value says
# so once at import rather than behaving as though it had been applied.
CRITICAL_CONFIDENCE = float(os.getenv("AI_CRIT_CONF", "0.6"))
SUSPICIOUS_CONFIDENCE = float(os.getenv("AI_SUS_CONF", "0.75"))

if (CRITICAL_CONFIDENCE, SUSPICIOUS_CONFIDENCE) != (0.6, 0.75):
    logging.getLogger(__name__).warning(
        "AI_CRIT_CONF/AI_SUS_CONF are set but no longer affect anything: the "
        "gate asks whether the log contains the evidence, not how confident "
        "the model felt. See ai/gating.py.")


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

    if outcome not in ("CRITICAL", "SUSPICIOUS"):
        return False
    if severity not in ESCALATING_SEVERITIES:
        # A criterion match raises severity to at least HIGH, so anything
        # lower means something overrode it and the verdict disagrees with
        # itself.
        return False
    return criterion_verified(verdict)


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
    return ("severity CRITICAL/HIGH and a criterion the log was checked "
            "against and found to support; model confidence is not consulted")
