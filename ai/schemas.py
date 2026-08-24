"""Structured verdict shapes for the AI workers.

Until now a verdict was a rendered string. `_format_insight` flattened the
model's answer into one line like

    [AI DEFENSIVE] [HIGH] conf=0.85 (T1055) ... -> BLOCK_IP

which went into `critical_summary`, and the UI then unpicked it again with a
regex. Everything downstream — severity chips, the shadow queue, filtering —
depended on parsing text back into fields that had been thrown away. A query
as simple as "CRITICAL verdicts above 0.8 confidence" could not be written,
because there were no columns to write it against.

These models are the shape instead. They are also handed to Ollama as a JSON
schema via the `format` parameter, so the model is *constrained* to produce
them rather than asked politely and parsed hopefully.

Kept deliberately flat — no nested models — so `model_json_schema()` emits a
schema without `$ref`/`$defs`, which is what Ollama's structured output
handles most reliably across versions.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# The model is allowed to say it cannot tell. That is a real answer and more
# useful than a fabricated one — see the note on _lazy() in ai_worker.py.
TriageOutcome = Literal["CRITICAL", "SUSPICIOUS", "NOT_CRITICAL", "INSUFFICIENT_DATA"]
DefensiveOutcome = Literal["ACT", "MONITOR", "IGNORE", "INSUFFICIENT_DATA"]


class _Base(BaseModel):
    """Shared coercion. Deliberately declares no fields.

    Small local models are loose with types: confidence arrives as "0.85", as
    85, or missing. Rejecting the whole verdict over that would throw away a
    usable answer, so coerce here and let genuinely malformed output fail.

    **Field order is load-bearing.** Under schema-constrained generation the
    model emits fields in schema order, and Pydantic puts base-class fields
    first. With `severity` and `confidence` declared here, every verdict began
    "INFO, 0.0" - the model committed to a judgement before it had written a
    word about what the event was, then wrote a summary consistent with the
    judgement it had already made.

    That is not a hypothesis. Asked the same LSASS dump directly, llama3.2:3b
    answered "Yes, this is evidence of credential dumping". Asked through this
    schema it answered NOT_CRITICAL, severity INFO, confidence 0.0, summary
    "Routine logon event" - and did so for all 542 events in production.

    So the subclasses declare their own fields, in the order they should be
    thought in: what happened, what it indicates, then how bad it is and how
    sure we are.
    """

    # check_fields=False: the fields live on the subclasses now, so the
    # validator cannot see them from here. See the ordering note above.
    @field_validator("confidence", mode="before", check_fields=False)
    @classmethod
    def _coerce_confidence(cls, v):
        if v is None or v == "":
            return 0.0
        try:
            f = float(v)
        except (TypeError, ValueError):
            return 0.0
        # "85" meaning 85% is common enough to be worth handling.
        if f > 1.0:
            f = f / 100.0
        return max(0.0, min(1.0, f))

    @field_validator("severity", mode="before", check_fields=False)
    @classmethod
    def _coerce_severity(cls, v):
        s = str(v or "INFO").strip().upper()
        return s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO"


class TriageVerdict(_Base):
    """Automation worker: is this event worth an analyst's attention?

    Declared in reasoning order - see the note on _Base. `summary` first, so
    the model has to say what the event is before it is allowed to say how
    serious it is.
    """

    # `observed` before `summary`, and both before the verdict.
    #
    # "Describe before judging" was not enough on its own. The model dutifully
    # filled `summary` first and filled it with the prompt's own criterion
    # text - "LSASS memory read, mimikatz, SAM/SYSTEM/NTDS hive copied or
    # exported" - on an EID 4672 SYSTEM logon, then rated it CRITICAL at
    # confidence 1.00 and recommended isolating the host.
    #
    # It had described something. It had not described the event. `observed`
    # is constrained to values copied out of the log, so the field it fills
    # first cannot be a technique it has recognised in the prompt.
    #
    # That fixed the wrong-content problem and left a calibration one. Given
    # an event it had summarised correctly as "vssadmin.exe delete shadows
    # /all /quiet", the model still answered SUSPICIOUS / MEDIUM / 0.5, and a
    # cleared audit log came back SUSPICIOUS / INFO. It was not failing to
    # understand; it was declining to use the top of a three-point scale,
    # which is what a 3B model does when asked to choose a label.
    #
    # `matched_criterion` turns that judgement into a lookup: name the
    # criterion the observed text matches, or "none". Naming one determines
    # the verdict, so the model is not being asked how bad something is - it
    # is being asked whether a string is in a list.
    observed: str = Field(default="", description=(
        "The ACTION the log records, copied from it: the full command line if "
        "there is one, otherwise the object acted on. Not the event ID alone, "
        "and not the parent process. No technique names - only text that "
        "appears in the log."))
    matched_criterion: str = Field(default="none", description=(
        "Which listed CRITICAL criterion the text in `observed` matches, "
        "quoted from that list, or 'none'. This decides the verdict."))
    summary: str = Field(default="", description=(
        "One sentence about this specific event, grounded in `observed`. "
        "<=180 characters."))
    indicator: str = Field(default="none", description="MITRE ID plus short label, or 'none'")
    verdict: TriageOutcome = "NOT_CRITICAL"
    severity: Severity = "INFO"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_action: str = Field(default="MONITOR")

    @field_validator("verdict", mode="before")
    @classmethod
    def _coerce_verdict(cls, v):
        s = str(v or "").strip().upper()
        return s if s in ("CRITICAL", "SUSPICIOUS", "NOT_CRITICAL", "INSUFFICIENT_DATA") else "NOT_CRITICAL"


class DeepAnalysis(_Base):
    """Manual worker: operator asked for this, so always produce something.

    Same ordering rule as TriageVerdict: narrative first, judgement after.
    """

    summary: str = Field(default="", description=(
        "2-4 sentence technical narrative of what the telemetry shows, "
        "written before any judgement is made about it."))
    kill_chain_stage: str = "none"
    techniques: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    verdict: TriageOutcome = "NOT_CRITICAL"
    severity: Severity = "INFO"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    next_steps: list[str] = Field(default_factory=list)

    @field_validator("verdict", mode="before")
    @classmethod
    def _coerce_verdict(cls, v):
        s = str(v or "").strip().upper()
        return s if s in ("CRITICAL", "SUSPICIOUS", "NOT_CRITICAL", "INSUFFICIENT_DATA") else "NOT_CRITICAL"

    @field_validator("techniques", "iocs", "next_steps", mode="before")
    @classmethod
    def _coerce_list(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            # Models sometimes emit "T1055, T1003" instead of an array.
            return [p.strip() for p in v.split(",") if p.strip()]
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        return []


class DefensiveDecision(_Base):
    """Defensive worker: should the platform do something, and what?

    Same ordering rule. This one dispatches SOAR actions, so a judgement made
    before the event has been described is the most expensive version of the
    problem.
    """

    event_name: str = Field(default="", description="The event, named: channel, ID and what it is")
    reason: str = Field(default="", description=(
        "Full sentence an analyst can paste into a ticket, describing what "
        "happened - written before the verdict below."))
    verdict: DefensiveOutcome = "MONITOR"
    severity: Severity = "INFO"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    action: str = "MONITOR"
    target: str = "none"

    @field_validator("verdict", mode="before")
    @classmethod
    def _coerce_verdict(cls, v):
        s = str(v or "").strip().upper()
        return s if s in ("ACT", "MONITOR", "IGNORE", "INSUFFICIENT_DATA") else "MONITOR"

    @field_validator("action", mode="before")
    @classmethod
    def _coerce_action(cls, v):
        return str(v or "MONITOR").strip().upper()


SCHEMAS: dict[str, type[_Base]] = {
    "automation": TriageVerdict,
    "manual": DeepAnalysis,
    "defensive": DefensiveDecision,
}


# Verdicts that satisfy the schema and still say nothing
# -----------------------------------------------------
# Constraining generation guarantees *shape*, not *sense*. A real stored row:
#
#   {"summary": "NOT_RELEVANT", "verdict": "NOT_CRITICAL",
#    "severity": "CRITICAL", "indicator": "NOT_INDOMINANT",
#    "confidence": 0.0, "recommended_action": "NOT_RECOMMENDED"}
#
# The model pattern-matched "answer NOT_something" into every field, coining
# "NOT_INDOMINANT" on the way. Every value is schema-valid. The verdict is
# still nonsense, and because `severity` happened to land on CRITICAL it
# surfaced anywhere the console filters on severity.
#
# Rewriting severity to agree with the verdict would be worse: that invents an
# answer the model did not give, which is the habit `_lazy()` was removed for.
# Instead this reports the contradiction, and the caller records an honest
# INSUFFICIENT_DATA row.
#
# Deliberately narrow. Only a flat contradiction between two fields counts.
# Low confidence on its own is a weak verdict, not an incoherent one, and
# discarding those would throw away the model's genuine uncertainty.

_ESCALATED = ("CRITICAL", "HIGH")


def coherence_problem(verdict: _Base) -> Optional[str]:
    """Describe how a verdict contradicts itself, or None if it holds together."""
    outcome = str(getattr(verdict, "verdict", "") or "").upper()
    severity = str(getattr(verdict, "severity", "") or "").upper()

    quiet = outcome in ("NOT_CRITICAL", "IGNORE")
    loud = outcome in ("CRITICAL", "SUSPICIOUS", "ACT")

    if quiet and severity in _ESCALATED:
        return f"verdict {outcome} contradicts severity {severity}"
    if loud and severity == "INFO":
        return f"verdict {outcome} contradicts severity INFO"
    return None


def constrained_schema(model: type[BaseModel]) -> dict:
    """JSON schema for Ollama's `format`, with every field required.

    Pydantic omits any field that has a default from `required`. Under
    schema-constrained generation the model is then free to skip those fields
    entirely — and it does. The result was verdicts arriving with severity
    INFO and confidence 0.00 on events the same model had previously rated
    HIGH/0.90, because it simply never emitted the keys and Pydantic filled in
    the defaults.

    The defaults still matter: they keep validation lenient when a repair
    round or a legacy cached value comes back partial. They just must not
    reach the model as permission to leave fields out.
    """
    schema = model.model_json_schema()
    schema["required"] = sorted(schema.get("properties", {}).keys())
    # Stops the model padding the object with keys we would silently discard.
    schema["additionalProperties"] = False
    return schema


def json_schema_for(worker_type: str) -> Optional[dict]:
    """JSON schema to hand Ollama's `format` parameter.

    Constraining the model beats parsing its prose: it removes the whole class
    of failure where a missing closing brace loses an entire verdict.
    """
    model = SCHEMAS.get(worker_type)
    return constrained_schema(model) if model else None


def narrative_of(verdict: _Base) -> str:
    """The prose field, whichever this verdict type calls it."""
    for field in ("summary", "reason"):
        text = (getattr(verdict, field, "") or "").strip()
        if text:
            return text
    return ""


def render_summary(verdict: _Base, prefix: str) -> str:
    """Human-readable one-liner for `critical_summary`.

    Still produced, but it is now *derived* from the stored columns rather
    than being the only record of them. Nothing reads it back to recover a
    field.
    """
    parts = [f"[{prefix}]", f"[{verdict.severity}]", f"conf={verdict.confidence:.2f}"]

    indicator = (getattr(verdict, "indicator", "") or getattr(verdict, "kill_chain_stage", "") or "").strip()
    if indicator and indicator.lower() != "none":
        parts.append(f"({indicator})")

    narrative = narrative_of(verdict)
    if narrative:
        parts.append(narrative)

    action = (getattr(verdict, "recommended_action", "") or getattr(verdict, "action", "") or "").strip().upper()
    if action and action not in ("MONITOR", "NONE", ""):
        parts.append(f"-> {action}")

    return " ".join(parts)
