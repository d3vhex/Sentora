"""Tests for the structured verdict schemas.

These are what replaced brace-counting through model prose. The coercion
matters more than it looks: a small local model is loose with types, and
rejecting a whole verdict because confidence arrived as the string "0.85"
throws away a usable answer. Rejecting one because the model invented a
severity does not.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ai.schemas import (
    DeepAnalysis,
    DefensiveDecision,
    TriageVerdict,
    json_schema_for,
    narrative_of,
    render_summary,
)


# --------------------------------------------------------------------------
# Coercion
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("0.85", 0.85),
    (0.85, 0.85),
    (85, 0.85),        # "85" meaning percent is common enough to handle
    (None, 0.0),
    ("", 0.0),
    ("garbage", 0.0),
    (-1, 0.0),
    (2.5, 0.025),      # >1 is read as a percentage, then clamped
])
def test_confidence_is_coerced(raw, expected):
    v = TriageVerdict.model_validate({"confidence": raw})
    assert v.confidence == pytest.approx(expected, abs=1e-6)


def test_unknown_severity_falls_back_rather_than_failing():
    """A verdict is still useful when only the severity label is odd."""
    assert TriageVerdict.model_validate({"severity": "SUPER_BAD"}).severity == "INFO"
    assert TriageVerdict.model_validate({"severity": "high"}).severity == "HIGH"


def test_unknown_verdict_defaults_to_the_safe_side():
    """An unrecognised verdict must not become CRITICAL by accident."""
    assert TriageVerdict.model_validate({"verdict": "MAYBE"}).verdict == "NOT_CRITICAL"
    assert DefensiveDecision.model_validate({"verdict": "FIRE_ZE_MISSILES"}).verdict == "MONITOR"


def test_insufficient_data_is_a_real_verdict():
    """The model saying it cannot tell is an answer worth recording.

    `_lazy()` used to intercept exactly this and fabricate a narrative from
    the log's own fields instead.
    """
    assert TriageVerdict.model_validate({"verdict": "INSUFFICIENT_DATA"}).verdict == "INSUFFICIENT_DATA"
    assert DefensiveDecision.model_validate({"verdict": "INSUFFICIENT_DATA"}).verdict == "INSUFFICIENT_DATA"


@pytest.mark.parametrize("raw,expected", [
    (["T1055", "T1003"], ["T1055", "T1003"]),
    ("T1055, T1003", ["T1055", "T1003"]),   # model emitted a string, not a list
    (None, []),
    ([], []),
    ([" T1055 ", ""], ["T1055"]),
])
def test_list_fields_tolerate_a_comma_string(raw, expected):
    assert DeepAnalysis.model_validate({"techniques": raw}).techniques == expected


def test_empty_object_validates_to_safe_defaults():
    """A model returning `{}` should yield a benign verdict, not an exception
    that loses the event."""
    v = TriageVerdict.model_validate({})
    assert v.verdict == "NOT_CRITICAL"
    assert v.severity == "INFO"
    assert v.confidence == 0.0


# --------------------------------------------------------------------------
# Schema handed to Ollama
# --------------------------------------------------------------------------

@pytest.mark.parametrize("worker", ["automation", "manual", "defensive"])
def test_schema_is_flat_enough_for_ollama(worker):
    """Nested models produce $ref/$defs, which Ollama's structured output
    handles inconsistently across versions. Keep them flat."""
    schema = json_schema_for(worker)
    assert schema is not None
    assert "$defs" not in schema, f"{worker} schema gained a nested model"
    assert json.dumps(schema)  # must be serialisable for the request body


@pytest.mark.parametrize("worker", ["automation", "manual", "defensive"])
def test_every_field_is_required_in_the_constrained_schema(worker):
    """The bug this exists for.

    Pydantic leaves any field with a default out of `required`. Under
    schema-constrained generation the model then skips those fields, and
    verdicts came back severity=INFO confidence=0.00 on events the same model
    had rated HIGH/0.90 minutes earlier — because it never emitted the keys
    and the defaults filled in.
    """
    schema = json_schema_for(worker)
    props = set(schema["properties"])
    required = set(schema.get("required", []))
    assert props == required, f"{worker}: not required -> {sorted(props - required)}"


@pytest.mark.parametrize("worker", ["automation", "manual", "defensive"])
def test_schema_forbids_extra_keys(worker):
    assert json_schema_for(worker).get("additionalProperties") is False


def test_defaults_still_apply_when_validating():
    """Required in the schema, defaulted in validation. The defaults keep a
    partial repair round or a stale cached value usable; they just must not
    reach the model as permission to omit fields."""
    v = TriageVerdict.model_validate({"verdict": "CRITICAL"})
    assert v.severity == "INFO"
    assert v.confidence == 0.0


def test_unknown_worker_has_no_schema():
    assert json_schema_for("nonexistent") is None


@pytest.mark.parametrize("worker,field", [
    ("automation", "verdict"),
    ("automation", "confidence"),
    ("manual", "techniques"),
    ("defensive", "action"),
    ("defensive", "target"),
])
def test_schema_exposes_the_fields_the_worker_reads(worker, field):
    assert field in json_schema_for(worker)["properties"]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def test_narrative_prefers_summary_then_reason():
    assert narrative_of(TriageVerdict(summary="a thing happened")) == "a thing happened"
    assert narrative_of(DefensiveDecision(reason="because of X")) == "because of X"
    assert narrative_of(TriageVerdict()) == ""


def test_render_summary_includes_the_stored_fields():
    line = render_summary(
        TriageVerdict(verdict="CRITICAL", severity="HIGH", confidence=0.91,
                      indicator="T1055 injection", summary="LSASS access observed",
                      recommended_action="KILL_PROCESS"),
        "AUTO",
    )
    assert "[AUTO]" in line
    assert "[HIGH]" in line
    assert "conf=0.91" in line
    assert "T1055 injection" in line
    assert "LSASS access observed" in line
    assert "-> KILL_PROCESS" in line


def test_render_summary_omits_noise():
    """`none` indicators and a MONITOR action add nothing to the line."""
    line = render_summary(
        TriageVerdict(indicator="none", recommended_action="MONITOR", summary="routine"),
        "AUTO REVIEW",
    )
    assert "none" not in line
    assert "->" not in line
    assert "routine" in line


def test_render_summary_survives_an_empty_verdict():
    """Cards used to render chips and no body. The line must never be a bare
    stub like `[AI DEFENSIVE] [INFO] -> none`."""
    line = render_summary(DefensiveDecision(), "AI DEFENSIVE")
    assert line.startswith("[AI DEFENSIVE] [INFO] conf=0.00")
    assert "->" not in line


def test_payload_round_trips():
    """`payload` is stored as JSON and read back by the UI, so it has to
    survive the trip."""
    original = DeepAnalysis(verdict="SUSPICIOUS", severity="MEDIUM", confidence=0.6,
                            techniques=["T1059"], iocs=["1.2.3.4"],
                            summary="powershell download cradle",
                            next_steps=["pull the parent process tree"])
    assert DeepAnalysis.model_validate_json(original.model_dump_json()) == original
