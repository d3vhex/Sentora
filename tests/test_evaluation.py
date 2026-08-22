"""Tests for eval scoring.

The scoring is where an eval harness lies to you if it is going to. A metric
that flatters the model is worse than no metric, because it ends arguments
rather than settling them - so most of what is pinned here is the arithmetic
that makes a bad model look bad.
"""
from __future__ import annotations

import pytest

from core.evaluation import NO_VERDICT, Case, compare, summarise


def c(cid, expected, actual, **kw):
    return Case(id=cid, expected=expected, actual=actual, **kw)


# --------------------------------------------------------------------------
# The metric that matters
# --------------------------------------------------------------------------

def test_a_do_nothing_model_scores_well_on_accuracy_and_zero_on_recall():
    """Why accuracy is not the headline.

    Real telemetry is overwhelmingly benign. A model that answers
    NOT_CRITICAL to everything is right most of the time and detects nothing;
    the report has to make that obvious rather than average it away.
    """
    cases = [c(f"n{i}", "NOT_CRITICAL", "NOT_CRITICAL") for i in range(97)]
    cases += [c(f"crit{i}", "CRITICAL", "NOT_CRITICAL") for i in range(3)]

    r = summarise(cases)
    assert r.accuracy == pytest.approx(0.97)
    assert r.escalation_recall == 0.0          # caught nothing
    assert len(r.missed) == 3


def test_escalation_recall_counts_any_escalating_verdict():
    """SUSPICIOUS instead of CRITICAL is not a miss. The event reached a
    human, which is what recall is measuring."""
    r = summarise([
        c("1", "CRITICAL", "SUSPICIOUS"),
        c("2", "CRITICAL", "ACT"),
        c("3", "CRITICAL", "NOT_CRITICAL"),
    ])
    assert r.escalation_recall == pytest.approx(2 / 3)


def test_escalation_precision_is_the_cost_of_recall():
    r = summarise([
        c("1", "CRITICAL", "CRITICAL"),
        c("2", "NOT_CRITICAL", "CRITICAL"),
        c("3", "NOT_CRITICAL", "CRITICAL"),
    ])
    assert r.escalation_precision == pytest.approx(1 / 3)
    assert len(r.spurious) == 2


# --------------------------------------------------------------------------
# Failures to answer
# --------------------------------------------------------------------------

def test_no_verdict_stays_in_the_denominator():
    """A model that fails on half the corpus is not as good as the half it
    managed. Excluding those cases would report exactly that."""
    r = summarise([
        c("1", "CRITICAL", "CRITICAL"),
        c("2", "CRITICAL", NO_VERDICT),
    ])
    assert r.total == 2
    assert r.no_verdict == 1
    assert r.accuracy == pytest.approx(0.5)
    assert r.escalation_recall == pytest.approx(0.5)


def test_no_verdict_is_a_miss_not_a_false_positive():
    """Failing to answer is not the same error as answering wrongly, and
    charging it as a false positive against a class it never predicted would
    misattribute the fault."""
    r = summarise([
        c("1", "CRITICAL", NO_VERDICT),
        c("2", "NOT_CRITICAL", "NOT_CRITICAL"),
    ])
    assert NO_VERDICT not in r.by_class
    assert r.by_class["CRITICAL"].false_negative == 1
    assert r.by_class["NOT_CRITICAL"].false_positive == 0


# --------------------------------------------------------------------------
# Per-class arithmetic
# --------------------------------------------------------------------------

def test_precision_and_recall_per_class():
    r = summarise([
        c("1", "CRITICAL", "CRITICAL"),
        c("2", "CRITICAL", "CRITICAL"),
        c("3", "CRITICAL", "NOT_CRITICAL"),
        c("4", "NOT_CRITICAL", "CRITICAL"),
    ])
    crit = r.by_class["CRITICAL"]
    assert (crit.true_positive, crit.false_positive, crit.false_negative) == (2, 1, 1)
    assert crit.precision == pytest.approx(2 / 3)
    assert crit.recall == pytest.approx(2 / 3)
    assert crit.f1 == pytest.approx(2 / 3)


def test_support_is_reported_so_small_samples_are_visible():
    """A precision of 1.00 over two examples is not evidence."""
    r = summarise([c("1", "SUSPICIOUS", "SUSPICIOUS")])
    assert r.by_class["SUSPICIOUS"].precision == 1.0
    assert r.by_class["SUSPICIOUS"].support == 1


def test_rates_are_none_not_zero_when_undefined():
    """A class the model never predicted has undefined precision. Reporting
    0.0 would read as 'always wrong' rather than 'never tried'."""
    r = summarise([c("1", "CRITICAL", "NOT_CRITICAL")])
    assert r.by_class["CRITICAL"].precision is None
    assert r.by_class["CRITICAL"].recall == 0.0


def test_empty_corpus_does_not_divide_by_zero():
    r = summarise([])
    assert r.total == 0
    assert r.accuracy is None
    assert r.escalation_recall is None


# --------------------------------------------------------------------------
# Comparing two runs
# --------------------------------------------------------------------------

def test_a_swap_of_equal_size_is_still_a_regression():
    """The case the comparison exists for.

    Catching three new detections while losing three others leaves recall
    flat. Reading that as neutral would let a change quietly alter what the
    platform sees.
    """
    baseline = summarise([
        c("a", "CRITICAL", "CRITICAL"),
        c("b", "CRITICAL", "NOT_CRITICAL"),
    ])
    candidate = summarise([
        c("a", "CRITICAL", "NOT_CRITICAL"),
        c("b", "CRITICAL", "CRITICAL"),
    ])
    diff = compare(baseline, candidate)

    assert diff["escalation_recall"] == 0.0     # headline unchanged
    assert diff["newly_missed"] == ["a"]
    assert diff["newly_caught"] == ["b"]
    assert diff["regression"] is True


def test_a_clean_improvement_is_not_flagged():
    baseline = summarise([c("a", "CRITICAL", "NOT_CRITICAL")])
    candidate = summarise([c("a", "CRITICAL", "CRITICAL")])
    diff = compare(baseline, candidate)
    assert diff["escalation_recall"] == pytest.approx(1.0)
    assert diff["regression"] is False


def test_comparison_reports_a_rise_in_unanswered_cases():
    baseline = summarise([c("a", "NOT_CRITICAL", "NOT_CRITICAL")])
    candidate = summarise([c("a", "NOT_CRITICAL", NO_VERDICT)])
    assert compare(baseline, candidate)["no_verdict"] == 1


def test_cases_absent_from_the_baseline_are_ignored():
    """Adding corpus entries must not register as newly caught or missed."""
    baseline = summarise([c("a", "CRITICAL", "CRITICAL")])
    candidate = summarise([
        c("a", "CRITICAL", "CRITICAL"),
        c("new", "CRITICAL", "NOT_CRITICAL"),
    ])
    diff = compare(baseline, candidate)
    assert diff["newly_missed"] == []
    assert diff["regression"] is False
