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


# --------------------------------------------------------------------------
# The harness has to be runnable
# --------------------------------------------------------------------------

def test_prompts_import_without_the_worker_runtime():
    """The eval harness must not need a RabbitMQ client to read a prompt.

    PROMPTS lived in ai_worker.py, which imports aio_pika and the SOAR module.
    `run_eval.py` pulled it from there, so the first real eval run died with
    ModuleNotFoundError on a host that had no broker client installed - the
    harness was unrunnable anywhere except inside the worker container, which
    is the one place nobody wants to iterate on prompts.

    Prompts are data. This pins them somewhere data can be read from.
    """
    import importlib
    import subprocess
    import sys
    import textwrap

    # A subprocess, not an import: aio_pika may already be in this process's
    # sys.modules via another test, which would make the check pass while the
    # real failure remained.
    src = textwrap.dedent("""
        import sys
        from ai.prompts import PROMPTS
        assert set(PROMPTS) >= {"automation", "manual", "defensive"}, sorted(PROMPTS)
        heavy = [m for m in ("aio_pika", "mysql.connector", "sanic") if m in sys.modules]
        assert not heavy, f"ai.prompts dragged in {heavy}"
    """)
    r = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

    # And the harness reaches for that module rather than the worker.
    import pathlib
    run_eval = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "run_eval.py"
    text = run_eval.read_text(encoding="utf-8")
    assert "from ai.prompts import PROMPTS" in text
    assert "from ai_worker import" not in text


# --------------------------------------------------------------------------
# A model that answers the same thing to everything
# --------------------------------------------------------------------------

def test_a_constant_model_is_named_as_such():
    """The failure that a scoreboard hides.

    llama3.2:3b answered NOT_CRITICAL to all 15 cases of the attack corpus -
    including an LSASS memory dump it summarised as "Routine logon event" -
    and to all 542 events it had processed in production. Accuracy read 33%,
    every benign case was "correct", and the UI showed a steady stream of
    Reviewed cards. Nothing in the numbers said the layer was inert.

    A constant function carries no information. The report has to say so in
    words, because a reader scanning recall 0.00 next to precision 1.00 will
    conclude the model is cautious rather than absent.
    """
    cases = ([c(f"a{i}", "CRITICAL", "NOT_CRITICAL") for i in range(10)]
             + [c(f"b{i}", "NOT_CRITICAL", "NOT_CRITICAL") for i in range(5)])
    report = summarise(cases)
    assert report.constant_verdict == "NOT_CRITICAL"
    assert report.escalation_recall == 0.0


def test_a_model_that_discriminates_is_not_flagged():
    cases = [c("a", "CRITICAL", "CRITICAL"), c("b", "NOT_CRITICAL", "NOT_CRITICAL")]
    assert summarise(cases).constant_verdict is None


def test_one_case_is_not_evidence_of_constancy():
    """A single case is always 'constant'; that says nothing."""
    assert summarise([c("a", "CRITICAL", "CRITICAL")]).constant_verdict is None


def test_unusable_verdicts_do_not_count_as_an_answer():
    """A run where the model failed everywhere is a different problem, and
    run_eval already refuses to save it."""
    cases = [c(f"a{i}", "CRITICAL", NO_VERDICT) for i in range(5)]
    assert summarise(cases).constant_verdict is None


def test_constancy_is_reported_before_the_metrics():
    """Otherwise it reads as one number among several."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "scripts" / "run_eval.py").read_text(encoding="utf-8")
    assert "constant_verdict" in src
    assert src.index("ANSWERED") < src.index("Escalation recall")


def test_surfaced_recall_can_be_lower_than_escalation_recall():
    """The gap that hid a non-result: flagged is not seen."""
    cases = [Case(id="a", expected="CRITICAL", actual="SUSPICIOUS", surfaced=False),
             Case(id="b", expected="CRITICAL", actual="CRITICAL", surfaced=True)]
    r = summarise(cases)
    assert r.escalation_recall == 1.0
    assert r.surfaced_recall == 0.5


def test_surfaced_recall_is_none_for_older_runs():
    """'Not measured' and 'measured zero' are different claims."""
    cases = [Case(id="a", expected="CRITICAL", actual="CRITICAL")]
    assert summarise(cases).surfaced_recall is None


def test_a_constant_confidence_is_called_out():
    """llama3.2:3b returned exactly 0.60 for every attack it flagged.

    That is not a calibrated probability. A gate built from it flips every
    detection at once when the threshold moves a hundredth, so the report has
    to say this before anyone tunes AI_SUS_CONF against it.
    """
    cases = [Case(id=f"c{i}", expected="CRITICAL", actual="SUSPICIOUS",
                  confidence=0.60) for i in range(5)]
    assert summarise(cases).confidence_is_anchored == 0.60


def test_varied_confidence_is_not_flagged():
    cases = [Case(id="a", expected="CRITICAL", actual="CRITICAL", confidence=0.9),
             Case(id="b", expected="CRITICAL", actual="SUSPICIOUS", confidence=0.6),
             Case(id="c", expected="NOT_CRITICAL", actual="NOT_CRITICAL", confidence=0.3)]
    assert summarise(cases).confidence_is_anchored is None


def test_anchoring_needs_more_than_two_answers():
    cases = [Case(id="a", expected="CRITICAL", actual="CRITICAL", confidence=0.6),
             Case(id="b", expected="CRITICAL", actual="CRITICAL", confidence=0.6)]
    assert summarise(cases).confidence_is_anchored is None


def test_runs_without_confidence_are_not_flagged():
    """Older saved runs have no confidence recorded."""
    cases = [Case(id=f"c{i}", expected="CRITICAL", actual="SUSPICIOUS") for i in range(5)]
    assert summarise(cases).confidence_is_anchored is None


def test_the_report_states_what_it_can_resolve():
    """Two runs of the same corpus, same prompt, temperature 0, returned 50%
    and 60% escalation recall. CPU inference reduces across threads in a
    non-deterministic order, so a near-tie flips.

    With ten positives, one flip is ten points - which is the whole size of
    the difference between two prompt versions I reported as an improvement.
    The report has to carry its own error bar, because a number without one
    invites exactly that reading.
    """
    cases = ([c(f"a{i}", "CRITICAL", "CRITICAL") for i in range(10)]
             + [c(f"b{i}", "NOT_CRITICAL", "NOT_CRITICAL") for i in range(9)])
    assert summarise(cases).resolution == pytest.approx(0.1)


def test_resolution_tightens_as_the_corpus_grows():
    few = summarise([c(f"a{i}", "CRITICAL", "CRITICAL") for i in range(4)])
    many = summarise([c(f"a{i}", "CRITICAL", "CRITICAL") for i in range(100)])
    assert few.resolution > many.resolution


def test_resolution_is_none_without_positives():
    """A corpus that cannot measure recall cannot state a resolution for it."""
    cases = [c(f"b{i}", "NOT_CRITICAL", "NOT_CRITICAL") for i in range(10)]
    assert summarise(cases).resolution is None


# --------------------------------------------------------------------------
# What the number was measured on
# --------------------------------------------------------------------------

def test_provenance_separates_constructed_positives_from_real_ones():
    """Recall on hand-written attacks and recall on real ones are different
    claims, and only one of them is a safety claim.

    They are separable here and impossible to separate once the figure has
    been quoted somewhere, which is why it travels with the report.
    """
    report = summarise([
        Case(id="a", expected="CRITICAL", actual="CRITICAL", constructed=True),
        Case(id="b", expected="CRITICAL", actual="CRITICAL", constructed=True),
        Case(id="c", expected="SUSPICIOUS", actual="SUSPICIOUS", constructed=False),
        Case(id="d", expected="NOT_CRITICAL", actual="NOT_CRITICAL", constructed=True),
    ])
    assert report.provenance == (2, 1, 0)


def test_a_run_saved_before_provenance_existed_counts_as_unknown():
    """Not as real. An absent flag is missing information, and defaulting it
    to the flattering answer is how a caveat gets quietly dropped."""
    report = summarise([Case(id="a", expected="CRITICAL", actual="CRITICAL")])
    assert report.provenance == (0, 0, 1)


def test_negatives_are_not_counted_in_provenance():
    """The caveat is about recall. Precision is measurable on real telemetry
    and the negatives here largely are real."""
    report = summarise([
        Case(id="a", expected="NOT_CRITICAL", actual="NOT_CRITICAL", constructed=True),
    ])
    assert report.provenance == (0, 0, 0)


def test_the_shipped_corpus_declares_provenance_on_every_case():
    """An unlabelled case would report as 'unknown' and dilute the caveat."""
    import json
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    corpus = root / "evals" / "corpus_attacks.jsonl"
    rows = [json.loads(l) for l in
            corpus.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows
    missing = [r["id"] for r in rows if "constructed" not in r]
    assert missing == [], f"cases with no provenance: {missing}"


def test_the_runner_carries_provenance_from_the_corpus():
    """The field exists on Case and in the corpus; the run is where they meet,
    and a run that drops it reports every positive as unknown."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    runner = (root / "scripts" / "run_eval.py").read_text(encoding="utf-8")
    assert 'constructed=row.get("constructed")' in runner


def test_the_report_states_the_caveat_rather_than_only_the_number():
    """A recall figure printed without it gets quoted without it."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    runner = (root / "scripts" / "run_eval.py").read_text(encoding="utf-8")
    assert "upper bound" in runner
    assert "report.provenance" in runner


def test_the_tracked_corpus_carries_no_real_machine_identifiers():
    """`evals/corpus.jsonl` is gitignored because it is one machine's real
    logs. `corpus_attacks.jsonl` is tracked, and a case copied across from the
    first without redaction puts a hostname and a SID into every checkout.

    That happened: a hard negative kept `DESKTOP-EVS8H9J` and the account SID
    it was observed under. The event is a good hard negative; the identifiers
    are not the reason it is one.
    """
    import json
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    blob = (root / "evals" / "corpus_attacks.jsonl").read_text(encoding="utf-8")

    hostnames = re.findall(r"DESKTOP-[A-Z0-9]+", blob)
    assert not hostnames, f"real hostname in a tracked corpus: {set(hostnames)}"

    # Machine and domain SIDs are S-1-5-21 followed by three large authorities.
    # The placeholder repdigits are fine; anything else came off a real host.
    for sid in re.findall(r"S-1-5-21-(\d+)-(\d+)-(\d+)", blob):
        assert all(len(set(part)) == 1 for part in sid), \
            f"real SID in a tracked corpus: S-1-5-21-{'-'.join(sid)}"

    rows = [json.loads(line) for line in blob.splitlines() if line.strip()]
    assert all(r.get("constructed") for r in rows), \
        "the tracked corpus should hold constructed cases only"


def test_the_builder_refuses_to_fold_real_telemetry_into_the_tracked_corpus():
    """The fold is useful locally - precision measured on real events is a
    claim about production - and it must not reach version control. The guard
    is in the builder rather than in a comment because a comment does not
    stop the command from running."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    builder = (root / "scripts" / "build_attack_corpus.py").read_text(encoding="utf-8")
    assert "refusing to fold real telemetry" in builder
    assert 'default=""' in builder, "the fold must be off by default"


def test_false_alarms_are_counted_after_the_gate_not_before():
    """The mirror of the bug that started this file.

    The harness once reported 40% escalation recall while production surfaced
    nothing, because it scored the verdict and the product also applies a
    gate. Escalation precision has the same gap in the other direction: a run
    can look poor on verdicts while the gate filters most of the noise before
    an analyst sees any of it.
    """
    report = summarise([
        Case(id="a", expected="NOT_CRITICAL", actual="SUSPICIOUS", surfaced=False),
        Case(id="b", expected="NOT_CRITICAL", actual="SUSPICIOUS", surfaced=True),
        Case(id="c", expected="NOT_CRITICAL", actual="NOT_CRITICAL", surfaced=False),
        Case(id="d", expected="CRITICAL", actual="CRITICAL", surfaced=True),
    ])
    # Three benign, two of them escalated by the model, one reaching an
    # analyst. Precision would say 33%; the console shows one alert.
    assert report.surfaced_false_alarms == (1, 3)


def test_runs_without_gate_information_report_no_false_alarm_count():
    """Rather than reporting zero, which would read as 'no false alarms'."""
    report = summarise([Case(id="a", expected="NOT_CRITICAL", actual="SUSPICIOUS")])
    assert report.surfaced_false_alarms is None


def test_a_corpus_with_no_negatives_reports_none():
    report = summarise([Case(id="a", expected="CRITICAL", actual="CRITICAL",
                             surfaced=True)])
    assert report.surfaced_false_alarms is None


def test_the_report_prints_what_the_gate_let_through():
    """A precision figure quoted without it describes a console nobody has."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    runner = (root / "scripts" / "run_eval.py").read_text(encoding="utf-8")
    assert "surfaced_false_alarms" in runner
    assert "False alarms shown" in runner
