"""Scoring for AI triage runs against a labelled corpus.

Every prompt change so far has been made blind. A wording tweak might have
improved triage or wrecked it, and the only feedback available was reading a
handful of insight cards and forming an impression. This is what replaces
that impression with a number.

Why not accuracy
----------------
Accuracy is close to useless here. Real telemetry is overwhelmingly benign, so
a model that answers NOT_CRITICAL to everything scores ~97% and detects
nothing. `summarise()` therefore reports per-class precision and recall, and
treats the two error directions as the different problems they are:

- **A missed CRITICAL** is an intrusion nobody looked at.
- **A false CRITICAL** is alert fatigue, which eventually causes the first.

Recall on the dangerous classes is the number to watch; precision is the cost
of getting it.

Unusable verdicts are counted, never silently excluded. A model that fails to
answer on a third of the corpus is not an 80%-accurate model, and averaging
over only the cases it managed would say exactly that.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Verdicts that mean "a human should look at this". Recall over this set is
# the headline number: these are the cases where being wrong is expensive.
ESCALATING = {"CRITICAL", "SUSPICIOUS", "ACT"}

# The model could not produce a usable verdict. Distinct from any real answer.
NO_VERDICT = "NO_VERDICT"


@dataclass
class Case:
    """One labelled event and what the model said about it."""
    id: str
    expected: str
    actual: str
    latency_s: float | None = None
    note: str = ""
    # Whether production would have shown this to an analyst, per ai/gating.
    # A verdict alone is not a detection: the worker also requires a severity
    # and a confidence, and a run can score well on verdicts while surfacing
    # nothing at all. Defaults to None for runs saved before this existed.
    surfaced: bool | None = None
    # Kept so threshold questions can be answered without re-running the
    # model, and so the report can say when confidence is not being computed
    # at all - see EvalReport.confidence_is_anchored.
    severity: str | None = None
    confidence: float | None = None

    @property
    def correct(self) -> bool:
        return self.expected == self.actual


@dataclass
class ClassScore:
    label: str
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def support(self) -> int:
        """How many cases in the corpus actually carry this label.

        Reported alongside every rate, because a precision of 1.00 over two
        examples is not evidence of anything.
        """
        return self.true_positive + self.false_negative

    @property
    def precision(self) -> float | None:
        predicted = self.true_positive + self.false_positive
        return self.true_positive / predicted if predicted else None

    @property
    def recall(self) -> float | None:
        return self.true_positive / self.support if self.support else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


@dataclass
class EvalReport:
    cases: list[Case] = field(default_factory=list)
    by_class: dict[str, ClassScore] = field(default_factory=dict)
    confusion: dict[tuple[str, str], int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.cases)

    @property
    def no_verdict(self) -> int:
        """Cases where the model produced nothing usable."""
        return sum(1 for c in self.cases if c.actual == NO_VERDICT)

    @property
    def accuracy(self) -> float | None:
        """Present for completeness, but see the module docstring: on this
        distribution a do-nothing model scores well here."""
        return sum(1 for c in self.cases if c.correct) / self.total if self.total else None

    @property
    def confidence_is_anchored(self) -> float | None:
        """The single confidence the model returned, if it returned only one.

        llama3.2:3b answered exactly 0.60 to every attack it flagged. That is
        not a calibrated probability, it is a number the model has settled on,
        and a gate built from it will behave arbitrarily: move the threshold a
        hundredth either side and every detection flips at once.

        Worth knowing before anyone tunes AI_SUS_CONF against it.
        """
        seen = {c.confidence for c in self.cases
                if c.confidence is not None and c.actual != NO_VERDICT}
        if len(seen) == 1 and len([c for c in self.cases
                                   if c.actual != NO_VERDICT]) > 2:
            return seen.pop()
        return None

    @property
    def surfaced_recall(self) -> float | None:
        """Of the events that should be escalated, how many an analyst would see.

        The number that describes the product. `escalation_recall` describes
        the model, and the two came apart badly: a rewritten prompt took
        escalation recall from 0% to 40% while every one of those detections
        came back SUSPICIOUS at confidence 0.60, just under the 0.75 the
        worker requires - so the analyst saw exactly as much as before, which
        was nothing.

        None when the run predates this field, rather than 0, because
        "not measured" and "measured zero" are different claims.
        """
        should = [c for c in self.cases if c.expected in ESCALATING]
        if not should or any(c.surfaced is None for c in should):
            return None
        return sum(1 for c in should if c.surfaced) / len(should)

    @property
    def constant_verdict(self) -> str | None:
        """The verdict this model gave to everything, if it gave one verdict.

        A model that answers the same thing regardless of input carries no
        information: its output is a constant function and cannot be a
        detection capability, however good its accuracy looks.

        This is not hypothetical. llama3.2:3b answered NOT_CRITICAL to all 15
        cases of the attack corpus - including an LSASS memory dump, which it
        summarised as "Routine logon event" - and to all 542 events it had
        processed in production. Accuracy read 33%, the five benign cases were
        all "correct", and the UI showed a steady stream of Reviewed cards.
        Nothing in the numbers said the layer was inert.

        Reported before recall, because when this is set every other figure is
        a description of the same fact.
        """
        answered = {c.actual for c in self.cases if c.actual != NO_VERDICT}
        if len(answered) == 1 and self.total > 1:
            return answered.pop()
        return None

    @property
    def escalation_recall(self) -> float | None:
        """Of the events that should have been escalated, how many were.

        The headline. A miss here is an intrusion nobody looked at.
        """
        should = [c for c in self.cases if c.expected in ESCALATING]
        if not should:
            return None
        return sum(1 for c in should if c.actual in ESCALATING) / len(should)

    @property
    def escalation_precision(self) -> float | None:
        """Of the events that were escalated, how many deserved it."""
        did = [c for c in self.cases if c.actual in ESCALATING]
        if not did:
            return None
        return sum(1 for c in did if c.expected in ESCALATING) / len(did)

    @property
    def missed(self) -> list[Case]:
        """Escalations the model failed to make, worst error first."""
        return [c for c in self.cases
                if c.expected in ESCALATING and c.actual not in ESCALATING]

    @property
    def spurious(self) -> list[Case]:
        """Escalations that were not warranted."""
        return [c for c in self.cases
                if c.actual in ESCALATING and c.expected not in ESCALATING]

    @property
    def median_latency(self) -> float | None:
        vals = sorted(c.latency_s for c in self.cases if c.latency_s is not None)
        if not vals:
            return None
        mid = len(vals) // 2
        return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def summarise(cases: list[Case]) -> EvalReport:
    """Score a completed run.

    Cases where the model gave no verdict stay in the denominator. Dropping
    them would let a model that fails half the time report the accuracy of the
    half it managed.
    """
    report = EvalReport(cases=list(cases))

    labels = {c.expected for c in cases} | {c.actual for c in cases}
    labels.discard(NO_VERDICT)          # not a prediction, so not a class
    for label in labels:
        report.by_class[label] = ClassScore(label=label)

    for c in cases:
        report.confusion[(c.expected, c.actual)] = \
            report.confusion.get((c.expected, c.actual), 0) + 1

        if c.expected == c.actual:
            report.by_class[c.expected].true_positive += 1
        else:
            if c.expected in report.by_class:
                report.by_class[c.expected].false_negative += 1
            # NO_VERDICT is a failure to answer, not a wrong answer, so it is
            # not charged as a false positive against any class.
            if c.actual in report.by_class:
                report.by_class[c.actual].false_positive += 1

    return report


def compare(baseline: EvalReport, candidate: EvalReport) -> dict:
    """Did a prompt or model change help?

    The question every prompt edit should have to answer. Reported as deltas
    on the two numbers that matter, plus which specific cases changed hands —
    an unchanged headline can still hide a swap of one detection for another.
    """
    def delta(a, b):
        return None if a is None or b is None else round(b - a, 4)

    base_ids = {c.id: c for c in baseline.cases}
    newly_missed, newly_caught = [], []
    for c in candidate.cases:
        was = base_ids.get(c.id)
        if not was:
            continue
        was_ok = was.actual in ESCALATING
        now_ok = c.actual in ESCALATING
        if c.expected in ESCALATING and was_ok and not now_ok:
            newly_missed.append(c.id)
        elif c.expected in ESCALATING and not was_ok and now_ok:
            newly_caught.append(c.id)

    return {
        "escalation_recall": delta(baseline.escalation_recall, candidate.escalation_recall),
        "escalation_precision": delta(baseline.escalation_precision, candidate.escalation_precision),
        "no_verdict": candidate.no_verdict - baseline.no_verdict,
        "newly_missed": newly_missed,
        "newly_caught": newly_caught,
        # A change that catches three and drops three leaves recall flat while
        # changing what the platform sees. Stated so it cannot pass as neutral.
        "regression": bool(newly_missed),
    }
