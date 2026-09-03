"""ATT&CK techniques as a hierarchy, and tactics as an order.

Two things this exists to stop.

**Techniques compared as opaque strings.** The coverage endpoint did
`set(covered) - set(observed)`, so a rule tagged `T1003.001` and an event
carrying `T1003` never matched: one landed in "covered but never seen", the
other in "seen with nothing covering it", and both were wrong. Those two lists
are the only ones an operator acts on.

**Coverage claimed upwards.** Detecting `T1003.001` (LSASS memory) says
nothing about `T1003.003` (the AD database) - they are different actions with
different telemetry, and the rule for one will never fire on the other. So
covering a sub-technique gives its parent *partial* coverage and never full,
while a rule tagged with a bare parent does claim the whole thing. The
asymmetry is the point: rolled-up coverage that ignores it is how a heatmap
turns eleven green cells into a number nobody should trust.
"""

from __future__ import annotations

import re

#: MITRE Enterprise, in the order an intrusion tends to move through them.
#: Used to lay a host's activity out as a chain rather than a bag of tags -
#: "we saw execution and then persistence" is a different sentence from "we
#: saw persistence and then execution", and only one of them is a foothold.
TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

TACTIC_POSITION = {name: i for i, name in enumerate(TACTIC_ORDER)}

_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)


def normalise(value: str | None) -> str:
    """`" t1059.001 "` -> `"T1059.001"`, and anything else -> `""`.

    Total on purpose. Technique strings arrive from rule tags, from the AI
    path, and from a regex list, and a malformed one is a thing to drop
    rather than to raise on halfway through building a coverage report.
    """
    text = str(value or "").strip().upper()
    return text if _TECHNIQUE.match(text) else ""


def parent(technique: str) -> str:
    """`"T1059.001"` -> `"T1059"`. A parent is its own parent."""
    clean = normalise(technique)
    return clean.split(".")[0] if clean else ""


def is_subtechnique(technique: str) -> bool:
    return "." in normalise(technique)


def tactic_position(tactic: str) -> int:
    """Where a tactic sits in the chain; unknown tactics sort last.

    Unknown rather than dropped, because a tactic this file has not heard of
    is still something that happened on the host.
    """
    return TACTIC_POSITION.get(str(tactic or "").strip().lower(), len(TACTIC_ORDER))


def order_tactics(tactics) -> list[str]:
    """The tactics given, deduplicated and in kill-chain order."""
    seen = {t for t in (str(x or "").strip().lower() for x in tactics) if t}
    return sorted(seen, key=lambda t: (tactic_position(t), t))


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------

#: What a rule set says about one observed technique.
#:
#: `covered`   a rule addresses exactly this
#: `parent`    a rule addresses the whole parent technique, so this is
#:             included in what it claims
#: `sibling`   rules address other sub-techniques of the same parent and not
#:             this one. NOT coverage, and the state most likely to be read as
#:             coverage: the parent looks green while this specific action
#:             would go unnoticed.
#: `none`      nothing addresses it
COVERAGE_STATES = ("covered", "parent", "sibling", "none")


def coverage_of(technique: str, covered) -> str:
    """How well `covered` addresses one technique. See COVERAGE_STATES."""
    target = normalise(technique)
    if not target:
        return "none"

    index = {normalise(c) for c in covered}
    index.discard("")
    if target in index:
        return "covered"

    root = parent(target)
    if target != root and root in index:
        return "parent"
    if any(c != target and parent(c) == root for c in index):
        return "sibling"
    return "none"


def classify(covered, observed) -> dict:
    """Split observed techniques by how well the rule set addresses them.

    Returns one list per state in COVERAGE_STATES, each sorted.

    `sibling` is reported separately rather than folded into `none` because
    the two call for different work: nothing at all needs a rule written,
    while a covered sibling usually needs an existing rule widened, and
    somebody reading a rolled-up heatmap would see neither.
    """
    buckets: dict[str, list[str]] = {state: [] for state in COVERAGE_STATES}
    for raw in observed:
        clean = normalise(raw)
        if clean:
            buckets[coverage_of(clean, covered)].append(clean)
    return {state: sorted(set(values)) for state, values in buckets.items()}


def unseen(covered, observed) -> list[str]:
    """Techniques a rule addresses that have never fired here.

    Compared with the parent relation rather than as strings: a rule tagged
    `T1003.001` has been exercised by an event carrying `T1003`, and calling
    it unseen sends somebody to test a detection that is already working.
    """
    seen = {normalise(o) for o in observed}
    seen.discard("")
    roots = {parent(o) for o in seen}
    quiet = []
    for raw in covered:
        clean = normalise(raw)
        if not clean or clean in seen:
            continue
        # An observation at parent granularity counts as having exercised the
        # sub-technique rules underneath it; the reverse does not hold.
        if parent(clean) in seen:
            continue
        if clean in roots:
            continue
        quiet.append(clean)
    return sorted(set(quiet))


def rollup(techniques) -> dict:
    """Parent technique -> the sub-techniques given for it.

    The grid is drawn at parent granularity because that is the only way it
    fits on a screen. This keeps what was rolled up, so a cell can say "3 of
    the sub-techniques here" instead of implying the whole of T1003.
    """
    out: dict[str, set[str]] = {}
    for raw in techniques:
        clean = normalise(raw)
        if not clean:
            continue
        out.setdefault(parent(clean), set())
        if is_subtechnique(clean):
            out[parent(clean)].add(clean)
    return {root: sorted(children) for root, children in sorted(out.items())}
