"""Every shipped rule is proved to fire, and proved not to fire on its near miss.

A detection rule is the one kind of code whose failure is silence. A broken
web handler returns an error; a broken rule returns nothing, which is exactly
what a rule with nothing to detect returns. The 23 rules in
`Sentora/conf/sigma/builtin` were written, reviewed and shipped, and until now
nothing had ever demonstrated that a single one of them matches a real event.

Three things are checked here, and the third is the one that catches the
mistakes nobody expects:

  fires        the rule matches an event of the kind it was written for
  holds off    it does not match the benign command it most resembles - the
               false positive its own author wrote down in `falsepositives`
  stays put    it does not match *another* rule's sample

That last one is the false-positive matrix. Broadening a rule is the easiest
edit to make and the hardest to review: `CommandLine|contains: bash` looks
reasonable in isolation and turns nine unrelated rules into noise. Overlaps
that are genuinely correct are declared in the sample file, so an overlap is
something somebody decided rather than something that happened.

Samples live beside the tests rather than inside the rules. The rules ship to
every endpoint, and test fixtures are not configuration.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from core import sigma_loader

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE_DIR = ROOT / "Sentora" / "conf" / "sigma" / "builtin"
SAMPLE_DIR = pathlib.Path(__file__).resolve().parent / "sigma_samples"


def _load_rules() -> dict:
    """Every shipped rule, keyed by filename stem."""
    result = sigma_loader.load_dir(RULE_DIR)
    assert not result.rejected, (
        f"rules that do not compile are rules that are not running: "
        f"{result.rejected}"
    )
    return {pathlib.Path(r.source_path).stem: r for r in result.rules}


BENIGN_FILE = SAMPLE_DIR / "benign.yml"


def _load_samples() -> dict:
    samples: dict = {}
    for path in sorted(SAMPLE_DIR.glob("*.yml")):
        if path == BENIGN_FILE:
            continue                      # not keyed by rule; see _load_benign
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for stem, spec in loaded.items():
            assert stem not in samples, f"{stem} has samples in two files"
            spec["_file"] = path.name
            samples[stem] = spec
    return samples


def _load_benign() -> list:
    loaded = yaml.safe_load(BENIGN_FILE.read_text(encoding="utf-8")) or {}
    return loaded.get("events") or []


RULES = _load_rules()
SAMPLES = _load_samples()
BENIGN = _load_benign()


# --------------------------------------------------------------------------
# The rules load at all
# --------------------------------------------------------------------------

def test_the_scan_found_the_rules():
    """If this collapses to zero, every test below passes vacuously."""
    assert len(RULES) >= 20, f"only found {sorted(RULES)}"


def test_every_rule_has_evidence():
    """A rule may not ship without something that proves it works."""
    missing = sorted(set(RULES) - set(SAMPLES))
    assert not missing, (
        f"no sample for {missing} - add one to tests/sigma_samples/ rather "
        f"than shipping a rule nothing has ever fired"
    )


def test_every_sample_belongs_to_a_rule():
    """A sample for a rule that no longer exists passes forever and proves
    nothing, which is worse than no sample at all."""
    orphaned = sorted(set(SAMPLES) - set(RULES))
    assert not orphaned, f"samples for rules that do not exist: {orphaned}"


# --------------------------------------------------------------------------
# It fires
# --------------------------------------------------------------------------

def _cases(kind: str):
    for stem, spec in sorted(SAMPLES.items()):
        for case in spec.get(kind) or []:
            yield pytest.param(stem, case["name"], case["event"],
                               id=f"{stem}-{case['name'].replace(' ', '-')}")


@pytest.mark.parametrize("stem,name,event", list(_cases("matches")))
def test_the_rule_fires_on_what_it_was_written_for(stem, name, event):
    rule = RULES[stem]
    assert rule.matches(event), (
        f"{rule.title} does not fire on {name!r}. The rule ships, the console "
        f"counts it as coverage, and it detects nothing."
    )


@pytest.mark.parametrize("stem,name,event", list(_cases("ignores")))
def test_the_rule_holds_off_on_the_thing_it_resembles(stem, name, event):
    rule = RULES[stem]
    assert not rule.matches(event), (
        f"{rule.title} fires on {name!r}, which is benign. A rule that pages "
        f"on ordinary administration gets muted, and a muted rule is worse "
        f"than an absent one because the console still counts it."
    )


# --------------------------------------------------------------------------
# It stays in its lane
# --------------------------------------------------------------------------

@pytest.mark.parametrize("stem,name,event", list(_cases("matches")))
def test_no_other_rule_fires_on_this_sample(stem, name, event):
    """The false-positive matrix.

    Broadening a rule is the easiest edit to make and the hardest to review.
    An overlap that is genuinely right - two credential-access rules seeing
    one command line - is declared in `also_fires`, so it reads as a decision.
    """
    allowed = set(SAMPLES[stem].get("also_fires") or [])
    unexpected = sorted(
        other for other, rule in RULES.items()
        if other != stem and other not in allowed and rule.matches(event)
    )
    assert not unexpected, (
        f"{sorted(unexpected)} also fire on {stem}'s {name!r}. Either the "
        f"rule is too broad, or the overlap is correct and belongs in "
        f"`also_fires` in {SAMPLES[stem]['_file']}."
    )


@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_declared_overlaps_actually_happen(stem):
    """An `also_fires` entry that no longer overlaps is a silent exemption:
    it would keep excusing a rule that has since been narrowed, and hide the
    day it broadens again."""
    declared = set(SAMPLES[stem].get("also_fires") or [])
    if not declared:
        return
    unknown = sorted(declared - set(RULES))
    assert not unknown, f"{stem} excuses rules that do not exist: {unknown}"

    actual = set()
    for case in SAMPLES[stem].get("matches") or []:
        actual |= {other for other, rule in RULES.items()
                   if other != stem and rule.matches(case["event"])}
    stale = sorted(declared - actual)
    assert not stale, (
        f"{stem} declares an overlap with {stale} that no longer happens; "
        f"remove it, or the exemption outlives the reason for it"
    )


# --------------------------------------------------------------------------
# The samples themselves have to be worth something
# --------------------------------------------------------------------------

@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_a_sample_proves_both_directions(stem):
    """A rule with no near miss is a rule nobody has thought about in the
    direction that produces 3am pages."""
    spec = SAMPLES[stem]
    assert spec.get("matches"), f"{stem} has no event that must fire it"
    assert spec.get("ignores"), (
        f"{stem} has no benign near miss. Fires-on-the-right-thing is half a "
        f"test; the half that gets rules muted is the other one."
    )


@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_the_near_miss_resembles_the_real_thing(stem):
    """A negative that shares no field with the positive tests nothing - an
    empty event would pass. It has to be the same *kind* of event."""
    fields = lambda cases: {k for c in cases for k in c["event"]}
    positive = fields(SAMPLES[stem]["matches"])
    negative = fields(SAMPLES[stem]["ignores"])
    assert positive & negative, (
        f"{stem}'s near miss shares no field with its positive, so it is not "
        f"a near miss - any unrelated event would pass"
    )


# --------------------------------------------------------------------------
# The floor underneath every rule
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name,event",
    [pytest.param(c["name"], c["event"], id=c["name"].replace(" ", "-"))
     for c in BENIGN])
def test_no_rule_fires_on_ordinary_activity(name, event):
    """A rule's own `ignores` is that rule arguing with its own near miss.
    This is the shared floor, and it catches what a per-rule sample cannot: a
    rule broadened to `CommandLine|contains: bash` still passes its own tests
    and then pages on every shell on the estate."""
    firing = sorted(s for s, r in RULES.items() if r.matches(event))
    assert not firing, (
        f"{firing} fire on {name!r}, which happens thousands of times a day. "
        f"A rule that pages on ordinary administration gets muted, and a muted "
        f"rule is worse than an absent one because the console still counts it."
    )


def test_the_benign_floor_is_not_empty():
    """It would pass vacuously, and it is the check most worth having when
    somebody is in a hurry to add a rule."""
    assert len(BENIGN) >= 10, f"only {len(BENIGN)} benign events"


def test_every_rule_declares_a_technique():
    """ATT&CK coverage is read off the rules themselves. A rule with no
    technique is invisible to the coverage report while still firing."""
    missing = sorted(s for s, r in RULES.items() if not r.techniques)
    assert not missing, f"no attack.tNNNN tag on: {missing}"
