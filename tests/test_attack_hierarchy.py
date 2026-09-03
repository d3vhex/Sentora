"""Techniques are a hierarchy, and coverage does not roll up freely.

The coverage endpoint compared techniques as opaque strings:

    "quiet":              set(covered) - set(observed)
    "uncovered_but_seen": set(observed) - set(covered)

So a rule tagged `T1003.001` and an event carrying `T1003` never matched each
other. One landed in "covered but never seen", the other in "seen with nothing
covering it", and both were wrong - and those two lists are the only ones an
operator acts on. One sends somebody to test a detection that already works;
the other sends them to write a rule that already exists.

The fix is not "compare parents". Detecting `T1003.001` (LSASS memory) says
nothing whatsoever about `T1003.003` (the AD database): different action,
different telemetry, and the rule for one will never fire on the other. So
coverage travels *down* from a parent and only partially *up* from a child,
and a heatmap that ignores the asymmetry turns eleven green cells into a
number nobody should trust.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from core import attack

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("T1059.001", "T1059.001"),
    ("t1059.001", "T1059.001"),
    ("  T1059  ", "T1059"),
    ("attack.t1059", ""),        # the tag form is stripped before this
    ("T105", ""),
    ("T10590", ""),
    ("T1059.1", ""),
    ("", ""),
    (None, ""),
    ("'; DROP TABLE siem_events; --", ""),
])
def test_a_technique_is_parsed_or_dropped(raw, expected):
    """Total on purpose. These arrive from rule tags, from the AI path and
    from a regex list, and a malformed one is a thing to drop rather than to
    raise on halfway through building a coverage report."""
    assert attack.normalise(raw) == expected


def test_a_parent_is_its_own_parent():
    assert attack.parent("T1059.001") == "T1059"
    assert attack.parent("T1059") == "T1059"
    assert attack.parent("nonsense") == ""


def test_subtechniques_are_recognised():
    assert attack.is_subtechnique("T1003.001")
    assert not attack.is_subtechnique("T1003")


# --------------------------------------------------------------------------
# The asymmetry
# --------------------------------------------------------------------------

def test_a_rule_for_the_parent_covers_its_children():
    """A rule tagged with a bare technique claims the whole thing."""
    assert attack.coverage_of("T1003.001", {"T1003"}) == "parent"


def test_a_rule_for_one_child_does_not_cover_its_sibling():
    """The case this file exists for. Detecting LSASS memory says nothing
    about the AD database - and if the two were folded together, the parent
    cell would be green while the second action went unnoticed."""
    assert attack.coverage_of("T1003.003", {"T1003.001"}) == "sibling"


def test_a_sibling_is_not_reported_as_uncovered_either():
    """`none` and `sibling` need different work: one needs a rule written,
    the other usually needs an existing rule widened. Folding them together
    loses the cheaper of the two fixes."""
    states = attack.classify({"T1003.001"}, {"T1003.003", "T1486"})
    assert states["sibling"] == ["T1003.003"]
    assert states["none"] == ["T1486"]


def test_an_exact_match_is_exact():
    assert attack.coverage_of("T1003.001", {"T1003.001"}) == "covered"


def test_nothing_related_is_nothing():
    assert attack.coverage_of("T1486", {"T1003.001", "T1059"}) == "none"


# --------------------------------------------------------------------------
# What has never fired
# --------------------------------------------------------------------------

def test_an_observation_at_parent_granularity_exercises_the_children():
    """A rule tagged T1003.001 has been exercised by an event carrying
    T1003. Calling it unseen sends somebody to test a detection that is
    already working."""
    assert attack.unseen({"T1003.001"}, {"T1003"}) == []


def test_a_rule_nothing_has_triggered_is_still_reported():
    assert attack.unseen({"T1486"}, {"T1003"}) == ["T1486"]


def test_an_exact_observation_is_not_quiet():
    assert attack.unseen({"T1059.004"}, {"T1059.004"}) == []


# --------------------------------------------------------------------------
# Tactics as an order
# --------------------------------------------------------------------------

def test_the_chain_runs_in_kill_chain_order():
    """"execution then persistence" and "persistence then execution" are
    different sentences, and only one of them is a foothold."""
    ordered = attack.order_tactics(
        ["impact", "execution", "initial-access", "persistence"])
    assert ordered == ["initial-access", "execution", "persistence", "impact"]


def test_an_unknown_tactic_sorts_last_rather_than_vanishing():
    """Something this file has not heard of still happened on the host."""
    ordered = attack.order_tactics(["impact", "wat", "execution"])
    assert ordered[-1] == "wat"


def test_the_order_is_the_enterprise_one():
    """Spot-checked at the ends rather than pinned in full, so adding a
    tactic does not fail this for the wrong reason."""
    assert attack.TACTIC_ORDER[0] == "reconnaissance"
    assert attack.TACTIC_ORDER[-1] == "impact"
    assert attack.tactic_position("initial-access") < attack.tactic_position("impact")


# --------------------------------------------------------------------------
# Rolling up for the grid
# --------------------------------------------------------------------------

def test_a_rolled_up_cell_remembers_what_it_rolled_up():
    """The grid is drawn at parent granularity because that is the only way
    it fits. Without this a cell implies the whole of T1003 when what is
    actually covered is one sub-technique of it."""
    rolled = attack.rollup(["T1003.001", "T1003.003", "T1059"])
    assert rolled["T1003"] == ["T1003.001", "T1003.003"]
    assert rolled["T1059"] == []


# --------------------------------------------------------------------------
# The endpoint uses it
# --------------------------------------------------------------------------

def _function(name: str) -> str:
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    return next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


def test_coverage_no_longer_subtracts_sets_of_strings():
    code = _function("get_attack_coverage")
    assert "attack.classify" in code
    assert "attack.unseen" in code
    assert "set(covered) - set(observed)" not in code
    assert "set(observed) - set(covered)" not in code


def test_the_sibling_state_reaches_the_console():
    """It is the state most easily mistaken for coverage, so it has to be
    something the page can show rather than an internal distinction."""
    code = _function("get_attack_coverage")
    assert "covered_only_by_a_sibling" in code


def test_the_chain_endpoint_returns_the_full_order():
    """So the UI can draw the stages that did *not* happen as gaps. A chain
    with holes in it is the readable thing; a list of four tactics is not."""
    code = _function("get_attack_chain")
    assert "tactic_order" in code
    assert "TACTIC_ORDER" in code


def test_the_chain_is_ordered_by_the_chain_not_the_clock():
    code = _function("_observed_chain")
    assert "tactic_position" in code


def test_a_technique_with_no_tactic_still_appears():
    """Dropping it would make an unmapped rule invisible in exactly the view
    meant to show what happened."""
    assert '"other"' in _function("_observed_chain") \
        or "'other'" in _function("_observed_chain")


def test_the_tactic_mapping_is_read_from_the_rules():
    """No table here to drift out of date - the same reason the coverage
    index reads them rather than keeping a list."""
    code = _function("_sigma_tactics_by_technique")
    assert "load_dir" in code
    assert "rule.tactics" in code
