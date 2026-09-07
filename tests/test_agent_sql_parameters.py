"""The agent never builds a SQL predicate out of a value.

`portscanner.is_duplicate` did, with a hand-rolled `normalize()` that doubled
single quotes, and on a live host it failed every cycle:

    [!] portscanner failed (1 consecutive): SyntaxError: unterminated quoted
        string at or near "'"

so no port scan result was written at all. The collector had been silently
dead, which - being a table that produces rows rarely - looked exactly like a
host with no open ports.

Which input broke it hardly matters. nmap returns product and version strings
containing whatever a service chose to advertise, and a banner is
attacker-controlled by definition. The answer to that is not a better
escaping function.

A security product assembling SQL by concatenation is running the pattern it
exists to detect elsewhere. Every driver here takes parameters; the helpers
have taken a `params` tuple all along.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "Sentora"

#: An interpolated *identifier* is fine and unavoidable: the table name comes
#: from this project's own fixed list, and no driver lets you parameterise it.
#: What must never be interpolated is a value.
_PREDICATE = re.compile(r"\b(?:WHERE|AND|OR|SET)\b[^\n]*?=\s*'?\{", re.I)


def _interpolated_predicates():
    found = []
    for path in sorted(AGENT.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            # Reconstruct with `{...}` where the substitutions are, so a
            # placeholder can be told from a literal.
            text = "".join(
                part.value if isinstance(part, ast.Constant) else "{}"
                for part in node.values)
            if _PREDICATE.search(text):
                found.append((path, node.lineno, text.strip()[:100]))
    return found


CASES = [pytest.param(p, ln, t, id=f"{p.name}:{ln}")
         for p, ln, t in _interpolated_predicates()]


@pytest.mark.parametrize("path,line,text", CASES or
                         [pytest.param(None, 0, "", id="none-found")])
def test_no_value_is_interpolated_into_a_predicate(path, line, text):
    """Quoting is the driver's job. Doing it by hand is how a service banner
    becomes a syntax error, and on a less lucky day something worse."""
    assert path is None, (
        f"{path.name}:{line} builds a SQL predicate by interpolation: {text!r}\n"
        f"Pass values as parameters - every helper in modules/db.py takes a "
        f"`params` tuple."
    )


def test_the_scan_can_still_see_sql():
    """A detector that has stopped matching anything passes silently. This
    holds it to a pattern it must keep recognising."""
    # Double-quoted outer string so the SQL quotes inside need no escaping;
    # the first version escaped them into a syntax error and tested nothing.
    sample = 'f"SELECT * FROM {table} WHERE name = \'{value}\'"'
    tree = ast.parse(sample)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.JoinedStr))
    text = "".join(part.value if isinstance(part, ast.Constant) else "{}"
                   for part in node.values)
    assert _PREDICATE.search(text), "the scan no longer recognises the bug"


def test_the_helpers_offer_parameters():
    """The fix has to be available, or the rule above is a rule nobody can
    follow."""
    source = (AGENT / "modules" / "db.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == "fetch_where")
    assert any(a.arg == "params" for a in fn.args.args)


def test_the_portscanner_uses_them():
    """The specific caller that was failing, pinned - it is the one with
    attacker-controlled input, since nmap reports whatever a service
    advertises."""
    source = (AGENT / "modules" / "portscanner" / "portscanner.py").read_text(
        encoding="utf-8")
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == "is_duplicate")
    body = ast.unparse(fn)
    assert "%s" in body, "the duplicate check builds its own literals again"
    assert "params" in body
