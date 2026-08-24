"""Table and database names interpolated into SQL must be escaped.

Identifiers cannot be parameterised - `DESCRIBE %s` is not valid SQL - so they
are interpolated, and several places did it as f"DESCRIBE `{table}`" with no
escaping. A name containing a backtick closes the quoting early and the rest
of it is parsed as SQL.

Every one of these paths requires `manage_db`, so this is depth rather than
the only control. It is still the difference between an administrator who can
manage databases and an administrator who can run arbitrary statements.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = (ROOT / "app.py").read_text(encoding="utf-8")
BACKTICK = chr(96)


def _quote():
    fn = next(n for n in ast.parse(SRC).body
              if getattr(n, "name", "") == "_quote_identifier")
    ns: dict = {}
    exec(compile(ast.Module([fn], []), "<q>", "exec"), ns)
    return ns["_quote_identifier"]


quote = _quote()


# --------------------------------------------------------------------------
# The escaping
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["users", "DESKTOP_EVS8H9J_db", "a-b", "x1"])
def test_ordinary_identifiers_are_quoted(name):
    assert quote(name) == BACKTICK + name + BACKTICK


def test_a_backtick_is_doubled_not_dropped():
    """MySQL escapes a backtick inside an identifier by doubling it. Dropping
    it would silently address a different table."""
    assert quote("a" + BACKTICK + "b") == BACKTICK + "a" + BACKTICK * 2 + "b" + BACKTICK


def test_the_injection_is_neutralised():
    payload = "tbl" + BACKTICK + "; DROP DATABASE x; -- "
    out = quote(payload)
    # Everything after the opening quote stays inside it: the only unescaped
    # backticks are the first and the last.
    assert out.startswith(BACKTICK) and out.endswith(BACKTICK)
    assert out[1:-1].count(BACKTICK) % 2 == 0


@pytest.mark.parametrize("name", ["", None, "a" * 65])
def test_impossible_identifiers_are_refused(name):
    with pytest.raises(ValueError):
        quote(name)


@pytest.mark.parametrize("bad", ["\x00", "\n", "\r"])
def test_control_characters_are_refused(bad):
    """None appears in a real identifier, and all three make a log entry
    describing the failure misleading."""
    with pytest.raises(ValueError):
        quote("tbl" + bad + "x")


# --------------------------------------------------------------------------
# Every call site uses it
# --------------------------------------------------------------------------

def _code_only(source: str) -> str:
    """The module with every docstring removed.

    The docstrings here quote the unescaped SQL deliberately, so the reason
    survives next to the fix. Scanning them makes the test fail on its own
    explanation, which is what happened the first time it ran.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            body.pop(0)
    return ast.unparse(tree)


def test_no_identifier_is_interpolated_raw():
    code = _code_only(SRC)
    pattern = "f['\"][^'\"\n]*" + BACKTICK + r"\{[a-z_]+\}" + BACKTICK
    found = re.findall(pattern, code)
    sql_like = [m for m in found
                if re.search(r"(SELECT|DESCRIBE|DROP|ALTER|INSERT|UPDATE|SHOW)",
                             m, re.I)]
    assert not sql_like, (
        "these interpolate an identifier into SQL without escaping:\n  "
        + "\n  ".join(sql_like)
    )


def test_the_helper_is_actually_used():
    assert SRC.count("_quote_identifier(") >= 6, (
        "the helper exists but the call sites still build their own SQL"
    )
