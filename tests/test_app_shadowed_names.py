"""In `app.py`, `json` is not the json module.

Line 12:

    from sanic.response import json, file, HTTPResponse, raw

so the bare name `json` is Sanic's *response helper*. The standard library is
imported beside it as `pyjson`, and `sanic_json` is a third alias for the same
response function.

Calling `json.loads(...)` there therefore raises

    'function' object has no attribute 'loads'

at request time, and only at request time. It is valid Python, it imports
cleanly, and every source-reading test passes — the WebAuthn registration
route shipped with exactly this and returned 500 on the first click, after a
suite of tests that checked the route existed, was permissioned, read its
challenge from the database and deleted it afterwards. All true; none of them
executed a line of it.

`file` and `raw` are shadowed the same way, and `file` is the more dangerous of
the two: `file(...)` is a Sanic response and reads like a builtin.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"

#: Names `app.py` binds to something other than what a reader assumes, mapped
#: to the attribute access that gives the mistake away.
SHADOWED = {
    "json": ("loads", "dumps", "load", "dump", "JSONDecodeError"),
    "file": ("read", "write", "open", "close"),
    "raw": ("encode", "decode"),
}


def _tree() -> ast.Module:
    return ast.parse(APP.read_text(encoding="utf-8"))


def test_the_shadowing_still_exists():
    """If Sanic's helpers stop being imported bare, this whole file can go.

    Asserted rather than assumed, so the check cannot quietly become a rule
    about nothing.
    """
    source = APP.read_text(encoding="utf-8")
    assert "from sanic.response import json" in source, (
        "`json` is no longer shadowed in app.py — these checks are obsolete"
    )
    assert "import json as pyjson" in source, "the real module has no alias"


@pytest.mark.parametrize("name", sorted(SHADOWED))
def test_no_module_attribute_is_read_off_a_shadowed_name(name):
    """The check that would have caught the 500 before a person did."""
    offenders = []
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.Attribute):
            continue
        value = node.value
        if not isinstance(value, ast.Name) or value.id != name:
            continue
        if node.attr in SHADOWED[name]:
            offenders.append(f"line {node.lineno}: {name}.{node.attr}")

    assert not offenders, (
        f"`{name}` in app.py is Sanic's response helper, not what this call "
        f"expects — it raises at request time and nowhere else. "
        + "; ".join(offenders)
        + (". Use `pyjson`." if name == "json" else ".")
    )


def test_the_webauthn_routes_use_the_real_json_module():
    """Named specifically, because this is where it happened. The generic
    check above would pass again if somebody reintroduced it with a different
    attribute name."""
    source = APP.read_text(encoding="utf-8")
    assert "pyjson.loads(lib[" in source
    assert "json.loads(lib[" not in source.replace("pyjson.loads(lib[", "")
