"""The LDAP login filter must escape what it interpolates.

`search_filter = login_filter % username` with a username of `*)(uid=*`
produces a filter matching every entry in the tree. The directory returns the
first user, the code takes `entries[0]`, and authentication becomes "did you
type anything".

`LoginRequest.username` also had no pattern, while `CreateUserRequest` has had
`^[a-zA-Z0-9_-]+$` all along - a username that cannot be created was still
accepted at login.
"""
from __future__ import annotations

import ast
import pathlib

import pytest
from ldap3.utils.conv import escape_filter_chars

APP = pathlib.Path(__file__).resolve().parent.parent / "app.py"
SRC = APP.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The escaping
# --------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "*)(uid=*",
    "a)(|(objectClass=*",
    "*",
    "admin)(&(1=1",
    r"\2a",
])
def test_the_metacharacters_do_not_survive_escaping(payload):
    r"""RFC 4515 escaping turns each metacharacter into `\XX` hex.

    Strip those sequences and nothing that can change the filter's structure
    may remain: a leftover `(` or `*` would still be interpreted.
    """
    import re
    escaped = escape_filter_chars(payload)
    residue = re.sub(r"\\[0-9a-fA-F]{2}", "", escaped)
    for char in "()*\\":
        assert char not in residue, (
            f"{payload!r} escaped to {escaped!r}, which still carries {char!r}"
        )


def test_an_ordinary_username_is_unchanged():
    """Escaping must not break the normal case."""
    for name in ("alice", "first.last", "user_1", "a-b", "user@corp.local"):
        assert escape_filter_chars(name) == name


def test_the_filter_is_built_from_the_escaped_value():
    i = SRC.index("search_filter = login_filter %")
    line = SRC[i:i + 120].splitlines()[0]
    assert "escape_filter_chars(username)" in line, line


def test_the_group_lookup_escapes_the_dn():
    """The DN comes from the directory, but a DN can contain parentheses."""
    assert 'escape_filter_chars(user_dn)' in SRC


def test_escape_is_imported():
    assert "from ldap3.utils.conv import escape_filter_chars" in SRC


# --------------------------------------------------------------------------
# The input model
# --------------------------------------------------------------------------

def _login_pattern() -> str:
    """The regex LoginRequest enforces, read from the AST.

    Taken from the literal rather than by matching the unparsed source: the
    pattern is a raw string, and `ast.unparse` re-escapes the backslashes, so
    a text search returns something that will not compile.
    """
    tree = ast.parse(SRC)
    cls = next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "LoginRequest")
    for node in ast.walk(cls):
        if isinstance(node, ast.keyword) and node.arg == "pattern":
            return ast.literal_eval(node.value)
    raise AssertionError("LoginRequest has no pattern= constraint")


def test_login_constrains_the_username():
    """CreateUserRequest has always had a pattern; login did not."""
    assert _login_pattern()


@pytest.mark.parametrize("payload", [
    "*)(uid=*", "a)(|(cn=*", "has spaces", "back\\slash", "semi;colon",
    "paren(s)", "star*",
])
def test_the_pattern_rejects_injection_payloads(payload):
    import re
    assert not re.fullmatch(_login_pattern(), payload), payload


@pytest.mark.parametrize("name", ["alice", "first.last", "user_1", "a-b",
                                  "user@corp.local", "SVC-Backup"])
def test_the_pattern_accepts_real_usernames(name):
    """Narrowing input is only safe if it still admits real accounts."""
    import re
    assert re.fullmatch(_login_pattern(), name), name
