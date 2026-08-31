"""The agent and the server carry separate versions, and the fleet reports its own.

Nothing in this repository recorded either, which meant the platform could not
answer the first question anyone asks about a misbehaving fleet: what is
actually installed out there.

It showed most sharply once the server stopped dialling agents. An agent that
cannot be commanded is told so in a message that had to *guess* why - "the
usual cause is an agent binary older than the channel" - because there was
nothing to check. The version rides the handshake now, so that stops being a
guess.

The rule these tests exist to hold: a version is a diagnosis, never an access
control. The server does not have a second route to an endpoint any more, so
refusing an old agent on version would make it permanently unreachable *and*
unupgradeable. It connects, and the server says what it is.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from core import version as product_version

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
AGENT_VERSION_PY = ROOT / "Sentora" / "modules" / "version.py"
LINK_PY = ROOT / "Sentora" / "modules" / "link.py"


# --------------------------------------------------------------------------
# Two versions, not one
# --------------------------------------------------------------------------

def test_the_agent_carries_its_own_version():
    """Its own file, not an import from the server's.

    The agent ships as a binary that lands on an endpoint and stays for
    months; the server is a container someone redeploys on a Tuesday. Sharing
    a constant would mean neither could move without the other, which is the
    opposite of what separate versioning is for.

    Asked of the imports rather than of the text: the file explains in prose
    why it does not import the server's version, and matching the text finds
    that explanation and reads it as the thing being warned about.
    """
    tree = ast.parse(AGENT_VERSION_PY.read_text(encoding="utf-8"))
    assert any(isinstance(n, ast.Assign)
               and getattr(n.targets[0], "id", "") == "AGENT_VERSION"
               for n in tree.body)

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert not any(m.startswith("core") for m in imported), \
        f"the agent is reading the server's version: {sorted(imported)}"


def test_the_agent_version_is_well_formed():
    tree = ast.parse(AGENT_VERSION_PY.read_text(encoding="utf-8"))
    value = next(n.value.value for n in tree.body
                 if isinstance(n, ast.Assign)
                 and getattr(n.targets[0], "id", "") == "AGENT_VERSION")
    assert product_version.is_valid_version(value), value


def test_the_product_version_is_not_the_wire_version():
    """`STREAM_VERSION` is the byte layout of a stream frame. Conflating them
    would mean a UI-only release forcing a protocol bump, or a frame change
    hiding inside a patch number.

    Asked of the names the module actually binds and uses, because its
    docstring names the very thing it must not be.
    """
    from core import agent_link

    assert agent_link.STREAM_VERSION == 1
    assert isinstance(product_version.SERVER_VERSION, str)

    tree = ast.parse((ROOT / "core" / "version.py").read_text(encoding="utf-8"))
    referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    referenced |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "STREAM_VERSION" not in referenced, \
        "the product version is defined in terms of the wire version"


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

@pytest.mark.parametrize("left,right,expected", [
    ("1.0.0", "1.0.0", 0),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.1", -1),
    ("2.0.0", "1.9.9", 1),
    ("1.10.0", "1.9.0", 1),          # not a string comparison
    ("1.2", "1.2.0", 0),             # padded, not shorter
    ("1.2.0.1", "1.2.0", 1),
])
def test_versions_order_numerically(left, right, expected):
    assert product_version.compare(left, right) == expected


@pytest.mark.parametrize("value", [
    None, "", "   ", "banana", "1.2.3.4.5", "-1.0", "1.0.0" + "x" * 60,
    "'; DROP TABLE agent_identities; --", "1.0.0\n[agent-link] fake line",
])
def test_junk_is_refused_rather_than_recorded(value):
    """This arrives over the network from an endpoint. It reaches a log line
    and a database column, so a newline in it is a forged log entry and the
    length is a column overflow."""
    assert not product_version.is_valid_version(value)
    assert product_version.parse_version(value) == ()


def test_an_unparseable_version_sorts_below_every_real_one():
    assert product_version.compare("banana", "0.0.1") == -1
    assert product_version.compare("0.0.1", "banana") == 1
    assert product_version.compare("banana", None) == 0


def test_a_prerelease_suffix_does_not_break_the_comparison():
    """Ordering suffixes correctly is a spec of its own, and this comparison
    exists to answer "is that agent behind", which a suffix does not change."""
    assert product_version.is_valid_version("1.2.0-rc1")
    assert product_version.compare("1.2.0-rc1", "1.2.0") == 0
    assert product_version.compare("1.2.0-rc1", "1.1.0") == 1


# --------------------------------------------------------------------------
# What the server does with it
# --------------------------------------------------------------------------

def test_an_agent_that_reports_nothing_is_its_own_answer():
    """NULL is not a gap here. It means the agent sent no header, so it
    predates version reporting - a different fact from "old but known", and
    the one the console most needs to distinguish."""
    state, detail = product_version.agent_support(None)
    assert state == "unknown"
    assert "predates" in detail


def test_a_current_agent_is_not_flagged():
    state, _ = product_version.agent_support(product_version.CURRENT_AGENT_VERSION)
    assert state == "current"


def test_an_agent_below_the_minimum_is_called_unsupported():
    state, detail = product_version.agent_support("0.0.1")
    assert state == "unsupported"
    assert product_version.MIN_AGENT_VERSION in detail


def test_version_never_refuses_a_connection():
    """The whole point. There is no second route to an endpoint now, so
    turning an old agent away would make it permanently unreachable and
    unupgradeable - a worse outcome than talking to it and saying so."""
    source = APP.read_text(encoding="utf-8")
    start = source.index("async def agent_link_socket")
    body = source[start:source.index("\nasync def ", start + 1)]

    assert "agent_support" in body, "the version is not consulted at all"
    closes = body[body.index("agent_support"):]
    assert "ws.close" not in closes.split("reason =")[0], \
        "the handshake closes the socket after classifying the version"


def test_the_version_is_read_from_the_handshake_not_a_later_frame():
    """A `hello` frame would leave a window where the agent is connected and
    unidentified - short, but it is the window a reconnect storm lives in,
    and the version is most wanted exactly when something is going wrong."""
    source = APP.read_text(encoding="utf-8")
    start = source.index("async def agent_link_socket")
    body = source[start:source.index("\nasync def ", start + 1)]
    assert "X-Agent-Version" in body
    assert body.index("X-Agent-Version") < body.index("AgentLink("), \
        "the link is registered before the version is known"


def test_the_agent_sends_it_on_the_handshake():
    source = LINK_PY.read_text(encoding="utf-8")
    assert "X-Agent-Version" in source
    assert "AGENT_VERSION" in source


def test_recording_the_version_cannot_fail_the_handshake():
    """A version is a diagnosis. Losing it costs a line in the console;
    refusing the channel over it would cost the endpoint."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_record_agent_version")
    handlers = [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]
    assert handlers, "a database hiccup here would drop the agent"
    assert "print" in ast.unparse(handlers[0]), "and it would do so silently"


def test_the_lookup_accepts_both_spellings_of_a_name():
    """Callers arrive with the database-derived name, whose hyphens have been
    flattened. Keying only on the stored name leaves every hyphenated host
    looking un-versioned - which reads exactly like an agent too old to report
    one. Same mismatch as `_linked_agent`, and this is the fifth place."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    for name in ("_agent_versions", "_record_agent_version"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and n.name == name)
        assert "_agent_name_forms" in ast.unparse(fn), name


# --------------------------------------------------------------------------
# Surfaces
# --------------------------------------------------------------------------

def test_health_reports_what_is_running(tree=None):
    """The one endpoint that answers without a session, so the only thing a
    deploy script or a load balancer can ask."""
    source = APP.read_text(encoding="utf-8")
    start = source.index("async def health_check")
    body = source[start:start + 900]
    assert "server_version" in body
    assert "current_agent_version" in body


def test_the_column_is_added_by_a_guarded_migration():
    """`agent_identities` is read on the first page an operator opens. An
    unguarded ALTER there is a metadata lock on every boot."""
    source = (ROOT / "core" / "schema_init.py").read_text(encoding="utf-8")
    start = source.index("async def init_enrollment_tables")
    body = source[start:source.index("\nasync def ", start + 1)]
    assert "agent_version" in body
    assert "information_schema" in body
    assert body.index("information_schema") < body.upper().index("ALTER TABLE")
    assert "lock_wait_timeout" in body
