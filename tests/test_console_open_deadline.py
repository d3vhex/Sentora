"""The deadline has to be longer than the work it is waiting for.

The console reported

    the agent would not open a console: DESKTOP-EVS8H9J-3 did not open a
    console within 15s

against an agent that was opening one. On Windows the agent tries three
strategies in order - a pseudoconsole in its own process, a helper in the
interactive session, then a shell behind pipes - and only the last works when
the agent runs as a service. The first fails fast; the second times out after
twelve seconds. Measured on a live host:

    17:25:03,382  no console in this process; trying the user's session
    17:25:18,548  falling back to a shell behind pipes
    17:24:48,854  shell alive: powershell -NoLogo -NoProfile

Fifteen seconds to reach the strategy that works, against a fifteen second
deadline. The console was never broken; nobody was still listening when it
came up.

Two things follow, and both are here: a deadline that covers the worst case,
and an agent that does not pay for the discovery twice.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = ROOT / "core" / "agent_link.py"
CONSOLE = ROOT / "Sentora" / "modules" / "console.py"


def _const(path: pathlib.Path, name: str):
    node = next(n for n in ast.parse(path.read_text(encoding="utf-8")).body
                if isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == name for t in n.targets))
    return ast.literal_eval(node.value)


def test_the_deadline_covers_the_agents_worst_case():
    """The chain costs about fifteen seconds before the working strategy is
    even tried, so anything at or near fifteen is a deadline that expires
    exactly when the answer is about to arrive."""
    timeout = _const(LINK, "STREAM_OPEN_TIMEOUT_S")
    assert timeout >= 30, (
        f"opening a stream gives up after {timeout}s; the Windows console "
        f"chain takes ~15s to reach the strategy that works"
    )


def test_it_is_longer_than_an_ordinary_request():
    """Opening a console is not an ordinary request and must not inherit an
    ordinary request's patience."""
    assert (_const(LINK, "STREAM_OPEN_TIMEOUT_S")
            > _const(LINK, "DEFAULT_TIMEOUT_S"))


def test_the_deadline_is_named_not_inlined():
    """It was a literal default in the signature, where the reasoning had
    nowhere to live and nothing could assert on it."""
    fn = next(n for n in ast.walk(ast.parse(LINK.read_text(encoding="utf-8")))
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "open_stream")
    assert "STREAM_OPEN_TIMEOUT_S" in ast.unparse(fn.args)


def test_no_caller_reintroduces_a_shorter_one():
    """A default that every call site overrides is decoration."""
    import re

    app = (ROOT / "app.py").read_text(encoding="utf-8")
    for call in re.findall(r"open_stream\([^)]*\)", app):
        assert "timeout" not in call, f"a caller sets its own deadline: {call}"


# --------------------------------------------------------------------------
# And the agent stops paying for the discovery
# --------------------------------------------------------------------------

def test_the_working_strategy_is_remembered():
    """Whether this process can host a pseudoconsole is a property of how it
    was started; it cannot change while it runs. Rediscovering it on every
    console open spends fifteen seconds proving something already known."""
    source = CONSOLE.read_text(encoding="utf-8")
    assert "_WORKING_STRATEGY" in source

    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, ast.FunctionDef) and n.name == "new_session")
    body = ast.unparse(fn)
    remembered = body.index("_WORKING_STRATEGY")
    first_attempt = body.index("new_direct_session")
    assert remembered < first_attempt, \
        "the remembered strategy is tried after the chain, which saves nothing"


def test_a_stale_memory_falls_back_rather_than_failing():
    """A helper that has since died, a session that logged out. Reporting that
    as "no console" would turn a cache into an outage."""
    fn = next(n for n in ast.walk(ast.parse(CONSOLE.read_text(encoding="utf-8")))
              if isinstance(n, ast.FunctionDef) and n.name == "new_session")
    body = ast.unparse(fn)
    guard = body[:body.index("no console in this process")]
    assert "_WORKING_STRATEGY = None" in guard, \
        "a strategy that stopped working is never forgotten"


def test_every_strategy_records_itself():
    """Remembering only one of them leaves the others paying full price."""
    body = ast.unparse(next(
        n for n in ast.walk(ast.parse(CONSOLE.read_text(encoding="utf-8")))
        if isinstance(n, ast.FunctionDef) and n.name == "new_session"))
    for strategy in ("new_direct_session", "HelperSession", "PipeSession"):
        assert f"_WORKING_STRATEGY = {strategy}" in body, \
            f"{strategy} succeeding is not remembered"


def test_the_memory_does_not_survive_a_restart():
    """It records how *this* process was started. A restarted agent may have
    been started differently - from a service, from a terminal - and a cache
    that outlived that would be confidently wrong."""
    source = CONSOLE.read_text(encoding="utf-8")
    assert "_WORKING_STRATEGY = None" in source
    for persisted in ("json.dump", "open(", "pickle"):
        block = source[source.index("_WORKING_STRATEGY = None"):]
        block = block[:block.index("def new_session")]
        assert persisted not in block, "the strategy is written to disk"
