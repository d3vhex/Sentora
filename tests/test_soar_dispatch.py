"""Guard against the SOAR dispatch loop.

`call_agent_soar` defaults to `background_queue=True`, which inserts a fresh
`pending` row into `automations` so an agent that missed the HTTP push can
still poll for the order. That is correct when something new is being
commanded, and a loop when the *dispatcher* does it: every execution enqueued
its own successor, one row per cycle, forever.

The observed consequence: a single self-destruct triggered once from the UI
kept re-arming itself and destroyed the agent again on every reinstall. Four
agent databases each accumulated a chain of them, roughly one every 36
seconds, with the comment growing an `automation#N |` prefix each time -

    automation#40 | automation#39 | ... | automation#1 | Self-destruct from UI

Checked by reading the source rather than by running the dispatchers, which
would need a live agent and a database.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

APP = pathlib.Path(__file__).resolve().parent.parent / "app.py"
SRC = APP.read_text(encoding="utf-8-sig")
TREE = ast.parse(SRC)


def _call_sites():
    """Every call to call_agent_soar, tagged with whether it is a dispatch.

    A dispatcher re-sends a row that is already in `automations`. Three of the
    four build the `automation#<id>` prefix in a preceding statement rather
    than inside the call, so the whole enclosing function is searched - an
    earlier version of this test looked only at the call's own arguments and
    found one site out of four while reporting success on the rest.
    """
    sites = []
    for node in ast.walk(TREE):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fn_src = ast.unparse(node)
        is_dispatch = "automation#" in fn_src
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call)
                    and getattr(inner.func, "id", getattr(inner.func, "attr", None))
                    == "call_agent_soar"):
                kwargs = {k.arg: k.value for k in inner.keywords if k.arg}
                sites.append((node.name, inner.lineno, kwargs, is_dispatch))
    return sites


SITES = _call_sites()


def test_there_are_call_sites_to_check():
    """If this fails the AST walk stopped finding them and every assertion
    below would pass vacuously."""
    assert SITES, "no call_agent_soar call sites found"


def test_every_dispatcher_disables_background_queue():
    """The loop itself.

    A call that re-sends an automation already in the table must not create
    another one. Identified by the `automation#<id>` comment prefix, which
    only a dispatcher builds.
    """
    offenders = []
    for fn, lineno, kwargs, is_dispatch in SITES:
        if not is_dispatch:
            continue
        bq = kwargs.get("background_queue")
        if bq is None or (isinstance(bq, ast.Constant) and bq.value is not False):
            offenders.append(f"{fn}:{lineno}")
    assert not offenders, (
        "these re-dispatch an existing automation while still queueing a new "
        f"one: {offenders}"
    )


def test_at_least_four_dispatchers_are_covered():
    """There were four independent copies of this dispatch logic, and the fix
    had to be applied to each. This pins that the walk still sees them all -
    a detector that quietly finds one would let the other three regress."""
    dispatchers = [f"{fn}:{ln}" for fn, ln, _, is_d in SITES if is_d]
    assert len(dispatchers) >= 4, f"expected 4+ dispatchers, found {dispatchers}"


def test_the_default_is_still_queue_on_new_commands():
    """The default must stay True. A genuinely new order does need to be
    queued, so an agent that missed the push picks it up by polling."""
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "call_agent_soar")
    default = next((d for kw, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults)
                    if kw.arg == "background_queue"), None)
    assert isinstance(default, ast.Constant) and default.value is True


@pytest.mark.parametrize("fn_name", [
    "run_due_automations", "periodic_soar_automation_check",
])
def test_named_dispatchers_exist(fn_name):
    """Pins the names the comments refer to, so a rename does not quietly
    orphan the explanation of why background_queue is False."""
    assert any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == fn_name for n in ast.walk(TREE)), \
        f"{fn_name} no longer exists"
