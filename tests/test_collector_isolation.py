"""An empty table must mean "nothing to report", never "the collector broke".

The console showed no hardware inventory and no network connections at the
same time. Both collectors were running, both had tables, and nothing anywhere
said anything was wrong.

`edr_enforcer.main` called five collectors as five bare statements in a row:

    check_fim()
    track_network()
    monitor_processes()
    get_hardware_inventory()
    monitor_registry()

so the first one to raise took the rest of the cycle with it - and because the
caller retries on a timer, it took them again every two minutes, for the life
of the agent. Network is second and hardware is fourth, which is why those two
went dark together.

Two layers of silence underneath it. The collectors themselves ended in
`except Exception: pass`, and `periodic_wrapped` reported failures behind
`if debug`, which nothing sets.

The result was a security console showing a host with no hardware, no network
connections and no explanation - which reads as a quiet machine, and is the
one thing it did not mean.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
EDR = ROOT / "Sentora" / "modules" / "edr_enforcer.py"
MAIN = ROOT / "Sentora" / "main.py"


def _function(path: pathlib.Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == name)


def _code(path: pathlib.Path, name: str) -> str:
    """A function's statements, docstring dropped - these explain the bug they
    fixed, and matching prose finds the explanation."""
    fn = _function(path, name)
    body = fn.body
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)):
        body = body[1:]
    return "\n".join(ast.unparse(n) for n in body)


# --------------------------------------------------------------------------
# One collector failing costs its own data and nothing else
# --------------------------------------------------------------------------

def test_the_collectors_are_isolated_from_each_other():
    code = _code(EDR, "main")
    assert "try:" in code, (
        "the collectors run as bare statements, so the first to raise "
        "silently disables every one after it - permanently, because the "
        "caller retries on a timer"
    )
    assert "except Exception" in code


def test_every_collector_still_runs():
    """Isolating them must not quietly drop one."""
    code = _code(EDR, "main")
    for collector in ("check_fim", "track_network", "monitor_processes",
                      "get_hardware_inventory", "monitor_registry"):
        assert collector in code, collector


def test_a_failing_collector_names_itself():
    """"something in edr_enforcer failed" sends somebody to read five
    functions. The name is the whole diagnosis."""
    code = _code(EDR, "main")
    assert "collector failed" in code
    assert "print(" in code


# --------------------------------------------------------------------------
# Nothing swallows its own failure
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "get_hardware_inventory", "monitor_registry",
])
def test_the_collector_does_not_swallow_everything(name):
    """`except Exception: pass` on a collector turns a broken PowerShell call
    into an empty inventory tab, and an empty inventory tab into "this host
    has no hardware"."""
    code = _code(EDR, name)
    assert "except Exception:\n    pass" not in code, name
    assert "pass" not in code.split("except")[-1] if "except" in code else True


def test_a_failed_powershell_call_is_an_error_not_an_empty_result():
    """The exit code was checked and then thrown away: `if returncode == 0`
    with no else, inside a try that passed. A command that failed and a
    command that returned nothing produced the same empty table."""
    code = _code(EDR, "get_hardware_inventory")
    assert "raise" in code
    assert "returncode" in code


# --------------------------------------------------------------------------
# The runner says when a collector stops working
# --------------------------------------------------------------------------

def test_a_failing_collector_is_reported_without_debug():
    """It was behind `if debug`, which nothing in this repository sets. A
    collector that raised on its first line failed silently every interval
    for the life of the agent."""
    code = _code(MAIN, "periodic_wrapped")
    printed = code[code.index("except"):]
    assert "print(" in printed
    # The print must not be conditional on debug.
    lines = [l.strip() for l in printed.splitlines()]
    for i, line in enumerate(lines):
        if line.startswith("print("):
            preceding = " ".join(lines[max(0, i - 2):i])
            assert "if debug" not in preceding, \
                "the failure report is still behind the debug flag"


def test_the_report_is_rate_limited():
    """The same argument that makes silence wrong makes a line every two
    minutes useless: it would bury the schema errors and auth rejections that
    share this log."""
    code = _code(MAIN, "periodic_wrapped")
    assert "_FAILURE_REPEAT_EVERY" in code or "%" in code


def test_recovery_is_reported_too():
    """Otherwise the log says a collector broke and never says it came back,
    and somebody chases a problem that fixed itself an hour ago."""
    code = _code(MAIN, "periodic_wrapped")
    assert "recovered" in code


def test_the_failure_count_resets_on_success():
    code = _code(MAIN, "periodic_wrapped")
    assert "failures = 0" in code
