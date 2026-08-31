"""Restart has to end with an agent running.

It relaunched the binary as

    [sys.executable] + sys.argv

which is right when you are running `python main.py` and wrong for the shipped
build. A frozen PyInstaller binary re-executes *itself*: `sys.executable` is
the exe and `sys.argv[0]` is the same path, so the new process was handed its
own path as a positional argument. `_parse_args` uses `parse_args`, not
`parse_known_args`, so argparse answered

    error: unrecognized arguments: C:\\Sentora\\main.exe

and exited 2 before the agent started. The old process then exited on a timer
regardless, so pressing Restart stopped the agent and nothing said so. The
installer's watchdog task starting it again fifteen minutes later is what made
this look like a slow restart rather than a failed one.

Two defects, and the second is the one worth keeping a test on: exiting on a
timer means a replacement that dies immediately is indistinguishable from a
clean handover. Both leave the host with no agent; only one of them says so.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = ROOT / "Sentora" / "main.py"


def _restart_source() -> str:
    """The inner `restart` closure, docstrings and comments dropped.

    The comment above it quotes the broken argv construction, so matching the
    raw file finds the warning and reads it as the code.
    """
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    outer = next(n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "cmd_restart")
    inner = next(n for n in ast.walk(outer)
                 if isinstance(n, ast.FunctionDef) and n.name == "restart")
    return ast.unparse(inner)


def _agent_parser():
    """The agent's own argument parser, compiled without importing main.py.

    Importing it starts collectors and dials a database. The parser is a pure
    function of the two modules named here.
    """
    import argparse
    import os

    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    src = next(ast.unparse(n) for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_parse_args")
    namespace = {"argparse": argparse, "os": os}
    exec(src, namespace)
    return namespace["_parse_args"]


@pytest.mark.parametrize("relaunch_argv", [
    # What `[sys.executable] + sys.argv` produced on a frozen build, with and
    # without the installer's --config.
    [r"C:\Sentora\main.exe", "--config", r"C:\Sentora\config.json"],
    [r"C:\Sentora\main.exe"],
])
def test_the_old_relaunch_argv_would_not_have_parsed(monkeypatch, relaunch_argv):
    """Not an argument about what argparse does - a demonstration of it."""
    monkeypatch.setattr("sys.argv", ["main.exe"] + relaunch_argv)
    with pytest.raises(SystemExit) as exit_info:
        _agent_parser()()
    assert exit_info.value.code != 0, \
        "the premise of this file is wrong; the extra positional is tolerated"


def test_the_argv_a_frozen_relaunch_now_sends_does_parse(monkeypatch):
    monkeypatch.setattr(
        "sys.argv", ["main.exe", "--config", r"C:\Sentora\config.json"])
    assert _agent_parser()().config == r"C:\Sentora\config.json"


def test_a_frozen_build_does_not_pass_itself_its_own_path():
    code = _restart_source()
    assert "'frozen'" in code, (
        "the relaunch does not distinguish a frozen binary from a script, so "
        "the shipped build gets an extra positional argument and argparse "
        "kills it before it starts"
    )
    assert "sys.argv[1:]" in code


def test_the_relaunch_is_the_binary_not_a_guess():
    assert "sys.executable" in _restart_source()


def test_the_old_process_waits_to_see_the_new_one_survive():
    """Exiting on a timer cannot tell a handover from a crash."""
    code = _restart_source()
    assert ".poll()" in code, (
        "nothing checks whether the replacement is alive before this process "
        "gives up the host"
    )
    assert code.index(".poll()") < code.index("os._exit"), \
        "it exits first and checks afterwards, which is not a check"


def test_a_replacement_that_dies_leaves_the_old_agent_running():
    """The failure mode this exists for: a bad argv, a missing config, a DLL
    that will not load. Staying up beats an unmonitored host."""
    code = _restart_source()
    assert "Restart aborted" in code
    # It returns rather than falling through to the exit.
    assert code.count("return") >= 2


def test_a_launch_that_raises_is_not_fatal_either():
    """`Popen` itself can fail - the binary moved, the disk is full. That is
    also a reason to stay up, not a reason to exit."""
    code = _restart_source()
    assert "except Exception" in code
    assert "could not launch" in code


def test_the_argument_parser_is_still_strict():
    """This test's premise. If `_parse_args` ever moves to
    `parse_known_args`, the extra positional stops being fatal and the first
    assertion here stops meaning anything - so the strictness is pinned
    rather than assumed."""
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    body = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_parse_args")
    assert "parse_args()" in body
    assert "parse_known_args" not in body


def test_the_new_process_is_told_which_one_to_replace():
    """`kill_old_agent_if_exists` reads this, and it is what actually ends the
    old process on the healthy path - the exit below is a backstop."""
    code = _restart_source()
    assert "OLD_AGENT_PID" in code

    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    killer = next(ast.unparse(n) for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "kill_old_agent_if_exists")
    assert "OLD_AGENT_PID" in killer


def test_restart_is_reachable_over_the_channel():
    """There is no HTTP route any more, so if the dispatcher does not carry
    it the button does nothing at all."""
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    dispatch = next(ast.unparse(n) for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "dispatch_channel_request")
    assert "/restart" in dispatch
    assert "cmd_restart" in dispatch
