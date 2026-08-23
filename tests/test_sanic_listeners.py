"""Sanic listener signatures.

Sanic deprecated the `loop` argument on listeners; it is removed in v26.6.
`setup_background_tasks(app, _)` was the only one still taking it, and it
never used the value - the warning was emitted on every boot, three times per
run, and would have become a TypeError on upgrade.

A scan rather than a spot check: the next listener someone adds is the one
that reintroduces this.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

LISTENERS = {
    "before_server_start", "after_server_start",
    "before_server_stop", "after_server_stop",
    "main_process_start", "main_process_stop",
    "main_process_ready",
}


def _listeners_in(path: pathlib.Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for dec in node.decorator_list:
            dumped = ast.dump(dec)
            hit = LISTENERS & {k for k in LISTENERS if k in dumped}
            if hit:
                yield node, sorted(hit)
                break


@pytest.mark.parametrize("filename", ["app.py", "server.py"])
def test_no_listener_takes_the_deprecated_loop_argument(filename):
    path = ROOT / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")

    offenders = [
        f"{filename}:{node.lineno} {node.name}"
        f"({', '.join(a.arg for a in node.args.args)}) -> {kinds}"
        for node, kinds in _listeners_in(path)
        if len(node.args.args) > 1
    ]
    assert not offenders, (
        "Sanic removes the listener `loop` argument in v26.6:\n  "
        + "\n  ".join(offenders)
    )


def test_the_scan_finds_listeners_at_all():
    """Guard against the test passing because the scan matched nothing."""
    found = list(_listeners_in(ROOT / "app.py"))
    assert len(found) >= 4, f"only found {len(found)} listeners; the scan is broken"
