"""Pooled connections must be released on the error path too.

The failure: agents polling `/automations/pending` got 500 on every request,
each after exactly ten seconds. The pool holds ten connections; handlers
acquire one and close it on the happy path only, so any exception between
acquiring and closing leaked it permanently. After ten leaks every request in
the server waited on an empty semaphore until Sanic's response timeout fired.

Nothing pointed at the pool. The 500 body carried the timeout, the log carried
`RuntimeWarning: coroutine '_PooledConn.close' was never awaited`, and the
endpoint had been returning 200 in 23ms an hour earlier.

Three separate things were wrong, and only the first was the outage:

- Twelve queries were blocked on a metadata lock taken by an unconditional
  ALTER, each legitimately holding a connection. See test_automation_status.
- `acquire()` waited on the semaphore forever, so an empty pool became a
  server-wide hang reported as a generic timeout.
- 72 handlers release their connection only on the happy path.

The third is now covered for anything served over HTTP: `_track_for_request`
registers the connection on the request and an `on_response` middleware
returns it, whatever the handler did. See test_db_pool_release.

This test still counts them, for two reasons. Background tasks have no request
and are not covered by the middleware. And a handler that holds a connection
across a slow call still occupies a slot for as long as it runs, middleware or
not - the count is a measure of how much of the pool is governed by hand.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
TREE = ast.parse(APP.read_text(encoding="utf-8"))

ACQUIRE = {"connect_db_for_agent", "connect_userdb"}

# Polled continuously by every agent. A leak here drains the pool in minutes,
# so these must never regress even while the others are being worked through.
HOT_PATH = {
    "get_pending_automations_for_agent",
    "report_automation_result_by_id",
}

# Handlers that still acquire a connection without a finally or async with.
# Lower this as they are fixed; it must never rise.
KNOWN_LEAKY_MAX = 72


def _acquiring_handlers():
    out = {}
    for fn in [n for n in ast.walk(TREE) if isinstance(n, ast.AsyncFunctionDef)]:
        direct = any(getattr(c.func, "id", "") in ACQUIRE
                     for c in ast.walk(fn) if isinstance(c, ast.Call))
        ctx = any(
            getattr(getattr(item.context_expr, "func", None), "id", "") in
            {"agent_conn", "userdb_conn"}
            for n in ast.walk(fn) if isinstance(n, ast.AsyncWith)
            for item in n.items
        )
        if direct or ctx:
            out[fn.name] = (fn, direct, ctx)
    return out


def _is_protected(fn, direct, ctx) -> bool:
    if ctx and not direct:
        return True
    for t in ast.walk(fn):
        if isinstance(t, ast.Try) and t.finalbody:
            if "close" in " ".join(ast.unparse(s) for s in t.finalbody):
                return True
    return False


HANDLERS = _acquiring_handlers()


def test_the_scan_finds_handlers():
    """Guard against a green run caused by matching nothing."""
    assert len(HANDLERS) > 50, f"only {len(HANDLERS)} found; the scan is broken"


@pytest.mark.parametrize("name", sorted(HOT_PATH))
def test_agent_polled_endpoints_cannot_leak(name):
    assert name in HANDLERS, f"{name} no longer acquires a connection; update this test"
    fn, direct, ctx = HANDLERS[name]
    assert _is_protected(fn, direct, ctx), (
        f"{name} is polled by every agent and releases its connection only on "
        f"the happy path. Ten failures drain the pool and every endpoint in "
        f"the server starts timing out."
    )


def test_the_leak_count_does_not_grow():
    leaky = sorted(n for n, (fn, d, c) in HANDLERS.items()
                   if not _is_protected(fn, d, c))
    assert len(leaky) <= KNOWN_LEAKY_MAX, (
        f"{len(leaky)} handlers can leak a pooled connection, up from "
        f"{KNOWN_LEAKY_MAX}. New ones: use `async with agent_conn(...)` or "
        f"`async with userdb_conn()`.\n  " + "\n  ".join(leaky[:10])
    )


def test_acquire_is_bounded():
    """An unbounded wait turns a leak into a server-wide hang."""
    src = APP.read_text(encoding="utf-8")
    i = src.index("async def acquire(self)")
    body = src[i:i + 1200]
    assert "wait_for" in body and "_POOL_ACQUIRE_TIMEOUT" in body, \
        "acquire() waits forever on an exhausted pool"


def test_the_exhaustion_error_names_the_cause():
    """The previous symptom was a bare timeout that pointed nowhere."""
    src = APP.read_text(encoding="utf-8")
    i = src.index("async def acquire(self)")
    body = src[i:i + 1200]
    assert "without releasing" in body


def test_the_timeout_is_under_the_response_timeout():
    """Otherwise Sanic answers first and the pool error is never seen."""
    src = APP.read_text(encoding="utf-8")
    line = next(l for l in src.splitlines() if "_POOL_ACQUIRE_TIMEOUT = " in l)
    default = float(line.split('"')[-2])
    assert default < 10.0, "the pool error will be masked by the response timeout"
