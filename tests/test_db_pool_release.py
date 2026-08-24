"""A pooled connection must come back even when the handler does not release it.

72 handlers acquire a connection and release it only on the happy path, so an
exception in between skips the close. The pool holds ten.

Two things kept this from being obvious. `_PooledConn.__del__` returns the
connection when the object is collected, so a leak in a simple path is
invisible - the first version of the test below could not exhaust the pool at
all until it held references. And the outage that exposed it was not caused by
this at all: twelve queries were blocked on a metadata lock, each legitimately
holding its connection, which emptied the pool on its own.

So `__del__` is a real mitigation, and it is also not a guarantee: it depends
on collection timing, it releases an asyncio semaphore from whatever context
the collector runs in, and it says nothing about a connection pinned by a live
exception traceback.

Rewriting 72 handlers would be a large diff over untested paths, and it holds
only until someone writes the seventy-third. The connection is tied to the
request instead: whoever acquires it, the response middleware returns it.

These tests run the real pool against a fake connection, so what is exercised
is the acquire/release accounting rather than a mock of it.
"""
from __future__ import annotations

import asyncio
import types

import pytest


class FakeConn:
    def __init__(self):
        self.closed = False

    async def rollback(self):
        pass

    async def close(self):
        self.closed = True


class FakeCtx:
    pass


class FakeRequest:
    def __init__(self):
        self.ctx = FakeCtx()


@pytest.fixture
def app_mod(monkeypatch):
    """Import app.py's pool machinery without starting a server.

    app.py imports sanic, bcrypt and mysql at module scope, so the pieces
    under test are compiled in isolation instead.
    """
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parent.parent / "app.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))

    wanted = {"_PooledConn", "_AsyncMySQLPool", "_track_for_request"}
    nodes = [n for n in tree.body
             if getattr(n, "name", None) in wanted]
    assert len(nodes) == 3, f"found {[getattr(n,'name',None) for n in nodes]}"

    ns = {
        "asyncio": asyncio, "time": __import__("time"),
        "collections": __import__("collections"),
        "_POOL_MAXSIZE": 3, "_POOL_IDLE_SEC": 60, "_POOL_ACQUIRE_TIMEOUT": 0.2,
        "Request": types.SimpleNamespace(get_current=lambda: None),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<app>", "exec"), ns)

    class Mod(types.SimpleNamespace):
        """Attribute writes land in the exec namespace, which is what the
        compiled functions actually resolve globals against."""
        def __init__(self, ns):
            object.__setattr__(self, "_ns", ns)

        def __getattr__(self, name):
            try:
                return self._ns[name]
            except KeyError:
                raise AttributeError(name) from None

        def __setattr__(self, name, value):
            self._ns[name] = value

    return Mod(ns)


def _pool(app_mod, conns):
    async def factory():
        c = FakeConn()
        conns.append(c)
        return c
    return app_mod._AsyncMySQLPool(factory, maxsize=3, max_idle_sec=60)


# --------------------------------------------------------------------------
# The leak
# --------------------------------------------------------------------------

def test_a_handler_that_never_closes_exhausts_the_pool(app_mod):
    """The behaviour being fixed, pinned so the fix has something to beat."""
    async def scenario():
        pool = _pool(app_mod, [])
        # Held, the way a handler frame or a blocked query holds them. Without
        # the reference __del__ hands them straight back and nothing leaks -
        # which is exactly why this went unnoticed for so long.
        leaked = [await pool.acquire() for _ in range(3)]
        assert len(leaked) == 3
        with pytest.raises(RuntimeError, match="No database connection"):
            await pool.acquire()
    asyncio.run(scenario())


def test_releasing_returns_the_connection(app_mod):
    async def scenario():
        pool = _pool(app_mod, [])
        held = [await pool.acquire() for _ in range(3)]
        await held[0].close()
        # a slot is free again
        again = await pool.acquire()
        assert again is not None
    asyncio.run(scenario())


def test_close_is_idempotent(app_mod):
    """The middleware closes what a well-behaved handler already closed."""
    async def scenario():
        pool = _pool(app_mod, [])
        conn = await pool.acquire()
        await conn.close()
        await conn.close()
        await conn.close()
        # three closes must not free three slots
        held = [await pool.acquire() for _ in range(3)]
        assert len(held) == 3
        with pytest.raises(RuntimeError):
            await pool.acquire()
    asyncio.run(scenario())


# --------------------------------------------------------------------------
# Request tracking
# --------------------------------------------------------------------------

def test_acquire_registers_the_connection_on_the_request(app_mod, monkeypatch):
    request = FakeRequest()
    monkeypatch.setattr(app_mod, "Request",
                        types.SimpleNamespace(get_current=lambda: request))

    async def scenario():
        pool = _pool(app_mod, [])
        conn = await pool.acquire()
        assert getattr(request.ctx, "_db_conns", []) == [conn]
    asyncio.run(scenario())


def test_every_acquire_in_one_request_is_tracked(app_mod, monkeypatch):
    """Handlers like run_playbook acquire four times."""
    request = FakeRequest()
    monkeypatch.setattr(app_mod, "Request",
                        types.SimpleNamespace(get_current=lambda: request))

    async def scenario():
        pool = _pool(app_mod, [])
        conns = [await pool.acquire() for _ in range(3)]
        assert request.ctx._db_conns == conns
    asyncio.run(scenario())


def test_no_request_context_is_not_an_error(app_mod, monkeypatch):
    """Background tasks acquire outside any request and must still work."""
    def boom():
        raise RuntimeError("no current request")
    monkeypatch.setattr(app_mod, "Request",
                        types.SimpleNamespace(get_current=boom))

    async def scenario():
        pool = _pool(app_mod, [])
        assert await pool.acquire() is not None
    asyncio.run(scenario())


def test_a_leaking_handler_is_recovered_by_the_middleware(app_mod, monkeypatch):
    """The whole point, end to end.

    Simulates the real shape: a handler acquires, raises, returns a 500
    without closing. The pool must be whole again afterwards.
    """
    import pathlib
    import ast

    src = pathlib.Path(__file__).resolve().parent.parent / "app.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    mw = next(n for n in tree.body
              if getattr(n, "name", "") == "_release_request_db_connections")
    # strip the @app.on_response decorator so it is a plain coroutine
    mw.decorator_list = []
    ns = {}
    exec(compile(ast.Module(body=[mw], type_ignores=[]), "<mw>", "exec"), ns)
    release = ns["_release_request_db_connections"]

    request = FakeRequest()
    monkeypatch.setattr(app_mod, "Request",
                        types.SimpleNamespace(get_current=lambda: request))

    async def scenario():
        pool = _pool(app_mod, [])
        leaked = [await pool.acquire() for _ in range(3)]   # handler leaks all
        assert len(leaked) == 3
        await release(request, object())    # response middleware runs
        # pool is whole again: three more acquires succeed
        recovered = [await pool.acquire() for _ in range(3)]
        assert len(recovered) == 3
    asyncio.run(scenario())


def test_the_middleware_clears_the_list(app_mod, monkeypatch):
    """Otherwise a keep-alive connection accumulates stale references."""
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parent.parent / "app.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    mw = next(n for n in tree.body
              if getattr(n, "name", "") == "_release_request_db_connections")
    mw.decorator_list = []
    ns = {}
    exec(compile(ast.Module(body=[mw], type_ignores=[]), "<mw>", "exec"), ns)

    request = FakeRequest()
    monkeypatch.setattr(app_mod, "Request",
                        types.SimpleNamespace(get_current=lambda: request))

    async def scenario():
        pool = _pool(app_mod, [])
        await pool.acquire()
        await ns["_release_request_db_connections"](request, object())
        assert request.ctx._db_conns == []
    asyncio.run(scenario())
