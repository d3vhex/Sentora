"""Unit tests for the session store.

MySQL is stubbed with a recording fake cursor — what matters here is the
security-relevant behaviour: that the raw token never reaches storage, that
both expiry clocks are enforced in SQL rather than in Python, and that `touch`
does not turn every polled request into a write.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from security import session as session_store


class FakeCursor:
    """Records executed statements and replays a queued result for fetchone."""

    def __init__(self, fetch_result=None, rowcount=0):
        self.statements: list[tuple[str, tuple]] = []
        self._fetch_result = fetch_result
        self.rowcount = rowcount

    async def execute(self, sql, params=()):
        self.statements.append((sql, params))

    async def fetchone(self):
        return self._fetch_result

    @property
    def last_sql(self) -> str:
        return self.statements[-1][0]

    @property
    def last_params(self) -> tuple:
        return self.statements[-1][1]


def test_tokens_are_unique_and_long():
    tokens = {session_store.new_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) >= 32 for t in tokens)


def test_hash_token_is_stable_and_hex():
    a = session_store.hash_token("abc")
    assert a == session_store.hash_token("abc")
    assert a != session_store.hash_token("abd")
    assert len(a) == 64
    int(a, 16)  # raises if not hex


async def test_create_never_stores_the_raw_token():
    """A dump of `sessions` must not yield anything a client can present."""
    cur = FakeCursor()
    raw = await session_store.create(
        cur, user_id=7, username="alice", role="admin",
        auth_type="local", ip="10.0.0.1", user_agent="pytest",
    )

    params = cur.last_params
    assert raw not in params, "raw token leaked into the INSERT"
    assert session_store.hash_token(raw) in params
    assert 7 in params and "alice" in params


async def test_create_sets_absolute_expiry():
    cur = FakeCursor()
    await session_store.create(cur, user_id=1, username="u", role=None)

    expires_at = cur.last_params[-1]
    expected = datetime.now() + timedelta(hours=session_store.SESSION_ABSOLUTE_HOURS)
    assert abs((expires_at - expected).total_seconds()) < 5


async def test_load_returns_none_without_a_token_and_issues_no_query():
    cur = FakeCursor()
    assert await session_store.load(cur, None) is None
    assert await session_store.load(cur, "") is None
    assert cur.statements == []


async def test_load_enforces_both_clocks_in_sql():
    """Expiry must not depend on the caller remembering to check it."""
    cur = FakeCursor(fetch_result={"user_id": 3})
    await session_store.load(cur, "raw-token")

    sql = " ".join(cur.last_sql.split())
    assert "revoked_at IS NULL" in sql
    assert "expires_at > NOW()" in sql
    assert "last_seen_at > (NOW() - INTERVAL %s MINUTE)" in sql
    assert session_store.hash_token("raw-token") in cur.last_params


async def test_touch_skips_write_inside_the_interval():
    cur = FakeCursor()
    fresh = datetime.now() - timedelta(seconds=session_store.TOUCH_INTERVAL_SECONDS - 10)

    assert await session_store.touch(cur, "hash", fresh) is False
    assert cur.statements == []


async def test_touch_writes_once_the_interval_has_passed():
    cur = FakeCursor()
    stale = datetime.now() - timedelta(seconds=session_store.TOUCH_INTERVAL_SECONDS + 10)

    assert await session_store.touch(cur, "hash", stale) is True
    assert "UPDATE sessions" in cur.last_sql
    assert cur.last_params == ("hash",)


async def test_revoke_hashes_before_lookup():
    cur = FakeCursor()
    await session_store.revoke(cur, "raw-token")

    assert "revoked_at = NOW()" in cur.last_sql
    assert cur.last_params == (session_store.hash_token("raw-token"),)


async def test_revoke_is_a_noop_without_a_token():
    cur = FakeCursor()
    await session_store.revoke(cur, None)
    assert cur.statements == []


async def test_revoke_for_user_targets_only_live_rows():
    cur = FakeCursor(rowcount=3)
    killed = await session_store.revoke_for_user(cur, 42)

    assert killed == 3
    assert cur.last_params == (42,)
    assert "revoked_at IS NULL" in cur.last_sql


@pytest.mark.parametrize("clause", [
    "expires_at < NOW()",
    "revoked_at IS NOT NULL",
    "last_seen_at <",
])
async def test_purge_covers_every_dead_state(clause):
    cur = FakeCursor(rowcount=1)
    await session_store.purge_expired(cur)
    assert clause in " ".join(cur.last_sql.split())
