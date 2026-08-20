"""Server-side session store for the management UI.

Before this module the UI "authenticated" by sending `X-User-ID: <n>`, which is
an unauthenticated claim any client can forge. The header is still part of the
wire format and is still checked, but it is no longer *identity*: the browser
now carries an opaque random token in an HttpOnly cookie and this table is the
authority. See `attach_session` in app.py for how the two are reconciled.

Only SHA-256(token) is persisted, so a dump of the `sessions` table does not
yield usable session tokens.

Every function takes an already-open cursor from the caller's pool
(`connect_userdb()` in app.py). Keeping connection management out of here means
the store is trivial to exercise in tests with a fake cursor.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta

SESSION_COOKIE = "sentora_session"

# Hard ceiling on a session's life regardless of activity: even a
# continuously-used session has to re-authenticate this often.
SESSION_ABSOLUTE_HOURS = int(os.getenv("SESSION_ABSOLUTE_HOURS", "12"))

# Sliding window: a session dies this long after the last request that used it.
SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "60"))

# `last_seen_at` is only rewritten once it is this stale. The dashboard polls
# several endpoints every 30s, and without this every one of those would cost
# an extra UPDATE.
TOUCH_INTERVAL_SECONDS = 60

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   CHAR(64)     NOT NULL PRIMARY KEY,
    user_id      INT          NOT NULL,
    username     VARCHAR(100) NOT NULL,
    role         VARCHAR(50),
    auth_type    VARCHAR(16)  NOT NULL DEFAULT 'local',
    ip_address   VARCHAR(45),
    user_agent   VARCHAR(255),
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME     NOT NULL,
    revoked_at   DATETIME     NULL,
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def new_token() -> str:
    """Opaque session token handed to the browser. Never stored as-is."""
    return secrets.token_urlsafe(32)


def hash_token(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def cookie_max_age() -> int:
    return SESSION_ABSOLUTE_HOURS * 3600


async def create(cur, *, user_id: int, username: str, role: str | None,
                 auth_type: str = "local", ip: str | None = None,
                 user_agent: str | None = None) -> str:
    """Issue a session and return the raw token for the Set-Cookie header."""
    raw = new_token()
    expires_at = datetime.now() + timedelta(hours=SESSION_ABSOLUTE_HOURS)
    await cur.execute(
        """INSERT INTO sessions
               (token_hash, user_id, username, role, auth_type,
                ip_address, user_agent, expires_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (hash_token(raw), user_id, username, role, auth_type,
         ip, (user_agent or "")[:255], expires_at),
    )
    return raw


async def load(cur, raw_token: str | None) -> dict | None:
    """Resolve a raw cookie value to its session row, or None.

    Both expiry clocks are enforced in SQL so an expired session can never be
    returned even if a caller forgets to check.
    """
    if not raw_token:
        return None
    await cur.execute(
        """SELECT token_hash, user_id, username, role, auth_type, last_seen_at
             FROM sessions
            WHERE token_hash = %s
              AND revoked_at IS NULL
              AND expires_at > NOW()
              AND last_seen_at > (NOW() - INTERVAL %s MINUTE)""",
        (hash_token(raw_token), SESSION_IDLE_MINUTES),
    )
    return await cur.fetchone()


async def touch(cur, token_hash: str, last_seen_at) -> bool:
    """Slide the idle window forward. No-op if refreshed within the interval."""
    if isinstance(last_seen_at, datetime):
        age = (datetime.now() - last_seen_at).total_seconds()
        if age < TOUCH_INTERVAL_SECONDS:
            return False
    await cur.execute(
        "UPDATE sessions SET last_seen_at = NOW() WHERE token_hash = %s",
        (token_hash,),
    )
    return True


async def revoke(cur, raw_token: str | None) -> None:
    if not raw_token:
        return
    await cur.execute(
        "UPDATE sessions SET revoked_at = NOW() WHERE token_hash = %s AND revoked_at IS NULL",
        (hash_token(raw_token),),
    )


async def revoke_for_user(cur, user_id: int) -> int:
    """Kill every live session for a user.

    Called when their password changes, their role changes, or the account is
    deleted — otherwise a stolen or stale session outlives the credential it
    was issued against.
    """
    await cur.execute(
        "UPDATE sessions SET revoked_at = NOW() WHERE user_id = %s AND revoked_at IS NULL",
        (user_id,),
    )
    return cur.rowcount or 0


async def purge_expired(cur) -> int:
    """Drop rows no longer usable. Safe to run on a timer."""
    await cur.execute(
        """DELETE FROM sessions
            WHERE expires_at < NOW()
               OR revoked_at IS NOT NULL
               OR last_seen_at < (NOW() - INTERVAL %s MINUTE)""",
        (SESSION_IDLE_MINUTES,),
    )
    return cur.rowcount or 0
