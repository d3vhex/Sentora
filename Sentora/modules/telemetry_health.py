"""What this agent has collected, and what it believes it has shipped.

Three bugs in one day had the same shape: every layer reported success and
the chain was broken anyway, and the only symptom was an empty table -
indistinguishable from a host that genuinely has nothing to report.

    a collector raised on its first line, so the four after it never ran
    the server accepted a batch and discarded every row of it
    the agent marked rows sent as soon as `sendall` returned

The last one is why none of it was visible from here. `sendall` returning
means the bytes reached the operating system's socket buffer. It says nothing
about whether the server stored them, and the ingest protocol has no reply -
so the agent cannot know, and has always reported success.

This module does not fix that. It makes the two halves *comparable*: the agent
says what it holds and what it has shipped, the server says what it holds, and
the difference names the broken link. `[+] network_connections sent (50 rows)`
against a server table with zero rows is not ambiguous once somebody puts the
two numbers next to each other - the whole difficulty was that nobody ever did.

Counts are read from the database rather than kept as counters. A counter
resets when the agent restarts and drifts whenever anything writes without
going through it; the tables are the truth, and reading them costs two
queries per cycle.
"""

from __future__ import annotations

import threading
import time

#: Per table: when the last send succeeded, how many rows it carried, and the
#: last error if there was one. Small, and the only thing here that is not
#: read straight from the database.
_send_state: dict[str, dict] = {}
_lock = threading.Lock()


def record_send(table: str, rows: int) -> None:
    with _lock:
        state = _send_state.setdefault(table, {})
        state["last_sent_at"] = time.time()
        state["last_sent_rows"] = int(rows)
        state["last_error"] = None


def record_send_failure(table: str, error: Exception | str) -> None:
    """A send that raised. Kept rather than logged only, because the console
    asking "why is this table empty" needs the answer, and the answer is on
    the endpoint."""
    with _lock:
        state = _send_state.setdefault(table, {})
        state["last_error"] = f"{type(error).__name__}: {error}" \
            if isinstance(error, Exception) else str(error)
        state["last_error_at"] = time.time()


def _counts(table: str) -> tuple[int, int]:
    """(rows held, rows not yet shipped) for one table.

    A table that does not exist is `(0, 0)` and not an error: the agent's
    schema gains tables over releases, and a missing one is a real state the
    report should show rather than an exception that hides every other table
    behind it.
    """
    from modules.db import get_conn

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*), COUNT(*) FILTER (WHERE sent = FALSE) "
                            f"FROM {table}")
                row = cur.fetchone()
                return int(row[0] or 0), int(row[1] or 0)
    except Exception:
        return 0, 0


def report(tables) -> dict:
    """Everything this agent knows about its own telemetry, per table.

    Deliberately flat and dumb. The judgement about what the numbers *mean*
    lives on the server, where the other half of the comparison is - putting
    it here would mean an agent deciding whether its own data arrived.
    """
    with _lock:
        state = {t: dict(v) for t, v in _send_state.items()}

    out = {}
    for table in tables:
        held, unsent = _counts(table)
        sent = state.get(table, {})
        out[table] = {
            "held": held,
            "unsent": unsent,
            # Rows this agent believes it has shipped. Belief, not fact:
            # nothing acknowledges an ingest batch.
            "shipped": max(held - unsent, 0),
            "last_sent_at": sent.get("last_sent_at"),
            "last_sent_rows": sent.get("last_sent_rows"),
            "last_error": sent.get("last_error"),
            "last_error_at": sent.get("last_error_at"),
        }
    return out
