"""What this agent has collected, and what it believes it has shipped.

Three bugs in one day had the same shape: every layer reported success and
the chain was broken anyway, and the only symptom was an empty table -
indistinguishable from a host that genuinely has nothing to report.

    a collector raised on its first line, so the four after it never ran
    the server accepted a batch and discarded every row of it
    the agent marked rows sent as soon as `sendall` returned

The last one is why none of it was visible from here. `sendall` returning
means the bytes reached the operating system's socket buffer. It says nothing
about whether the server stored them.

The protocol now carries a reply frame, so a batch can be acknowledged and
`record_send` can report what was actually stored - but only against a server
new enough to send one. `acknowledged: False` in the report below means the
server said nothing, which is not the same claim as "nothing arrived", and
the console has to be able to tell those apart.

That still leaves the comparison worth making. This module makes the two
halves *comparable*: the agent
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


def record_send(table: str, rows: int, receipt: dict | None = None) -> None:
    """A batch left this agent, and what the server said about it.

    `receipt` is the thing the module docstring above says does not exist. It
    does now: the ingest protocol carries a reply frame, so a send can report
    what was *stored* rather than only what was written to a socket. It stays
    optional because an agent can be pointed at a server older than the frame,
    and `None` means exactly that - not "nothing was stored", which is a
    different and much worse claim.
    """
    with _lock:
        state = _send_state.setdefault(table, {})
        state["last_sent_at"] = time.time()
        state["last_sent_rows"] = int(rows)
        state["last_error"] = None
        if receipt is None:
            state["acknowledged"] = False
            state.pop("last_stored_rows", None)
        else:
            state["acknowledged"] = True
            state["last_stored_rows"] = int(receipt.get("stored") or 0)
            state["last_duplicate_rows"] = int(receipt.get("duplicates") or 0)
            # Rows the server judged unstorable. Not retried - a row it could
            # not store will not become storable - so this count is the only
            # trace they leave on this side.
            state["last_rejected_rows"] = int(receipt.get("rejected") or 0)


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
            # Rows this agent believes it has shipped.
            "shipped": max(held - unsent, 0),
            "last_sent_at": sent.get("last_sent_at"),
            "last_sent_rows": sent.get("last_sent_rows"),
            # Whether the server confirmed the last batch, and how much of it
            # it kept. `acknowledged: False` means the server said nothing -
            # either it predates the reply frame, or it hung up - and the
            # number beside it is belief rather than fact. Reported as its own
            # field so the console can say which, instead of showing a count
            # whose reliability is invisible.
            "acknowledged": sent.get("acknowledged", False),
            "last_stored_rows": sent.get("last_stored_rows"),
            "last_duplicate_rows": sent.get("last_duplicate_rows"),
            "last_rejected_rows": sent.get("last_rejected_rows"),
            "last_error": sent.get("last_error"),
            "last_error_at": sent.get("last_error_at"),
        }
    return out
