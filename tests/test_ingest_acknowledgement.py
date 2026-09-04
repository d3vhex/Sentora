"""The agent may only call a batch sent once the server says it stored it.

This closes the last of the three failures in `telemetry_health`'s docstring,
and the one that made the other two invisible:

    a collector raised on its first line, so the four after it never ran
    the server accepted a batch and discarded every row of it
    the agent marked rows sent as soon as `sendall` returned

`sendall` returning means the bytes reached the operating system's socket
buffer. It says nothing about the server, and the ingest protocol had no reply
frame, so the agent could not have known better - which is how four tables
stayed permanently empty for days while `[+] network_connections sent (50
rows)` scrolled past every cycle. The rows were marked sent and dropped from
the retry queue on the strength of a socket write.

The protocol now carries a receipt. Three cases have to stay distinguishable,
and collapsing any two of them recreates the bug:

    a receipt saying rows were stored      -> mark sent
    a receipt carrying an error            -> keep the rows, retry, say why
    no receipt at all (an older server)    -> mark sent, and say it is belief

The third is the subtle one. "The server said nothing" is not "the server
stored nothing", and treating it as failure would make every agent pointed at
an older server retry the same rows for ever.
"""
from __future__ import annotations

import ast
import json
import pathlib
import socket
import struct
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = ROOT / "Sentora" / "main.py"
SERVER = ROOT / "server.py"


def _compiled(path: pathlib.Path, *names: str, extra: dict | None = None):
    """Named functions, compiled with the module constants they refer to."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    wanted = [n for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name in names]
    assert len(wanted) == len(names), f"missing one of {names} in {path.name}"

    referenced = set()
    for fn in wanted:
        referenced |= {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    constants = [n for n in tree.body
                 if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in referenced for t in n.targets)]

    namespace: dict = {"socket": socket, "struct": struct, "json": json}
    namespace.update(extra or {})
    exec(compile(ast.Module(body=[*constants, *wanted], type_ignores=[]),
                 str(path), "exec"), namespace)
    return [namespace[n] for n in names]


@pytest.fixture
def pair():
    """A connected socket pair, so the frame is tested on a real socket.

    `socket.socketpair()` is AF_UNIX on POSIX and a loopback TCP pair on
    Windows; both give the partial reads this code has to survive.
    """
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)
    yield a, b
    a.close()
    b.close()


# --------------------------------------------------------------------------
# The frame itself
# --------------------------------------------------------------------------

def test_a_receipt_survives_the_wire(pair):
    server_end, agent_end = pair
    read_receipt, _ = _compiled(MAIN, "_read_receipt", "_recv_exactly")

    body = json.dumps({"stored": 12, "duplicates": 3, "error": None}).encode()
    server_end.sendall(struct.pack("!I", len(body)) + body)

    assert read_receipt(agent_end) == {"stored": 12, "duplicates": 3, "error": None}


def test_a_server_that_says_nothing_reads_as_no_receipt(pair):
    """An agent built after the frame, talking to a server built before it.
    The server stores the batch and closes; that must not read as data loss."""
    server_end, agent_end = pair
    read_receipt, _ = _compiled(MAIN, "_read_receipt", "_recv_exactly")

    server_end.close()
    assert read_receipt(agent_end) is None


def test_a_truncated_receipt_reads_as_no_receipt(pair):
    """Half a frame is not half an answer. The batch is already stored or
    already lost by this point, and guessing which from a broken frame would
    be worse than saying it went unacknowledged."""
    server_end, agent_end = pair
    read_receipt, _ = _compiled(MAIN, "_read_receipt", "_recv_exactly")

    server_end.sendall(struct.pack("!I", 4096) + b'{"stored"')
    server_end.close()
    assert read_receipt(agent_end) is None


def test_an_absurd_length_is_refused_without_allocating(pair):
    """The length comes off the network. Allocating on it is how a reply
    frame becomes a denial of service against the agent."""
    server_end, agent_end = pair
    read_receipt, _ = _compiled(MAIN, "_read_receipt", "_recv_exactly")

    server_end.sendall(struct.pack("!I", 0xFFFFFFFF))
    assert read_receipt(agent_end) is None


def test_a_frame_split_across_packets_is_reassembled(pair):
    """TCP is a stream. A receipt arriving in two reads must not be treated
    as a truncated one."""
    server_end, agent_end = pair
    read_receipt, _ = _compiled(MAIN, "_read_receipt", "_recv_exactly")

    body = json.dumps({"stored": 1, "duplicates": 0, "error": None}).encode()

    def dribble():
        header = struct.pack("!I", len(body))
        server_end.sendall(header[:2])
        server_end.sendall(header[2:])
        for i in range(0, len(body), 3):
            server_end.sendall(body[i:i + 3])

    thread = threading.Thread(target=dribble)
    thread.start()
    try:
        assert read_receipt(agent_end) == {"stored": 1, "duplicates": 0, "error": None}
    finally:
        thread.join()


# --------------------------------------------------------------------------
# What the agent does with it
# --------------------------------------------------------------------------

def _send_table_body() -> str:
    """`send_table`, comments and docstrings dropped.

    The comments in it quote the old behaviour they warn about, so matching
    the raw source finds the warning and reads it as the code. That has caught
    several tests in this suite already.
    """
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "send_table")
    return ast.unparse(fn)


def test_an_error_receipt_keeps_the_rows():
    """The entire point of the frame. A server that took the bytes and stored
    none of them used to be indistinguishable from one that stored all of
    them, and the rows left the retry queue either way."""
    body = _send_table_body()
    assert "mark_sent" in body

    guard = body[:body.index("mark_sent")]
    assert "receipt" in guard, "mark_sent runs before the receipt is considered"
    assert "return" in guard, "an error receipt does not stop the rows being marked sent"


def test_the_receipt_is_read_before_the_socket_closes():
    """`with _ingest_socket() as s` closes at the end of the block. A read
    placed after it would always return nothing, and every batch would report
    as unacknowledged against a server that acknowledged it."""
    body = _send_table_body()
    lines = [line.strip() for line in body.splitlines()]
    open_at = next(i for i, line in enumerate(lines) if "_ingest_socket()" in line)
    read_at = next(i for i, line in enumerate(lines) if "_read_receipt" in line)
    decide_at = next(i for i, line in enumerate(lines) if line.startswith("if receipt"))
    assert open_at < read_at < decide_at


def test_a_missing_receipt_still_marks_the_batch_sent():
    """An agent pointed at a server older than the frame has to keep working.
    Treating silence as failure would make it retry the same rows for ever."""
    body = _send_table_body()
    # The failure path is entered on an error *in* a receipt, never on its
    # absence.
    assert "receipt is not None" in body


def test_the_agent_says_which_kind_of_success_it_had():
    """'sent (50 rows)' meant the same weak thing for months. Where the server
    confirms a count the log should show it, and where it does not the log has
    to say so rather than read identically."""
    body = _send_table_body()
    assert "unacknowledged" in body


# --------------------------------------------------------------------------
# The server half
# --------------------------------------------------------------------------

def _insert_data() -> ast.AsyncFunctionDef:
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    return next(n for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == "insert_data")


def test_insert_data_reports_what_it_stored():
    """It returned None and swallowed every insertion failure into a line
    behind `if debug`, which is off in production. That is how a batch of
    fifty rows failing 1406 on every INSERT was reported to nobody."""
    fn = _insert_data()
    body = ast.unparse(fn)

    assert "'stored': stored" in body or '"stored": stored' in body
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert returns, "insert_data still returns nothing"
    assert all(n.value is not None for n in returns), \
        "a bare `return` leaves the caller unable to tell success from a skip"


def test_a_failed_batch_is_reported_outside_debug():
    """The failure that mattered spent days inside `if debug`."""
    fn = _insert_data()
    reporting = [h for h in ast.walk(fn)
                 if isinstance(h, ast.ExceptHandler)
                 and "data insertion failed" in ast.unparse(h)]
    assert reporting, "the insertion failure message is gone"

    for handler in reporting:
        for node in ast.walk(handler):
            if isinstance(node, ast.If) and "debug" in ast.unparse(node.test):
                pytest.fail("the insertion failure is reported only when debug is on")


def test_the_receipt_write_cannot_break_an_older_fleet():
    """An agent built before the frame closes the connection without reading.
    The write then fails, and that has to be ordinary rather than an error
    that makes every legacy batch look broken."""
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_send_receipt")
    body = ast.unparse(fn)
    assert "try:" in body
    assert "except Exception" in body


# --------------------------------------------------------------------------
# One bad row must not take the batch with it
# --------------------------------------------------------------------------

def test_a_batch_is_fifty_facts_not_one_transaction():
    """A single unstorable row used to roll back the other forty-nine.

    Found by the change above, within seconds of it shipping: making the
    insertion failure visible turned up

        docker_containers: Duplicate entry '3d25565c...' for key
        'docker_containers.uniq_container'

    on a live host. The agent appends a row per container per collection
    cycle and ships fifty at a time, so one batch routinely carries the same
    container several times over. `docker_containers` has UNIQUE(container_id),
    the second copy raised 1062, and the whole batch was discarded - while the
    agent logged `docker_containers sent (8 rows)` every cycle.
    """
    fn = _insert_data()
    body = ast.unparse(fn)
    assert "rejected += 1" in body, \
        "a failing row still aborts the whole batch"

    # The per-row handler has to be inside the loop, not around it.
    loop = next(n for n in ast.walk(fn)
                if isinstance(n, ast.For) and "item" in ast.unparse(n.target))
    handlers = [h for h in ast.walk(loop) if isinstance(h, ast.ExceptHandler)]
    assert any("rejected" in ast.unparse(h) for h in handlers), \
        "nothing catches a single row's failure inside the loop"


def test_a_snapshot_takes_the_last_write():
    """A snapshot holds what is true now, so the same entity arriving twice in
    one batch is the newer picture replacing the older - not a conflict."""
    body = ast.unparse(_insert_data())
    assert "ON DUPLICATE KEY UPDATE" in body
    assert "SNAPSHOT_TABLES" in body


def test_rejected_rows_are_not_retried_for_ever():
    """The other side of reporting them. A row the server cannot store will
    not become storable on the next attempt, so `error` - which is what makes
    the agent keep a batch - must be reserved for a failure of the batch as a
    whole."""
    body = ast.unparse(_insert_data())
    success = body[body.index("conn.commit()"):]
    success = success[:success.index("except Exception")]
    assert "'error': None" in success or '"error": None' in success, \
        "a batch with rejected rows reports an error and will be resent for ever"
