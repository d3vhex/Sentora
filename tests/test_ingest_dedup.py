"""Deduplication that could never match anything.

`DEDUP_TABLES` names the tables the server is supposed to skip a repeat of, and
`compute_fingerprint` decided what "a repeat" meant by hashing the row as it
arrived. That cannot work, for two independent reasons:

  - encrypted columns arrive as `enc::gAAAA...`, and Fernet uses a random IV,
    so the same plaintext encrypts differently every single time;
  - `timestamp` / `created_at` are stamped per collection cycle, so even a
    table with nothing encrypted in it changes on every send.

Either one makes the hash unique by construction. Measured on a live host
before the fix:

    packages             249,980 rows stored,   167 distinct agent fingerprints
    software_inventory   161,157 rows stored,   313 distinct programs
    network_inventory     37,225 rows stored,    79 distinct ports
    ingest_fingerprint   one row per row received, none of them ever matched

`packages` is the one to read twice: the agent had been computing a perfectly
good `dup_fp` for it all along - 167 values for a quarter of a million rows -
and the server threw it away and hashed the ciphertext instead.

So there are two halves, and each has its own section below: the server has to
prefer the agent's `dup_fp`, and every deduplicated table has to carry one.

The second half is checked through the AST rather than by regex. The previous
version of this file matched `insert_record\\(["']<table>["']` and so was blind
to the five writers that pass a `TABLE` constant - including the two this
change was about. A regex over source also matches prose in comments, which has
produced a passing test over broken code here twice now.
"""
from __future__ import annotations

import ast
import hashlib
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"
AGENT = ROOT / "Sentora"
ENC_DB = AGENT / "modules" / "enc_db.py"

#: The two ways a row reaches the local database.
INSERT_CALLS = {"insert_record", "insert_record_enc"}


def _lift(source: pathlib.Path, name: str, **extra):
    """Execute one function out of a file, without importing the file.

    Both of these modules pull in the whole agent or the whole server at import
    time; the functions themselves need nothing but the standard library and,
    for the repair, the two module constants passed in as `extra`.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns: dict = {"hashlib": hashlib, "json": json, "_json_default": str, **extra}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), "exec"), ns)
    return ns[name]


def _literal(source: pathlib.Path, name: str):
    for node in ast.parse(source.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a module-level literal in {source.name}")


DEDUP_TABLES = set(_literal(SERVER, "DEDUP_TABLES"))
SNAPSHOT_TABLES = set(_literal(SERVER, "SNAPSHOT_TABLES"))
FINGERPRINTED_TABLES = set(_literal(ENC_DB, "FINGERPRINTED_TABLES"))


# --------------------------------------------------------------------------
# The server has to use the value the agent computed
# --------------------------------------------------------------------------

def test_the_agents_fingerprint_wins():
    compute = _lift(SERVER, "compute_fingerprint")
    assert compute("packages", {"package": "x", "dup_fp": "abc123"}) == "abc123"


def test_the_same_row_at_two_timestamps_is_one_fingerprint():
    """The bug, in one assertion. Two sends of the same program differ only in
    the timestamp the agent stamped on them."""
    compute = _lift(SERVER, "compute_fingerprint")
    first = compute("software_inventory", {
        "name": "Google Chrome", "version": "131.0.1",
        "timestamp": "2026-09-15 01:00:00", "dup_fp": "stable-value"})
    second = compute("software_inventory", {
        "name": "Google Chrome", "version": "131.0.1",
        "timestamp": "2026-09-15 02:00:00", "dup_fp": "stable-value"})
    assert first == second


def test_the_same_plaintext_encrypted_twice_is_one_fingerprint():
    """Fernet embeds a random IV, so this is not a contrived case - it is what
    every encrypted table does on every send."""
    compute = _lift(SERVER, "compute_fingerprint")
    a = compute("siem_events", {"message": "enc::gAAAAABmFIRST...",
                                "dup_fp": "content-hash"})
    b = compute("siem_events", {"message": "enc::gAAAAABmSECOND...",
                                "dup_fp": "content-hash"})
    assert a == b


def test_a_row_without_one_still_gets_a_fingerprint():
    """The fallback has to stay. A table whose producer sets nothing must not
    crash ingest; it just cannot be deduplicated reliably, which is what the
    writer check below is about."""
    compute = _lift(SERVER, "compute_fingerprint")
    value = compute("packages", {"package": "x", "version": "1"})
    assert isinstance(value, str)
    assert len(value) == 64


def test_an_empty_dup_fp_falls_back_rather_than_collapsing():
    """Every row carrying `dup_fp = ""` would otherwise share one fingerprint,
    and the first row of the table would suppress all the others."""
    compute = _lift(SERVER, "compute_fingerprint")
    a = compute("packages", {"package": "a", "dup_fp": ""})
    b = compute("packages", {"package": "b", "dup_fp": "   "})
    assert a != b


# --------------------------------------------------------------------------
# The agent's identity helper
# --------------------------------------------------------------------------

def test_identity_depends_on_the_table():
    """Two tables that happen to hold the same words are not the same row."""
    identity = _lift(ENC_DB, "identity_fingerprint")
    assert identity("software_inventory", "a") != identity("packages", "a")


def test_identity_is_stable_across_calls():
    """Trivially true today, and the thing that must not stop being true: a
    clock reading or a per-process salt in here would reproduce the original
    bug exactly, with a fingerprint that is new on every send."""
    identity = _lift(ENC_DB, "identity_fingerprint")
    first = identity("t", "a", "b")
    second = identity("t", "a", "b")
    assert first == second


def test_identity_distinguishes_field_order():
    """`a|b` and `b|a` must not collide - version and vendor are both free
    text and a program can easily put one where the other belongs."""
    identity = _lift(ENC_DB, "identity_fingerprint")
    assert identity("t", "a", "b") != identity("t", "b", "a")


def test_identity_treats_none_as_empty_rather_than_the_word():
    """A vendor that is absent one cycle and blank the next is one program,
    not two. `str(None)` would have made it two."""
    identity = _lift(ENC_DB, "identity_fingerprint")
    assert identity("t", "x", None) == identity("t", "x", "")


def test_identity_accepts_numbers():
    """Ports and PIDs arrive as ints. The helper stringifies so the callers do
    not have to remember to, which is the sort of thing one caller forgets."""
    identity = _lift(ENC_DB, "identity_fingerprint")
    assert identity("t", 443) == identity("t", "443")


# --------------------------------------------------------------------------
# Every deduplicated table has to carry one
# --------------------------------------------------------------------------

#: Deduplicated tables whose writer deliberately sets no `dup_fp`, with the
#: reason. The server then hashes the row, which is correct only where every
#: row genuinely is a distinct event.
NO_FINGERPRINT_ON_PURPOSE = {
    "soar_actions":
        "An action taken is a one-off event - a row per containment, each with "
        "its own event id and moment. There is no earlier row it could be a "
        "repeat of, so hashing the row is the right identity.",
}


def _agent_modules():
    for path in sorted(AGENT.rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def _module_constants(tree: ast.Module) -> dict:
    """Module-level `NAME = "literal"`, so `insert_record(TABLE, ...)` resolves.

    Five of the agent's writers name their table this way, and the regex this
    check replaced could not see any of them.
    """
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = node.value.value
    return out


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):          # enc_db.insert_record_enc(...)
        return func.attr
    return ""


def _writes() -> dict:
    """table -> list of (path, enclosing function, sets_dup_fp, encrypted_path).

    A call belongs to the innermost function containing it; `sets_dup_fp` asks
    whether that function mentions `dup_fp` anywhere, because several writers
    build the row first and set the fingerprint on it afterwards.
    """
    found: dict = {}

    for path, tree in _agent_modules():
        constants = _module_constants(tree)
        stack: list = []
        owner: dict = {}

        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                stack.append(node)
                self.generic_visit(node)
                stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node):
                if stack:
                    owner.setdefault(id(stack[-1]), (stack[-1], []))[1].append(node)
                self.generic_visit(node)

        Visitor().visit(tree)

        for fn, calls in owner.values():
            # `dup_fp` as an identifier or a string key, never as a comment -
            # ast.dump has already thrown the comments away, which is the point.
            mentions = "dup_fp" in ast.dump(fn)
            for call in calls:
                name = _call_name(call)
                if name not in INSERT_CALLS or not call.args:
                    continue
                arg = call.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    table = arg.value
                elif isinstance(arg, ast.Name) and arg.id in constants:
                    table = constants[arg.id]
                else:
                    continue
                found.setdefault(table, []).append(
                    (path, fn.name, mentions, name == "insert_record_enc"))
    return found


WRITES = _writes()


@pytest.mark.parametrize("table", sorted(DEDUP_TABLES))
def test_a_dedup_table_carries_a_fingerprint_from_the_agent(table):
    """Either the writer sets `dup_fp`, or `insert_record_enc` sets it.

    Without one the server falls back to hashing the row, which includes the
    timestamp, which means the table is listed as deduplicated and is not.
    That is worse than not listing it: the console shows hundreds of copies of
    the same program while every layer reports success.
    """
    if table in NO_FINGERPRINT_ON_PURPOSE:
        pytest.skip(NO_FINGERPRINT_ON_PURPOSE[table])

    writers = WRITES.get(table)
    if not writers:
        pytest.skip(f"{table} is not written by this agent")

    if table in FINGERPRINTED_TABLES:
        return                                   # insert_record_enc sets it

    uncovered = [f"{p.relative_to(ROOT)}:{fn}()"
                 for p, fn, mentions, _ in writers if not mentions]
    assert not uncovered, (
        f"{table} is in DEDUP_TABLES and {', '.join(uncovered)} sets no "
        f"dup_fp. The server will hash the row instead - including its "
        f"timestamp - so every send is a new row."
    )


@pytest.mark.parametrize("table", sorted(FINGERPRINTED_TABLES))
def test_an_automatically_fingerprinted_table_goes_through_the_encrypted_writer(table):
    """`FINGERPRINTED_TABLES` is consulted inside `insert_record_enc` alone.

    A table listed there whose writer calls plain `insert_record` gets nothing,
    and reads as covered from every angle except the database. This is the same
    shape of mistake as the one the file is about, so it gets its own check
    rather than a comment.
    """
    writers = WRITES.get(table)
    if not writers:
        pytest.skip(f"{table} is not written by this agent")

    plain = [f"{p.relative_to(ROOT)}:{fn}()"
             for p, fn, mentions, enc in writers if not enc and not mentions]
    assert not plain, (
        f"{table} is in FINGERPRINTED_TABLES but {', '.join(plain)} writes it "
        f"with insert_record(), which does not set one."
    )


@pytest.mark.parametrize("table", sorted(FINGERPRINTED_TABLES))
def test_nothing_is_fingerprinted_that_is_not_deduplicated(table):
    """Hashing a row the server will not deduplicate is wasted work, and more
    to the point it suggests one of the two lists has drifted."""
    assert table in DEDUP_TABLES, (
        f"{table} computes a fingerprint the server never looks at - it is "
        f"not in DEDUP_TABLES."
    )


def test_the_two_collectors_that_were_missing_one_have_it():
    """Named individually, because these are the two that were actually wrong
    and the generic check above would also pass if they were deleted."""
    for table in ("software_inventory", "network_inventory"):
        writers = WRITES.get(table)
        assert writers, f"{table} is no longer written by the agent"
        assert all(mentions for _, _, mentions, _ in writers), \
            f"{table} is written without a fingerprint again"


def _identity_call(table: str) -> ast.Call:
    src = (AGENT / "modules" / "inventory.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and _call_name(node) == "identity_fingerprint" \
                and node.args and isinstance(node.args[0], ast.Constant) \
                and node.args[0].value == table:
            return node
    raise AssertionError(f"no identity_fingerprint call for {table}")


def test_the_fingerprint_excludes_what_moves_on_its_own():
    """A PID changes when a service restarts and a timestamp changes every
    cycle. Either in the identity turns the same listener into a new row, which
    is the original bug wearing different clothes."""
    call = ast.dump(_identity_call("network_inventory"))
    assert "'pid'" not in call, "the PID is back in the network identity"
    assert "timestamp" not in call


def test_the_software_identity_is_the_program_not_the_moment():
    call = ast.dump(_identity_call("software_inventory"))
    assert "timestamp" not in call
    assert "install_date" not in call, (
        "install_date is derived from a file mtime on Linux, so a reinstall "
        "would list the same program a second time."
    )


def test_a_table_is_never_both_snapshotted_and_deduplicated():
    """The server asserts this at import. Repeated here so the reason arrives
    with the tests rather than only as a container that will not start."""
    assert not (SNAPSHOT_TABLES & DEDUP_TABLES)


# --------------------------------------------------------------------------
# Clearing out what the broken fingerprint already stored
# --------------------------------------------------------------------------
#
# Fixing ingest stops the pile growing. Nothing shrinks it, so without this the
# console still shows 515 copies of every program and the bug is, as far as
# anyone using it can tell, not fixed at all.

RE_REPORTED_TABLES = tuple(_literal(SERVER, "_RE_REPORTED_TABLES"))
DEDUP_REPAIR = _literal(SERVER, "_DEDUP_REPAIR")


REPAIR_CHUNK = _literal(SERVER, "_REPAIR_CHUNK")


class _FakeCursor:
    """Enough of a MySQL cursor to watch what the repair does, in order.

    `deleted` is what a DELETE reports back: 0 for a database with nothing left
    to clean, a positive number for one still working through the pile.
    """

    def __init__(self, *, marker_present=False, tables=(), deleted=0):
        self.sql: list = []
        self._marker = marker_present
        self._tables = tables
        self._deleted = deleted
        self._rows: list = []
        self.rowcount = 0

    def execute(self, sql, params=()):
        flat = " ".join(sql.split())
        self.sql.append(flat)
        low = flat.lower()
        self.rowcount = self._deleted if low.startswith("delete from `") else 0
        if "from ingest_migration" in low:
            self._rows = [(1,)] if self._marker else []
        elif "information_schema.tables" in low:
            self._rows = [(t,) for t in self._tables]
        else:
            self._rows = []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


def _repair():
    return _lift(SERVER, "_repair_rows_stored_without_a_fingerprint",
                 _RE_REPORTED_TABLES=RE_REPORTED_TABLES,
                 _DEDUP_REPAIR=DEDUP_REPAIR,
                 _REPAIR_CHUNK=REPAIR_CHUNK)


def test_the_repair_does_nothing_once_it_has_run():
    """It is called from `create_tables_if_not_exist`, which is on the ingest
    path. A repeat has to cost one primary-key lookup, not a self-join over a
    quarter of a million rows."""
    cursor = _FakeCursor(marker_present=True, tables=RE_REPORTED_TABLES)
    _repair()(cursor, "agent_db")
    assert not any("DELETE" in s for s in cursor.sql)


def test_the_repair_marks_itself_done_only_at_the_end():
    """Claiming the marker first would turn a half-finished repair into a
    permanent one - the rows stay, and nothing ever comes back to them."""
    cursor = _FakeCursor(tables=RE_REPORTED_TABLES)
    _repair()(cursor, "agent_db")
    written = [i for i, s in enumerate(cursor.sql)
               if s.startswith("INSERT IGNORE INTO ingest_migration")]
    assert written, "the repair never records that it ran"
    assert written[0] == len(cursor.sql) - 1


@pytest.mark.parametrize("table", RE_REPORTED_TABLES)
def test_the_repair_handles_both_kinds_of_stored_row(table):
    """Rows with a fingerprint collapse onto it; rows without one cannot be
    grouped at all and go. Then the table's fingerprints are rebuilt from what
    survived, because the old ones are row hashes that can never recur."""
    cursor = _FakeCursor(tables=RE_REPORTED_TABLES)
    _repair()(cursor, "agent_db")
    mine = [s for s in cursor.sql if f"`{table}`" in s]

    assert any("GROUP BY dup_fp" in s and "NOT IN" in s for s in mine), \
        "duplicates sharing a fingerprint are not collapsed"
    assert any(f"DELETE FROM `{table}` WHERE dup_fp IS NULL" in s for s in mine), \
        "rows stored before the agent set a fingerprint are left behind"
    assert any(s.startswith("INSERT IGNORE INTO ingest_fingerprint") for s in mine), \
        "the survivors' fingerprints are never recorded, so the next send " \
        "stores every one of them again"


def test_the_repair_rebuilds_fingerprints_only_once_a_table_is_clean():
    """The other order records fingerprints for rows that are about to be
    deleted in the next chunk, which leaves the table both emptied and unable
    to accept the collector's re-report: every row it sends is recognised as
    one already held."""
    cursor = _FakeCursor(tables=RE_REPORTED_TABLES, deleted=REPAIR_CHUNK)
    _repair()(cursor, "agent_db")
    assert not any(s.startswith("INSERT IGNORE INTO ingest_fingerprint")
                   for s in cursor.sql)


def test_a_pass_with_rows_left_does_not_mark_itself_done():
    """Otherwise a database too big for one chunk keeps the 400,000 rows it
    started with and never looks at them again."""
    cursor = _FakeCursor(tables=RE_REPORTED_TABLES, deleted=REPAIR_CHUNK)
    _repair()(cursor, "agent_db")
    assert not any(s.startswith("INSERT IGNORE INTO ingest_migration")
                   for s in cursor.sql)


@pytest.mark.parametrize("table", RE_REPORTED_TABLES)
def test_every_delete_is_bounded(table):
    """`create_tables_if_not_exist` is called from the ingest handler. An
    unbounded DELETE across a quarter of a million rows times out the send that
    triggered it; the agent retries, the repair restarts from the top, and it
    never finishes while every ingest pays for the attempt.
    """
    cursor = _FakeCursor(tables=RE_REPORTED_TABLES)
    _repair()(cursor, "agent_db")
    for statement in cursor.sql:
        if statement.startswith(f"DELETE FROM `{table}`"):
            assert statement.endswith(f"LIMIT {REPAIR_CHUNK}"), \
                f"unbounded delete: {statement}"


def test_the_repair_skips_a_table_the_database_does_not_have():
    cursor = _FakeCursor(tables=("packages",))
    _repair()(cursor, "agent_db")
    assert not any("`software_inventory`" in s for s in cursor.sql)


def test_the_repair_never_touches_a_change_log_table():
    """The load-bearing constraint. The agent marks a row sent once and never
    offers it again, so a row deleted from `fim_data` or `critical_files` is
    gone - there is no cycle that brings it back the way the inventory pair
    comes back in ten minutes.
    """
    every_table = DEDUP_TABLES | SNAPSHOT_TABLES
    cursor = _FakeCursor(tables=sorted(every_table))
    _repair()(cursor, "agent_db")

    deletes = [s for s in cursor.sql if s.startswith("DELETE")]
    for table in every_table - set(RE_REPORTED_TABLES):
        assert not any(f"`{table}`" in s for s in deletes), \
            f"the repair deletes from {table}, which is never re-reported"


@pytest.mark.parametrize("table", RE_REPORTED_TABLES)
def test_a_re_reported_table_really_is_re_reported(table):
    """The claim that makes deleting safe, checked against the collector.

    A writer guarded by a local duplicate check reports each thing once and
    then never again, which is the opposite of what this list asserts. That is
    exactly what `portscan_result` and `critical_files` do, and why they are
    not in it.
    """
    writers = WRITES.get(table)
    assert writers, f"{table} has no agent writer; it cannot re-report anything"

    for path, fn, _, _ in writers:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next(n for n in ast.walk(tree)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name == fn)
        guards = {_call_name(c) for c in ast.walk(node) if isinstance(c, ast.Call)}
        assert "is_duplicate" not in guards, (
            f"{path.name}:{fn}() skips rows it has already reported, so the "
            f"rows this repair deletes from {table} would never come back."
        )
