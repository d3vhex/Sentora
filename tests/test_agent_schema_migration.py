"""Guards on the agent's local schema migration.

The agent had no migration path. Its postgres mounts db/init.sql into
docker-entrypoint-initdb.d, which postgres runs *only* when the data
directory is empty - so on any machine where the agent had run before, a
column added in a later release never appeared. The agent then failed every
insert:

    column "severity" of relation "siem_events" does not exist

into its own log, where nothing on the server could see it. Telemetry stopped
while the platform still reported the agent as healthy. That combination -
broken and silent - is the reason this is tested rather than assumed.

The schema is read from disk and the module source is parsed; nothing here
needs a live postgres.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "Sentora"
INIT_SQL = AGENT / "db" / "init.sql"
DB_PY = AGENT / "modules" / "db.py"
MAIN_PY = AGENT / "main.py"
BUILD_PS1 = AGENT / "build_agent.ps1"


def _statements() -> list[str]:
    """Mirror what apply_schema executes.

    This used to filter chunks starting with "--", the same way apply_schema
    did - so the test agreed with the bug: 19 statements that the migration
    silently skipped were also invisible to the test checking the migration.
    Both now strip comment lines and keep what is left.
    """
    sql = INIT_SQL.read_text(encoding="utf-8")
    out = []
    for chunk in sql.split(";"):
        body = "\n".join(l for l in chunk.splitlines()
                         if not l.strip().startswith("--")).strip()
        if body:
            out.append(body)
    return out


def _load_func(path: pathlib.Path, name: str):
    """Compile one function out of a module without importing the module.

    The agent's package is not importable from the test environment, and
    `modules.db` would try to open a postgres connection at import time. Both
    splitters are pure functions over a string, so the function body is
    lifted out and compiled on its own - which keeps this file's promise that
    nothing here needs a live database.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns: dict = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(path), "exec"), ns)
    return ns[name]


def test_the_schema_file_exists():
    assert INIT_SQL.exists(), f"{INIT_SQL} is what the agent applies at start"


@pytest.mark.parametrize("index", range(len(_statements())))
def test_every_statement_is_re_runnable(index):
    """apply_schema runs the whole file on every start, so a statement that
    fails the second time would log an error on every launch and mask the
    ones that matter.

    `IF NOT EXISTS` covers almost everything. The exception is a CHECK
    constraint: Postgres has no `ADD CONSTRAINT IF NOT EXISTS`, and the
    obvious workaround - a `DO $$ ... $$` block catching duplicate_object -
    cannot be used here, because apply_schema splits the file on `;` and a DO
    block contains them.

    So `DROP CONSTRAINT IF EXISTS` immediately followed by the matching `ADD
    CONSTRAINT` is accepted: the pair is re-runnable even though the second
    statement is not, which is what the agent actually executes. The pairing
    is checked rather than assumed, so an ADD without its DROP still fails.
    """
    statements = _statements()
    stmt = statements[index]
    head = " ".join(stmt.split())[:80]

    if re.search(r"IF NOT EXISTS", stmt, re.I):
        return

    # DROP ... IF EXISTS is idempotent by the same logic, just spelled without
    # the NOT.
    if re.search(r"DROP\s+\w+\s+IF\s+EXISTS", stmt, re.I):
        return

    add = re.search(r"ADD\s+CONSTRAINT\s+(\w+)", stmt, re.I)
    if add:
        name = add.group(1)
        previous = statements[index - 1] if index else ""
        assert re.search(rf"DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+{name}\b",
                         previous, re.I), (
            f"ADD CONSTRAINT {name} is not preceded by a matching "
            f"DROP CONSTRAINT IF EXISTS, so re-running the file fails: {head}"
        )
        return

    pytest.fail(f"not idempotent: {head}")


def test_severity_is_in_the_agent_schema():
    """The column whose absence stopped telemetry. Pinned by name because the
    failure was invisible from the server side."""
    sql = INIT_SQL.read_text(encoding="utf-8")
    siem = sql[sql.index("siem_events"):]
    assert re.search(r"ADD COLUMN IF NOT EXISTS\s+severity", siem, re.I), \
        "siem_events has no guarded severity column"


# --------------------------------------------------------------------------
# The migration function
# --------------------------------------------------------------------------

DB_SRC = DB_PY.read_text(encoding="utf-8")
DB_TREE = ast.parse(DB_SRC)


def test_apply_schema_exists_and_is_exported():
    assert any(isinstance(n, ast.FunctionDef) and n.name == "apply_schema"
               for n in DB_TREE.body)


def test_each_statement_runs_in_its_own_transaction():
    """Postgres aborts the entire transaction on any error, so one statement
    the agent cannot apply would silently discard every migration after it."""
    fn = next(n for n in DB_TREE.body
              if isinstance(n, ast.FunctionDef) and n.name == "apply_schema")
    src = ast.unparse(fn)
    assert "autocommit" in src, \
        "without autocommit a single failure discards the remaining statements"


def test_a_failed_statement_does_not_raise():
    """A schema the agent cannot fully apply must not stop it collecting what
    it can."""
    fn = next(n for n in DB_TREE.body
              if isinstance(n, ast.FunctionDef) and n.name == "apply_schema")
    handlers = [h for n in ast.walk(fn) if isinstance(n, ast.Try) for h in n.handlers]
    assert handlers, "apply_schema has no error handling"
    for h in handlers:
        assert not any(isinstance(x, ast.Raise) for x in ast.walk(h)), \
            "a failed statement is re-raised, which would stop the agent"


def test_it_finds_the_schema_inside_a_pyinstaller_bundle():
    """The agent ships as a onefile exe; a path relative to __file__ points
    into the extracted temp dir only if _MEIPASS is consulted."""
    assert "_MEIPASS" in DB_SRC


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

def test_main_applies_the_schema_before_collectors_write():
    """Ordering matters: a collector that starts first writes against the old
    schema and fails."""
    src = MAIN_PY.read_text(encoding="utf-8")
    assert "apply_schema" in src, "main.py never applies the schema"
    assert src.index("apply_schema") < src.index("Starting agent"), \
        "the schema is applied after the agent starts collecting"


def test_the_build_bundles_the_schema():
    """Without db/ in --add-data the shipped binary has no init.sql to apply,
    and the migration silently does nothing in exactly the deployment that
    needs it."""
    ps = BUILD_PS1.read_text(encoding="utf-8")
    assert "dbPath" in ps and ";db" in ps, "build_agent.ps1 does not bundle db/"


# --------------------------------------------------------------------------
# The splitter
# --------------------------------------------------------------------------

class TestStatementSplitting:
    """A documented statement must not be skipped along with its comment.

    `apply_schema` skipped any chunk beginning with `--`, meaning to drop
    comment-only chunks. Splitting on `;` keeps a statement's leading comment
    in the same chunk, so every statement with an explanatory comment above it
    was discarded - 19 of 52, including siem_events, events_alert,
    soar_actions and docker_containers.

    It reported "33 statements, 0 skipped" throughout, because the 19 were
    never counted as statements at all. It escaped notice only because those
    tables already existed from the initdb run on a fresh data directory.
    """

    def test_a_documented_statement_survives(self):
        _split_statements = _load_func(DB_PY, "_split_statements")
        out = _split_statements(
            "-- why this table exists\n"
            "CREATE TABLE IF NOT EXISTS t (a int);"
        )
        assert len(out) == 1 and out[0].startswith("CREATE TABLE")

    def test_a_comment_only_chunk_is_dropped(self):
        """The behaviour the broken version was reaching for."""
        _split_statements = _load_func(DB_PY, "_split_statements")
        assert _split_statements("-- just a banner\n-- and another line\n") == []

    def test_trailing_comments_do_not_create_empty_statements(self):
        _split_statements = _load_func(DB_PY, "_split_statements")
        out = _split_statements("CREATE TABLE IF NOT EXISTS t (a int);\n-- done\n")
        assert out == ["CREATE TABLE IF NOT EXISTS t (a int)"]

    def test_comments_between_statements_do_not_merge_them(self):
        _split_statements = _load_func(DB_PY, "_split_statements")
        out = _split_statements(
            "CREATE TABLE IF NOT EXISTS a (x int);\n"
            "-- second table\n"
            "CREATE TABLE IF NOT EXISTS b (y int);"
        )
        assert len(out) == 2
        assert out[0].startswith("CREATE TABLE IF NOT EXISTS a")
        assert out[1].startswith("CREATE TABLE IF NOT EXISTS b")

    def test_the_real_schema_yields_every_create(self):
        """The regression, measured against the file that exposed it."""
        _split_statements = _load_func(DB_PY, "_split_statements")
        sql = INIT_SQL.read_text(encoding="utf-8")
        parsed = _split_statements(sql)
        # Counted on non-comment lines only. Counting the raw text picks up
        # prose that happens to name the statement - the note explaining that
        # "CREATE TABLE IF NOT EXISTS leaves the old CHECK in place" was
        # counted as a twentieth table.
        code = "\n".join(l for l in sql.splitlines()
                         if not l.strip().startswith("--"))
        creates_in_file = code.upper().count("CREATE TABLE IF NOT EXISTS")
        creates_parsed = sum(s.upper().count("CREATE TABLE IF NOT EXISTS")
                             for s in parsed)
        assert creates_parsed == creates_in_file, (
            f"{creates_in_file - creates_parsed} CREATE statement(s) would "
            f"never be applied"
        )

    def test_the_server_splitter_agrees(self):
        """server.py keeps its own copy; the two must not drift."""
        _split = _load_func(ROOT / "server.py", "_split_sql_statements")
        out = _split(
            "-- documented\nCREATE TABLE IF NOT EXISTS t (a int);\n-- banner only\n"
        )
        assert out == ["CREATE TABLE IF NOT EXISTS t (a int)"]
