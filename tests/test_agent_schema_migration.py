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

"""A semicolon inside a comment used to cut the statement it was part of.

    agent_name VARCHAR(255) NULL,  -- NULL means global; a value scopes the row

The splitter dropped comment *lines* after cutting the file on `;`, so that
comment's semicolon split `soar_notification_templates` in half. The table was
never created on any agent database, and both fragments came back as syntax
errors on every single ingest - one of them reading

    near 'a value scopes the row to one device'

which is the comment being executed as SQL. Comments are now removed first,
and the split sees only SQL.
"""

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

    Helpers the function calls are lifted with it. Compiling the one function
    alone was fine while the splitters were self-contained; the moment they
    delegated the comment stripping, calling one raised NameError - a failure
    of the harness that reads exactly like a failure of the code.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    top = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    wanted, pending = {}, [name]
    while pending:
        fname = pending.pop()
        if fname in wanted:
            continue
        wanted[fname] = top[fname]
        pending += [n.id for n in ast.walk(top[fname])
                    if isinstance(n, ast.Name) and n.id in top]
    ns: dict = {}
    exec(compile(ast.Module(body=list(wanted.values()), type_ignores=[]),
                 str(path), "exec"), ns)
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


def _both_splitters():
    """The agent's copy and the server's, which must behave identically."""
    return (_load_func(DB_PY, "_split_statements"),
            _load_func(ROOT / "server.py", "_split_sql_statements"))


class TestSemicolonInsideAComment:
    """A comment's semicolon must not cut the statement it sits in.

    The previous splitter dropped comment *lines* after cutting the file on
    `;`, so this line split the table it belongs to in half.
    """

    SCHEMA = (
        "CREATE TABLE IF NOT EXISTS templates (\n"
        "  id INT NOT NULL,\n"
        "  agent_name VARCHAR(255) NULL,  -- NULL means global; a value scopes it\n"
        "  name VARCHAR(150) NOT NULL\n"
        ");\n"
    )

    def test_the_statement_survives_in_one_piece(self):
        for split in _both_splitters():
            out = split(self.SCHEMA)
            assert len(out) == 1, f"the comment's semicolon split it: {out}"
            assert "name VARCHAR(150)" in out[0]

    def test_the_comment_tail_is_not_left_as_a_statement(self):
        """The reported error was `near 'a value scopes the row to one
        device'` - the tail of a comment handed to the database as SQL."""
        for split in _both_splitters():
            for stmt in split(self.SCHEMA):
                assert "a value scopes" not in stmt

    def test_each_shipped_schema_parses_into_sql_only(self):
        """Each splitter against the file it is actually given."""
        agent_split, server_split = _both_splitters()
        starts = {"CREATE", "ALTER", "INSERT", "DROP", "SET", "USE",
                  "UPDATE", "DELETE"}
        for split, schema in ((agent_split, INIT_SQL),
                              (server_split, ROOT / "db" / "init.sql")):
            for stmt in split(schema.read_text(encoding="utf-8")):
                first = stmt.lstrip().split(None, 1)[0].upper()
                assert first in starts, \
                    f"{schema.name}: not a statement: {stmt[:80]!r}"

    def test_the_table_that_was_lost_is_created(self):
        """The comment that carried the semicolon is in the server's schema -
        db/init.sql, which create_tables_if_not_exist applies to every
        per-agent database. The agent's own postgres schema has no such
        comment, so its copy of the splitter carried the trap without ever
        tripping it."""
        sql = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
        split = _load_func(ROOT / "server.py", "_split_sql_statements")
        assert any("soar_notification_templates" in s for s in split(sql)), \
            "the table whose comment carried the semicolon is missing again"

    def test_a_dash_dash_inside_a_string_literal_is_left_alone(self):
        """Stripping inside a literal would corrupt data, not just a note."""
        for split in _both_splitters():
            out = split("INSERT INTO t (a) VALUES ('not -- a comment');\n")
            assert len(out) == 1
            assert "-- a comment" in out[0]
