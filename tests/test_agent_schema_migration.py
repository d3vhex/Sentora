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
    sql = INIT_SQL.read_text(encoding="utf-8")
    return [s.strip() for s in sql.split(";")
            if s.strip() and not s.strip().startswith("--")]


def test_the_schema_file_exists():
    assert INIT_SQL.exists(), f"{INIT_SQL} is what the agent applies at start"


@pytest.mark.parametrize("stmt", _statements())
def test_every_statement_is_re_runnable(stmt):
    """apply_schema runs the whole file on every start, so a statement that
    fails the second time would log an error on every launch and mask the
    ones that matter."""
    head = " ".join(stmt.split())[:80]
    assert re.search(r"IF NOT EXISTS", stmt, re.I), f"not idempotent: {head}"


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
