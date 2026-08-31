"""`db/init.sql` runs on every ingest, so it must contain no ALTER at all.

`create_tables_if_not_exist` re-executes the whole file each time an agent
posts data - not once at boot. Every bare ALTER left in it therefore ran
several times a minute against a live database, and did so in two flavours,
only one of which was visible:

    ALTER TABLE siem_events ADD COLUMN severity VARCHAR(16) NULL;

which failed every time with `1060 Duplicate column name` and printed it,
four such lines per ingest, drowning the log the operator would have to read
to notice a *real* schema error; and

    ALTER TABLE soar_actions MODIFY COLUMN expires_at TIMESTAMP NULL;

which raised nothing at all, and was labelled "idempotent" on that basis. It
was not free. MySQL takes a metadata lock for a MODIFY whether or not the
type changes, and a waiting DDL blocks every reader queued behind it - which
is precisely how `ALTER TABLE automations` once made /automations/pending stop
answering agents until Sanic gave up with a 500.

The rule this file enforces: schema changes for existing deployments live in
guarded `_migrate_*` functions in server.py, which ask information_schema
first and touch the table only when there is something to change.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
INIT_SQL = ROOT / "db" / "init.sql"
SERVER_PY = ROOT / "server.py"

# Every guarded migration create_tables_if_not_exist runs, and the table each
# one is allowed to touch.
MIGRATIONS = {
    "_migrate_automation_status": "automations",
    "_migrate_siem_events": "siem_events",
    "_migrate_soar_actions": "soar_actions",
}


def _sql_only(text: str) -> str:
    """The schema file with its comment lines removed.

    Matching the raw text finds the prose *explaining* where a migration
    moved to and reports it as the migration itself.
    """
    return "\n".join(l for l in text.splitlines()
                     if not l.strip().startswith("--"))


def test_the_schema_file_has_no_alter_left_in_it():
    code = _sql_only(INIT_SQL.read_text(encoding="utf-8"))
    strays = re.findall(r"ALTER\s+TABLE\s+(\w+)", code, re.I)
    assert not strays, (
        f"ALTER on {sorted(set(strays))} runs on every ingest: it locks the "
        f"table, and if it is an ADD it also errors once the change is applied"
    )


def _code_of(name: str) -> str:
    """The function's statements, without its docstring.

    Every one of these migrations explains in prose the ALTER it replaced, so
    matching the raw source finds the explanation and reads it as the code.
    """
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    body = fn.body
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)):
        body = body[1:]
    return "\n".join(ast.unparse(n) for n in body)


@pytest.mark.parametrize("name,table", MIGRATIONS.items())
def test_each_migration_asks_before_it_alters(name, table):
    code = _code_of(name).upper()

    assert "INFORMATION_SCHEMA" in code, (
        f"{name} alters {table} unconditionally; on a database that is "
        f"already correct that is a metadata lock and a logged error per ingest"
    )
    assert code.index("INFORMATION_SCHEMA") < code.index("ALTER TABLE"), (
        f"{name} checks after altering, which is not a guard"
    )
    assert "LOCK_WAIT_TIMEOUT" in code, (
        f"{name} can queue behind an open transaction on {table} and block "
        f"every reader that arrives after it"
    )
    assert f"{name}(cursor" in SERVER_PY.read_text(encoding="utf-8"), \
        f"{name} is never called"


def test_the_columns_the_migrations_add_are_also_in_the_create():
    """A fresh database never runs the migrations, so the CREATE must be
    complete on its own. Removing an ALTER from init.sql is only safe while
    this holds."""
    text = INIT_SQL.read_text(encoding="utf-8")
    block = re.search(
        r"CREATE TABLE IF NOT EXISTS siem_events\s*\((.*?)\n\)", text, re.S)
    assert block, "siem_events not found"
    for column in ("severity", "techniques"):
        assert re.search(rf"\b{column}\s+VARCHAR", block.group(1)), column
    for index in ("idx_siem_sev", "idx_siem_tech"):
        assert index in block.group(1), index


def test_soar_actions_timestamps_are_nullable_in_the_create():
    text = INIT_SQL.read_text(encoding="utf-8")
    block = re.search(
        r"CREATE TABLE IF NOT EXISTS soar_actions\s*\((.*?)\n\)", text, re.S)
    assert block, "soar_actions not found"
    for column in ("expires_at", "resolved_at"):
        m = re.search(rf"\b{column}\s+([A-Z]+)([^,\n]*)", block.group(1))
        assert m, column
        assert "NOT NULL" not in m.group(2).upper(), (
            f"{column} is NOT NULL in the CREATE, so a fresh database needs "
            f"the migration it will never run"
        )


def test_os_info_is_not_guarded_with_mariadb_syntax():
    """`ADD COLUMN IF NOT EXISTS` is MariaDB; against MySQL it is a syntax
    error. Behind a bare `except: pass` that meant the column was never added
    on any deployment predating it, silently - the OS column just stayed empty
    for those agents.

    Comment lines are dropped first: the note left where that call used to be
    quotes the clause it warns about.
    """
    code = "\n".join(l for l in SERVER_PY.read_text(encoding="utf-8").splitlines()
                     if not l.strip().startswith("#"))
    assert "ADD COLUMN IF NOT EXISTS" not in code, (
        "MySQL rejects this outright, so the migration never applies"
    )
