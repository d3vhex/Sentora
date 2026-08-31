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
    "_migrate_agent_info": "agent_info",
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


def test_the_check_in_path_does_not_alter_on_every_call():
    """`update_agent_info` ran three ALTERs behind `except Exception: pass` on
    every agent check-in - three failed statements and three metadata locks
    per report, at whatever rate the fleet checks in."""
    server = SERVER_PY.read_text(encoding="utf-8")
    start = server.index("def update_agent_info")
    body = server[start:server.index("\ndef ", start + 1)]
    assert "ALTER TABLE" not in body.upper(), (
        "update_agent_info still migrates its own table on every check-in"
    )


def test_the_columns_the_check_in_writes_are_in_the_create():
    """hostname, mac_address and reported_ip are named by that INSERT. They
    used to be added by the ALTERs above, so a fresh database depended on
    those running first - and a guard that correctly does nothing would then
    have broken the very first check-in."""
    server = SERVER_PY.read_text(encoding="utf-8")
    block = re.search(
        r"CREATE TABLE IF NOT EXISTS agent_info\s*\((.*?)\n\s*\)", server, re.S)
    assert block, "agent_info CREATE not found"
    for column in ("reported_ip", "os_info", "hostname", "mac_address"):
        assert column in block.group(1), f"{column} is written but never created"


def test_the_playbook_routes_do_not_alter_on_every_request():
    """`ensure_playbooks_table` is called from every playbook route, and both
    columns are in its CREATE - so the two ALTERs it used to run failed on
    every request and locked the table to do it."""
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    start = app.index("async def ensure_playbooks_table")
    body = app[start:app.index("\ndef ", start + 1)]
    assert "information_schema" in body, "the migration is unguarded"
    assert body.index("information_schema") < body.upper().index("ALTER TABLE"), \
        "it checks after altering, which is not a guard"
    assert "lock_wait_timeout" in body
    assert "except Exception:\n        pass" not in body, \
        "a migration that fails silently becomes a failing SELECT elsewhere"


def _server_code_only() -> str:
    """server.py with its comments and docstrings removed.

    Both are prose, and the migrations here document the broken DDL they
    replaced by quoting it. Matching the raw file reads the warning as the
    thing being warned about.
    """
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            del body[0]
    return ast.unparse(tree)


def test_os_info_is_not_guarded_with_mariadb_syntax():
    """`ADD COLUMN IF NOT EXISTS` is MariaDB; against MySQL it is a syntax
    error. Behind a bare `except: pass` that meant the column was never added
    on any deployment predating it, silently - the OS column just stayed empty
    for those agents."""
    assert "ADD COLUMN IF NOT EXISTS" not in _server_code_only(), (
        "MySQL rejects this outright, so the migration never applies"
    )
