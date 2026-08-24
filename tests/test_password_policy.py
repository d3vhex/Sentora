"""The seeded admin password must be changed before the console can be used.

`db/init_userdb.sql` creates `admin` with a bcrypt hash that is published in
this repository, so it is a placeholder rather than a secret. Every
installation shipped with the same one and nothing required changing it - the
README asked politely, in a section headed "Default secrets".

The flag is enforced in the `authenticate` middleware rather than returned to
the front end. A flag the UI is trusted to honour is not a control; the API is
reachable with curl.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / "app.py").read_text(encoding="utf-8")
# The boot migrations moved to core/schema_init.py.
SCHEMA_INIT = (ROOT / "core" / "schema_init.py").read_text(encoding="utf-8")
SCHEMA = (ROOT / "db" / "init_userdb.sql").read_text(encoding="utf-8")
TREE = ast.parse(APP)
INIT_TREE = ast.parse(SCHEMA_INIT)


def _literal_set(name: str) -> set[str]:
    for node in TREE.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return set(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found at module level")


# --------------------------------------------------------------------------
# The schema
# --------------------------------------------------------------------------

def test_the_column_exists():
    m = re.search(r"CREATE TABLE users \((.*?)\n\)", SCHEMA, re.S)
    assert m and "must_change_password" in m.group(1)


def test_the_seeded_admin_is_flagged():
    """Seeding it as 0 would make the column decorative."""
    m = re.search(r"INSERT INTO users \(([^)]*)\)\s*VALUES \(([^;]*)\);",
                  SCHEMA, re.S)
    assert m, "the seeded admin INSERT is gone"
    cols = [c.strip() for c in m.group(1).split(",")]
    vals = [v.strip() for v in m.group(2).split(",")]
    assert "must_change_password" in cols
    assert vals[cols.index("must_change_password")] == "1"


def test_existing_deployments_get_the_column():
    """CREATE TABLE ran once; a deployment made before this needs a migration
    or the flag is never enforced there."""
    fn = next(n for n in ast.walk(INIT_TREE)
              if isinstance(n, ast.AsyncFunctionDef)
              and n.name == "init_password_policy")
    body = ast.unparse(fn)
    assert "information_schema" in body, "the migration is not guarded"
    assert "ADD COLUMN must_change_password" in body
    assert "UPDATE users SET must_change_password = 1" in body


def test_the_migration_runs_at_boot():
    """app.py calls run_all(); schema_init.run_all() calls this one."""
    assert "await schema_init.run_all()" in APP
    assert "await init_password_policy()" in SCHEMA_INIT


# --------------------------------------------------------------------------
# Enforcement
# --------------------------------------------------------------------------

def test_the_check_is_in_the_middleware_not_the_response():
    """Returning the flag to the front end and trusting it to redirect is not
    a control - the API answers curl too."""
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "authenticate")
    body = ast.unparse(fn)
    assert "must_change_password" in body
    assert "403" in body or "status=403" in body


def test_only_the_password_change_path_is_reachable():
    allowed = _literal_set("_PASSWORD_CHANGE_HANDLERS")
    assert "change_password" in allowed
    # Otherwise someone who cannot set a password is stuck in the session.
    assert "logout" in allowed


@pytest.mark.parametrize("forbidden", [
    "list_users", "run_playbook", "delete_soar_action", "get_ai_insights",
    "trigger_self_destruct", "create_user",
])
def test_the_allowlist_does_not_leak_real_functionality(forbidden):
    assert forbidden not in _literal_set("_PASSWORD_CHANGE_HANDLERS")


def test_changing_the_password_clears_the_flag():
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "change_password")
    assert "must_change_password = 0" in ast.unparse(fn)


def test_an_admin_reset_sets_the_flag_again():
    """A password an operator did not choose is in the same position as the
    seeded one."""
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "admin_reset_password")
    assert "must_change_password = 1" in ast.unparse(fn)
