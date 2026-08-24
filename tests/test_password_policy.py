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


# --------------------------------------------------------------------------
# The console has to be able to say why it is empty
# --------------------------------------------------------------------------
#
# Enforcing the flag in middleware without the UI knowing about it produced a
# console that rendered every page, fetched nothing, and explained nothing:
# 132 responses of 401/403 and blank tables. The operator's report was "no
# data, like there's no DB access" - the database was fine.
#
# A policy the interface cannot satisfy is a lockout, not a control.

FRONTEND = ROOT / "frontend" / "src"


def test_login_returns_the_flag():
    """Set before the first request fails, not after."""
    assert '"must_change_password": bool(must_change)' in APP
    assert "COALESCE(must_change_password, 0)" in APP


def test_the_client_reacts_to_the_refusal():
    api = (FRONTEND / "services" / "api.ts").read_text(encoding="utf-8")
    assert "must_change_password" in api, "the interceptor ignores the 403 code"
    assert "mustChangePassword" in api, "nothing records it for the UI to read"


def test_the_client_stores_it_at_login_too():
    api = (FRONTEND / "services" / "api.ts").read_text(encoding="utf-8")
    i = api.index("authService")
    assert "must_change_password" in api[i:], (
        "the flag is only picked up after a request has already failed"
    )


def test_the_operator_is_told():
    """A banner, not a console message."""
    sidebar = (FRONTEND / "components" / "Sidebar.tsx").read_text(encoding="utf-8")
    assert "mustChange" in sidebar
    assert "Set a password to continue" in sidebar


def test_the_banner_opens_the_dialog_that_fixes_it():
    """Telling someone to change their password without a way to do it is the
    same problem one step removed."""
    sidebar = (FRONTEND / "components" / "Sidebar.tsx").read_text(encoding="utf-8")
    i = sidebar.index("Set a password to continue")
    assert "setShowPasswordModal(true)" in sidebar[max(0, i - 900):i]


def test_the_flag_clears_when_the_password_changes():
    sidebar = (FRONTEND / "components" / "Sidebar.tsx").read_text(encoding="utf-8")
    assert "localStorage.removeItem('mustChangePassword')" in sidebar


def test_the_migration_only_flags_the_published_credential():
    """The first version matched on username and created_by, so it flagged
    the seeded admin whether or not the password had ever been changed. On a
    running deployment that is not a policy, it is a lockout for somebody who
    set a password months ago.
    """
    assert "SEEDED_ADMIN_HASH" in SCHEMA_INIT
    i = SCHEMA_INIT.index("UPDATE users SET must_change_password = 1")
    stmt = SCHEMA_INIT[i:i + 400]
    assert "password = %s" in stmt, (
        "the migration flags accounts regardless of their current password"
    )


def test_the_hash_matches_the_one_actually_seeded():
    """If they drift, the migration silently flags nobody."""
    import re
    m = re.search(r'SEEDED_ADMIN_HASH = "([^"]+)"', SCHEMA_INIT)
    assert m
    assert m.group(1) in SCHEMA, (
        "SEEDED_ADMIN_HASH is not the hash db/init_userdb.sql inserts"
    )
