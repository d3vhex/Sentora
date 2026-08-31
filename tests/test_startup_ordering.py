"""A database that is not up yet must not look like a wrong password.

The whole failure, end to end:

  1. `setup_hub` runs from `main_process_start`, which fires before any worker
     exists. Under compose the database container starts alongside the app, so
     all five migrations raced it and failed. Each caught its own exception and
     printed a tidy line - correct individually, and collectively a server that
     started with no `sessions` table.
  2. `setup_db_pool` then failed the same way and was not retried, so
     `app.ctx.db_pool` was never set and the worker served anyway.
  3. `/login` checked the password through the *synchronous* connector, which
     worked, and printed

         [+] Local login successful for user: admin

  4. Issuing the session needed the pool and the missing table. It raised. The
     login handler's outer `except` means "not a local user, try LDAP", so it
     swallowed the error, tried the directory, and answered **401**.

An operator with the correct password was told it was wrong, by a server
reporting itself healthy, with the reason written only into a database table
that also could not be read.

Every step was individually defensible. What made it a two-hour bug is that
each layer converted a specific failure into a vaguer one, and the last layer
converted it into a lie.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
SCHEMA_INIT = ROOT / "core" / "schema_init.py"


def _function(path: pathlib.Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


#: The exact statement, not the phrase. `setup_db_pool`'s docstring quotes the
#: log line it produced, so anchoring on the words lands in the explanation
#: rather than in the code - the same trap these tests keep finding elsewhere.
_SUCCESS_LINE = 'print(f"[+] Local login successful for user: {username}")'


def _successful_login_branch() -> str:
    """The part of `login` reached once the password has matched."""
    source = APP.read_text(encoding="utf-8")
    start = source.index(_SUCCESS_LINE)
    return source[start:source.index("Local password mismatch", start)]


# --------------------------------------------------------------------------
# Firing at all
# --------------------------------------------------------------------------

def _listener_names(kind: str) -> set[str]:
    """Functions registered under one Sanic startup hook."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if kind in ast.unparse(dec):
                found.add(node.name)
    return found


def test_nothing_starts_up_on_a_hook_this_server_never_fires():
    """`main_process_start` only fires when Sanic runs a multi-process
    manager. `app.run(single_process=True)` - which `WORKERS=1` selects, and
    which the compose file asks for - has none, so anything registered there
    never runs.

    `setup_hub` was, so no schema migration ran at all: no `users`, no
    `sessions`, no enrolment tables. And the symptom arrived three layers
    away, as a 401 on a correct password.
    """
    main_process = _listener_names("main_process_start")
    assert not main_process, (
        f"{sorted(main_process)} will never run while WORKERS=1, because "
        f"single_process has no main process manager"
    )


def test_the_schema_is_set_up_before_the_server_serves():
    assert "setup_hub" in _listener_names("before_server_start")


def test_single_process_is_still_what_one_worker_means():
    """The premise of the test above. If this stops being true the hook
    question changes, and the assertion should be revisited rather than
    quietly kept."""
    source = APP.read_text(encoding="utf-8")
    assert "single_process=(num_workers == 1)" in source


# --------------------------------------------------------------------------
# Waiting, rather than failing once
# --------------------------------------------------------------------------

def test_the_pool_waits_for_the_database():
    code = _function(APP, "setup_db_pool")
    assert "while True" in code or "for " in code, \
        "the pool is built once; a database that is not up yet is permanent"
    assert "sleep" in code


def test_a_pool_that_never_builds_stops_the_server():
    """Serving without one is worse than not serving. Password checks go
    through the synchronous connector and keep working, so the symptom is not
    an outage - it is every login being rejected as though the credential
    were wrong."""
    code = _function(APP, "setup_db_pool")
    assert "raise" in code, \
        "the worker would carry on serving with no pool"


def test_the_migrations_wait_too():
    """They run from `main_process_start`, which fires before any worker and
    long before the pool exists - so the pool's own retry does nothing for
    them. This is the one that left `sessions` missing."""
    code = _function(SCHEMA_INIT, "run_all")
    assert "_wait_for_database" in code
    assert code.index("_wait_for_database") < code.index("init_hub_db"), \
        "the migrations start before the database is known to be there"


def test_the_wait_gives_up_out_loud():
    code = _function(SCHEMA_INIT, "_wait_for_database")
    assert "Database unreachable" in code
    assert "sleep" in code


# --------------------------------------------------------------------------
# Checking afterwards, because each migration swallows its own errors
# --------------------------------------------------------------------------

def test_the_schema_is_verified_after_migrating():
    """Every `init_*` catches its own exceptions, which is right - one failing
    must not stop the rest. The consequence is that "all five failed" and "the
    database is fine" look identical from here."""
    code = _function(SCHEMA_INIT, "run_all")
    assert "_missing_required_tables" in code


def test_sessions_is_required():
    """It is the table whose absence produced a 401. Nothing about the
    platform works without it, and nothing else was checking."""
    source = SCHEMA_INIT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    required = next(
        ast.literal_eval(n.value) for n in tree.body
        if isinstance(n, ast.Assign)
        and getattr(n.targets[0], "id", "") == "REQUIRED_TABLES")
    assert "sessions" in required
    assert "users" in required


def test_a_missing_table_names_the_symptom_not_just_the_table():
    """"sessions missing" tells whoever reads the log nothing about why they
    cannot log in. The line has to connect the two, because the person
    reading it is looking for an authentication problem."""
    code = _function(SCHEMA_INIT, "run_all")
    assert "as though the password were wrong" in code


# --------------------------------------------------------------------------
# The lie at the end
# --------------------------------------------------------------------------

def test_a_correct_password_is_never_answered_with_401():
    """Past the password check, nothing may fall through to LDAP.

    The whole local branch sat inside one `try` whose `except` means "not a
    local user, try the directory". A failure *after* the password matched was
    caught by it, so the server answered 401 to a correct credential.
    """
    branch = _successful_login_branch()
    assert "_issue_session" in branch, "this is not the branch it looks like"
    assert "try:" in branch, \
        "issuing the session is unguarded, so it falls through to LDAP"
    assert "503" in branch, \
        "a server-side failure after a correct password must not be a 401"


def test_the_failure_says_whose_fault_it_is():
    """The operator's next move depends entirely on this. "Invalid username or
    password" sends them to reset a password that was never wrong."""
    assert "not a credential one" in _successful_login_branch()


def test_the_reason_reaches_the_log_as_well_as_the_operator():
    """It was going only into `login_logs` - a database table, on a server
    whose problem was that it could not reach the database.

    Matched on a fragment rather than the whole sentence: the message is
    written as wrapped f-string literals, so no contiguous run of the source
    holds it. Asserting the full sentence fails on the line break and reads
    as a missing message.
    """
    branch = _successful_login_branch()
    assert "print(" in branch
    assert "authenticated but the session" in branch
    assert "{e}" in branch, "the reason itself is not in the line"
