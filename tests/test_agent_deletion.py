"""Removing an agent must remove all of it.

The installer minted a new identity on every re-run, leaving one machine
represented as DESKTOP-EVS8H9J, -2, -3 and -4 with a database each. Nothing in
the platform could delete them: the fleet view counted one host four times and
there was no way to say so.

The trap here is the naming. `agent_identities.agent_name` holds
`DESKTOP-EVS8H9J-4`; the database is `DESKTOP_EVS8H9J_4_db`. Deleting by one
spelling leaves the other, and a "deleted" agent keeps appearing with its
telemetry still on disk.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
API_TS = ROOT / "frontend" / "src" / "services" / "api.ts"
AGENTS_TSX = ROOT / "frontend" / "src" / "pages" / "Agents.tsx"

SRC = APP.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _func(name: str):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


def _name_forms():
    """Compile the helper alone; importing app.py would start a server."""
    fn = _func("_agent_name_forms")
    ns: dict = {}
    exec("import re\n" + ast.unparse(fn), ns)
    return ns["_agent_name_forms"]


# --------------------------------------------------------------------------
# Both spellings
# --------------------------------------------------------------------------

class TestNameForms:
    def test_hyphen_identity_finds_the_underscore_database(self):
        hyphen, underscore, dbs = _name_forms()("DESKTOP-EVS8H9J-4")
        assert hyphen == "DESKTOP-EVS8H9J-4"
        assert underscore == "DESKTOP_EVS8H9J_4"
        assert "DESKTOP_EVS8H9J_4_db" in dbs

    def test_underscore_input_works_too(self):
        hyphen, _, dbs = _name_forms()("DESKTOP_EVS8H9J_4")
        assert hyphen == "DESKTOP-EVS8H9J-4"
        assert "DESKTOP_EVS8H9J_4_db" in dbs

    def test_a_name_already_ending_in_db_is_not_doubled(self):
        _, _, dbs = _name_forms()("DESKTOP_EVS8H9J_db")
        assert "DESKTOP_EVS8H9J_db" in dbs
        assert "DESKTOP_EVS8H9J_db_db" not in dbs

    @pytest.mark.parametrize("hostile", [
        "foo`; DROP DATABASE mysql; --",
        "../../etc/passwd",
        "a b; SELECT 1",
        "`backtick`",
    ])
    def test_identifier_injection_is_stripped(self, hostile):
        """The database name is interpolated, so it cannot carry SQL."""
        _, _, dbs = _name_forms()(hostile)
        for db in dbs:
            assert all(c.isalnum() or c == "_" for c in db), db

    def test_an_empty_name_yields_nothing_to_delete(self):
        hyphen, _, _ = _name_forms()("---")
        assert hyphen == ""


# --------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------

class TestEndpoint:
    def test_it_is_permission_gated(self):
        fn = _func("delete_agent")
        decorators = [ast.unparse(d) for d in fn.decorator_list]
        assert any("require_permission" in d for d in decorators), \
            "deleting an agent is session-only; any logged-in user could do it"
        assert any('"manage_agent"' in d or "'manage_agent'" in d
                   for d in decorators)

    def test_it_requires_the_name_repeated_in_the_body(self):
        """One misclick in a list of near-identical names is unrecoverable."""
        src = ast.unparse(_func("delete_agent"))
        assert "confirm" in src

    def test_it_drops_the_database_and_the_identity(self):
        src = ast.unparse(_func("delete_agent"))
        assert "DROP DATABASE" in src
        assert "agent_identities" in src

    def test_it_checks_the_database_exists_before_dropping(self):
        """So a wrong name reports 404 rather than silent success."""
        src = ast.unparse(_func("delete_agent"))
        assert "information_schema.schemata" in src
        assert "404" in src

    def test_it_is_audited(self):
        src = ast.unparse(_func("delete_agent"))
        assert "audit_log" in src and "DELETE_AGENT" in src

    def test_it_does_not_delete_enrolment_history(self):
        """Who enrolled what, and when, outlives the agent."""
        src = ast.unparse(_func("delete_agent"))
        assert "DELETE FROM userdb.enrollment_tokens" not in src

    def test_the_drop_runs_off_the_event_loop(self):
        """DROP DATABASE on a large agent blocks; every other request waits."""
        src = ast.unparse(_func("delete_agent"))
        assert "to_thread" in src


# --------------------------------------------------------------------------
# The UI
# --------------------------------------------------------------------------

class TestFrontend:
    def test_the_client_sends_the_confirmation(self):
        text = API_TS.read_text(encoding="utf-8")
        assert "deleteAgent" in text
        assert "confirm: agent" in text, "the server will reject this"

    def test_the_page_confirms_before_deleting(self):
        text = AGENTS_TSX.read_text(encoding="utf-8")
        assert "pendingDelete" in text, "no confirmation step"
        # The destructive call must not be wired straight to the row button.
        assert "onClick={confirmDelete}" in text
        assert "onClick={() => agentService.deleteAgent" not in text

    def test_a_failed_delete_is_shown(self):
        """A dialog that closes on failure looks identical to success."""
        text = AGENTS_TSX.read_text(encoding="utf-8")
        assert "deleteError" in text
