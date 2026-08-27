"""Renaming a device changes the label and nothing else.

`agent_name` is the identity. The agent's telemetry database is named after it
(`server._sanitize_db_name`), SOAR actions route by it, and the agent holds it
in its own `config.json`. Renaming *that* would mean moving a database,
re-issuing the agent's configuration, and reconciling every stored row that
refers to the old name.

What an operator wants is to see "Web server 1" instead of
"ip-172-31-42-49", which is a label. These tests exist to keep the two from
being confused later, because the cheap version of this feature is the one
that quietly starts renaming identities.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / "app.py").read_text(encoding="utf-8")
TREE = ast.parse(APP)
FRONTEND = ROOT / "frontend" / "src"


def _handler(name):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
                and n.name == name)


# --------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------

def test_the_endpoint_exists_and_is_gated():
    fn = _handler("set_agent_display_name")
    decorators = [ast.unparse(d) for d in fn.decorator_list]
    assert any("display-name" in d for d in decorators)
    assert any("require_permission" in d for d in decorators), \
        "renaming a device is an administrative action"


def test_it_only_writes_display_name():
    """The one assertion that matters. If this handler ever issues a RENAME,
    a CREATE DATABASE, or an UPDATE against agent_name, the identity is
    moving and every one of the places listed in this module's docstring
    breaks."""
    fn = _handler("set_agent_display_name")

    # The SQL only. Matching the whole body caught `RENAME_AGENT`, the audit
    # action name - a test failing on the word rather than on the statement.
    statements = [n.value for n in ast.walk(fn)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and any(kw in n.value.upper()
                          for kw in ("SELECT ", "UPDATE ", "INSERT ", "DELETE ",
                                     "ALTER ", "DROP ", "CREATE "))]
    assert any("UPDATE agent_identities SET display_name" in s for s in statements)

    joined = " ".join(statements).upper()
    for forbidden in ("RENAME", "CREATE DATABASE", "DROP DATABASE",
                      "SET AGENT_NAME", "AGENT_KEY"):
        assert forbidden not in joined, \
            f"the rename endpoint's SQL touches {forbidden}"


def test_a_name_that_is_too_long_is_refused():
    """The column is VARCHAR(128); MySQL would otherwise truncate silently in
    a non-strict mode and store something the operator did not type."""
    body = ast.unparse(_handler("set_agent_display_name"))
    assert "128" in body


def test_control_characters_are_refused():
    """Agent names are interpolated into log lines an operator reads. A
    newline in one is a forged log entry."""
    body = ast.unparse(_handler("set_agent_display_name"))
    assert "control characters" in body


def test_clearing_it_falls_back_rather_than_leaving_a_blank_device():
    body = ast.unparse(_handler("set_agent_display_name"))
    assert "name or None" in body


def test_an_unknown_agent_is_a_404_not_a_silent_success():
    body = ast.unparse(_handler("set_agent_display_name"))
    assert "unknown agent" in body
    assert "404" in body


def test_the_rename_is_audited():
    """It is an administrative change to what a device is called, which is
    exactly the kind of thing an investigation later needs to reconstruct."""
    body = ast.unparse(_handler("set_agent_display_name"))
    assert "audit_log" in body
    assert "RENAME_AGENT" in body


# --------------------------------------------------------------------------
# Reading it back
# --------------------------------------------------------------------------

def test_the_agents_list_carries_the_display_name():
    body = ast.unparse(_handler("list_agents"))
    assert "_agent_display_names" in body
    assert "display_name" in body


def test_the_lookup_is_one_query_not_one_per_agent():
    """The list endpoint already opens a connection per host. Adding another
    round trip each would double that for a label."""
    body = ast.unparse(_handler("_agent_display_names"))
    assert body.count("cur.execute") == 1


def test_a_missing_column_does_not_break_the_agents_list():
    """This is the first page an operator opens. Failing it over a cosmetic
    column would hide the entire estate - and the column is absent on any
    installation that has not run the migration yet."""
    body = ast.unparse(_handler("_agent_display_names"))
    assert "except Exception" in body
    assert "return {}" in body


# --------------------------------------------------------------------------
# The migration
# --------------------------------------------------------------------------

def test_the_column_is_in_the_schema():
    schema = (ROOT / "db" / "init_userdb.sql").read_text(encoding="utf-8")
    assert "display_name VARCHAR(128) NULL" in schema


def test_existing_installations_get_the_column():
    """`CREATE TABLE IF NOT EXISTS` leaves an existing table alone, so without
    a migration the column only appears on installations made after today."""
    init = (ROOT / "core" / "schema_init.py").read_text(encoding="utf-8")
    assert "ADD COLUMN display_name" in init


def test_the_migration_checks_rather_than_swallowing():
    """A DDL that fails for some other reason should be visible, not
    indistinguishable from "already applied"."""
    init = (ROOT / "core" / "schema_init.py").read_text(encoding="utf-8")
    assert "information_schema.COLUMNS" in init


# --------------------------------------------------------------------------
# The UI
# --------------------------------------------------------------------------

def test_the_detail_page_can_rename():
    page = (FRONTEND / "pages" / "AgentDetail.tsx").read_text(encoding="utf-8")
    assert "setAgentDisplayName" in page
    assert "saveDisplayName" in page


@pytest.mark.parametrize("page_name", ["Agents.tsx", "AgentDetail.tsx"])
def test_the_real_name_stays_visible(page_name):
    """A label that replaces the identity outright makes a renamed host
    impossible to match against a log line, a database name, or a SOAR
    action - all of which still use the real one."""
    page = (FRONTEND / "pages" / page_name).read_text(encoding="utf-8")
    assert "display_name ?" in page or "displayName ?" in page


def test_the_list_falls_back_to_the_real_name():
    page = (FRONTEND / "pages" / "Agents.tsx").read_text(encoding="utf-8")
    assert "agent.display_name || agent.name" in page


def test_search_matches_either_name():
    """Somebody who renamed a host still knows what it used to be called, and
    somebody who did not only knows the label."""
    page = (FRONTEND / "pages" / "Agents.tsx").read_text(encoding="utf-8")
    assert "agent.name.toLowerCase().includes" in page
    assert "agent.display_name || ''" in page


def test_a_background_refresh_does_not_overwrite_what_is_being_typed():
    """The detail page reloads every few seconds."""
    page = (FRONTEND / "pages" / "AgentDetail.tsx").read_text(encoding="utf-8")
    assert "if (!editingName) setDisplayName" in page


def test_the_navigation_still_uses_the_real_name():
    """The URL and every API call are keyed on the identity. Routing by a
    label would break the moment two hosts were given the same one."""
    page = (FRONTEND / "pages" / "Agents.tsx").read_text(encoding="utf-8")
    assert "to={`/agent/${agent.name}`}" in page
    assert "to={`/agent/${agent.display_name" not in page
