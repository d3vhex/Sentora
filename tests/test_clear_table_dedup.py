"""Clearing a table has to clear what it has already seen.

`/<agent>/clear/<table>` ran a bare `TRUNCATE TABLE siem_events` and left
`ingest_fingerprint` untouched. That is not untidiness - it permanently blinds
the table.

Ingest writes a fingerprint per row and skips any row whose fingerprint it
already holds. Emptying the rows without emptying the fingerprints means every
future row is skipped as a duplicate of a row that no longer exists. So:

    the table stays empty for ever
    the server tells the agent it already holds the data
    the agent marks those rows sent and never offers them again
    every layer reports success

Seen live in the telemetry health view, which is the only place the two counts
sit side by side: an agent had shipped 507 new `siem_events` rows into a table
holding zero, with `unsent: 0` on its side. One click on Clear had turned the
most important table on the console into a silence indistinguishable from a
host with nothing to report.

Both clearable tables are in `DEDUP_TABLES`, so this applies to both of them,
and the delayed route is the same TRUNCATE written a second time - which is
how the two came to disagree.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
SERVER = ROOT / "server.py"


def _function(name: str) -> ast.AST:
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


def _dedup_tables() -> set:
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "DEDUP_TABLES" for t in node.targets):
            return set(ast.literal_eval(node.value))
    raise AssertionError("DEDUP_TABLES is not a literal set in server.py")


def _clearable() -> list:
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "CLEARABLE_TABLES" for t in node.targets):
            return list(ast.literal_eval(node.value))
    raise AssertionError("CLEARABLE_TABLES is not a literal in app.py")


def test_clearing_forgets_the_fingerprints_too():
    """The fix. Without it the TRUNCATE is a one-way door."""
    body = ast.unparse(_function("_clear_one_table"))
    assert "TRUNCATE TABLE" in body
    assert "DELETE FROM ingest_fingerprint" in body


def test_only_this_tables_fingerprints_are_dropped():
    """The fingerprints for every other table describe rows that are still
    there. Dropping those would re-admit every duplicate the ingest path
    exists to reject - a quieter failure than the one being fixed, and a
    harder one to notice."""
    body = ast.unparse(_function("_clear_one_table"))
    delete = body[body.index("DELETE FROM ingest_fingerprint"):]
    assert "table_name=%s" in delete or "table_name = %s" in delete, \
        "the clear drops every table's fingerprints, not just this one's"


@pytest.mark.parametrize("route", ["clear_table", "clear_table_delayed"])
def test_neither_route_truncates_on_its_own(route):
    """There were two copies of the same TRUNCATE and only one of them would
    ever have been fixed."""
    body = ast.unparse(_function(route))
    assert "TRUNCATE" not in body, (
        f"{route} still empties the table itself; it has to go through "
        f"_clear_one_table or it will drift again"
    )
    assert "_clear_one_table" in body


def test_the_two_routes_agree_on_what_may_be_cleared():
    """They each carried their own `allowed_tables` list. Two lists that have
    to match, with nothing making them match."""
    for route in ("clear_table", "clear_table_delayed"):
        body = ast.unparse(_function(route))
        assert "allowed_tables = " not in body, \
            f"{route} keeps its own copy of the allow-list"
        assert "CLEARABLE_TABLES" in body


@pytest.mark.parametrize("table", _clearable())
def test_every_clearable_table_is_actually_deduplicated(table):
    """The reason the fingerprint delete is needed at all. If a table ever
    becomes clearable *without* being deduplicated this test says so, and the
    extra DELETE is then harmless rather than load-bearing."""
    assert table in _dedup_tables(), (
        f"{table} can be cleared but is not deduplicated - check whether "
        f"_clear_one_table still describes what happens to it"
    )
