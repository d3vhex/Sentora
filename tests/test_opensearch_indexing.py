"""What reaches the search index, and in what form.

Two bugs lived in one unconditional line. `server.py` called
`os_utils.index_log(agent, table, item)` for whatever ingest had just stored,
with `item` exactly as received - so:

  - **the index held ciphertext.** Measured on the running deployment:

        siem-events / message            71/71 enc::gAAAA...
        registry-logs / value_data     300/300
        fim-data / path                300/300
        network-connections / process  300/300
        hardware-inventory / name      300/300
        packages / package             300/300

    and the consequence, over the same 69 documents:

        message:*powershell*   ->  0 hits
        source:*PowerShell*    -> 52 hits

    `core/telemetry_crypto` documents four destinations and which of them get
    plaintext. The index was a fifth that the list never mentioned.

  - **it grew without bound.** A snapshot table is emptied and rewritten in
    MySQL on every batch; the index kept every copy ever sent. 426,768
    `hardware_inventory` documents on one host, for a CPU, some RAM and four
    disks.

So the index is now an allowlist, and what goes into it is decrypted.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"
OS_MODULE = ROOT / "core" / "opensearch.py"
CRYPTO = ROOT / "core" / "telemetry_crypto.py"


def _literal(source: pathlib.Path, name: str):
    """Read a module-level constant without importing the module.

    `frozenset({...})` is a call, not a literal, so `literal_eval` refuses it -
    unwrap the one argument and evaluate that instead.
    """
    for node in ast.parse(source.read_text(encoding="utf-8")).body:
        if not (isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == name for t in node.targets)):
            continue
        value = node.value
        if isinstance(value, ast.Call) and getattr(value.func, "id", "") in (
                "frozenset", "set", "tuple", "list", "dict") and value.args:
            value = value.args[0]
        return ast.literal_eval(value)
    raise AssertionError(f"{name} is not a module-level literal in {source.name}")


ALLOWED_TABLES = set(_literal(SERVER, "ALLOWED_TABLES"))
SNAPSHOT_TABLES = set(_literal(SERVER, "SNAPSHOT_TABLES"))
INDEXED_TABLES = set(_literal(OS_MODULE, "INDEXED_TABLES"))
NOT_INDEXED = _literal(OS_MODULE, "NOT_INDEXED")
ENCRYPTED_FIELDS = _literal(CRYPTO, "ENCRYPTED_FIELDS")

#: Indexed but not ingested from an agent. `audit_logs` is the platform's own
#: trail, written by app.py's audit helper straight to `index_log`.
NOT_FROM_AN_AGENT = {"audit_logs"}


# --------------------------------------------------------------------------
# Every ingested table is a decision, one way or the other
# --------------------------------------------------------------------------

@pytest.mark.parametrize("table", sorted(ALLOWED_TABLES))
def test_an_ingested_table_is_either_indexed_or_explained(table):
    """A table added to ingest and to neither list is a silent decision.

    Silent in the direction that matters: `index_log` returns early for
    anything it does not recognise, so the table is simply absent from search
    and nothing anywhere says so. That is the shape of every bug in this
    repository's history - a gap that renders identically to a quiet system.
    """
    if table in INDEXED_TABLES:
        return
    assert table in NOT_INDEXED, (
        f"{table} is ingested, is not indexed, and no reason is recorded. Add "
        f"it to INDEXED_TABLES, or to NOT_INDEXED with the view that answers "
        f"the question instead."
    )
    assert NOT_INDEXED[table].strip(), f"{table} has an empty reason"


def test_the_two_lists_do_not_overlap():
    assert not (INDEXED_TABLES & set(NOT_INDEXED))


def test_nothing_is_excused_that_is_not_ingested():
    """A stale entry in NOT_INDEXED reads as a considered decision about a
    table that no longer exists."""
    stale = sorted(set(NOT_INDEXED) - ALLOWED_TABLES - {"vulnerabilities_report"})
    assert not stale, f"NOT_INDEXED mentions tables ingest does not accept: {stale}"


def test_every_indexed_table_is_ingested_or_named_as_platform_data():
    unexplained = sorted(INDEXED_TABLES - ALLOWED_TABLES - NOT_FROM_AN_AGENT)
    assert not unexplained, (
        f"{unexplained} are indexed but never ingested; nothing writes them."
    )


# --------------------------------------------------------------------------
# The two properties that were actually broken
# --------------------------------------------------------------------------

def test_what_is_indexed_is_decrypted_first():
    """The bug, as a structural check.

    Asserted against the AST rather than the source text: a comment explaining
    that the document is decrypted is exactly what this file would have matched
    while the code did nothing of the kind.
    """
    tree = ast.parse(OS_MODULE.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "index_log")

    calls = {n.func.attr for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "decrypt_item" in calls, (
        "index_log indexes the row as received. Encrypted columns arrive as "
        "enc::gAAAA..., so the field an operator searches on holds ciphertext "
        "and matches nothing."
    )


def test_the_allowlist_is_checked_before_anything_is_sent():
    """The guard has to be the first thing, not a filter after the document is
    built - a half-built document that then returns is how a later edit turns
    the guard back off without failing anything."""
    tree = ast.parse(OS_MODULE.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "index_log")
    body = [n for n in fn.body if not isinstance(n, ast.Expr)]   # drop docstring
    first = body[0]
    assert isinstance(first, ast.If), "index_log does not start with the guard"
    assert "INDEXED_TABLES" in ast.dump(first.test)
    assert any(isinstance(n, ast.Return) for n in ast.walk(first))


@pytest.mark.parametrize("table", sorted(INDEXED_TABLES - {"audit_logs"}))
def test_an_indexed_table_with_encrypted_columns_is_covered_by_the_crypto_map(table):
    """`decrypt_item` decrypts the fields `ENCRYPTED_FIELDS` names for a table
    and nothing else. A table indexed but missing from that map goes in as
    ciphertext again, through the new code path rather than the old one.
    """
    from_agent_encrypted = {
        "siem_events", "events_alert", "fim_data", "registry_logs",
        "process_events", "critical_files", "security_audit",
    }
    if table not in from_agent_encrypted:
        return                      # written in the clear; nothing to decrypt
    assert table in ENCRYPTED_FIELDS, (
        f"{table} is indexed and the agent encrypts it, but "
        f"telemetry_crypto.ENCRYPTED_FIELDS does not list it, so decrypt_item "
        f"leaves it as ciphertext."
    )


# --------------------------------------------------------------------------
# Why the state tables are out
# --------------------------------------------------------------------------

@pytest.mark.parametrize("table", sorted(SNAPSHOT_TABLES))
def test_a_snapshot_table_is_not_indexed(table):
    """A snapshot is emptied and rewritten in MySQL on every batch, so the
    table holds one current picture. The index has no such mechanism and keeps
    every picture ever sent - which is where 426,768 hardware_inventory
    documents came from, and why they are not a history anybody can use: the
    deletes are not in them.
    """
    assert table not in INDEXED_TABLES, (
        f"{table} is a snapshot table. Indexing it accumulates one document "
        f"per entity per collection cycle, for ever, with no record of the "
        f"deletes that made it a snapshot."
    )
