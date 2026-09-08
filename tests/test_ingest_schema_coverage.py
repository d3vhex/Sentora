"""Every table the server accepts has to be a table the server has.

Found in the telemetry health view, which is the only place the two halves of
the count appear side by side:

    registry_logs   NO TABLE   held 7788   shipped 7788   on server —

The agent had been collecting registry changes for weeks and shipping them
every cycle. `ALLOWED_TABLES` in server.py named `registry_logs`, so ingest
accepted the batch. `DEDUP_TABLES` named it, so a fingerprint was written for
every row. And `db/init.sql` — the per-agent schema the server applies before
the first insert — had no such table, so each row failed with

    1146 (42S02): Table 'DESKTOP_EVS8H9J_3_db.registry_logs' doesn't exist

Three tables were in this state: `registry_logs`, `process_events` and
`security_audit`. Nothing reported it. The failure was printed behind `if
debug`, the agent's log said `registry_logs sent (3 rows)` because `sendall`
had returned, and the console showed an empty table — which is exactly what a
host with no registry activity looks like.

The lists were the whole bug. Four of them describe the same set of tables and
they were maintained by hand:

    ALLOWED_TABLES     what ingest will accept
    SNAPSHOT_TABLES    replace the contents
    DEDUP_TABLES       skip what we have already seen
    db/init.sql        where it actually goes

Any name present in the first three and absent from the fourth is data the
platform accepts and then throws away.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"
SCHEMA = ROOT / "db" / "init.sql"
AGENT_SCHEMA = ROOT / "Sentora" / "db" / "init.sql"


def _set_literal(name: str) -> set:
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == name for t in node.targets):
            return set(ast.literal_eval(node.value))
    raise AssertionError(f"{name} is not a literal set in server.py")


def _schema_tables(path: pathlib.Path) -> set:
    """Table names, from SQL only.

    Comments go first. The agent schema documents one of its own migrations
    with the line

        -- Existing agents: CREATE TABLE IF NOT EXISTS leaves the old CHECK …

    and this used to read a table called `leaves` out of it. Harmless where
    the result is filtered against `ALLOWED_TABLES`, and not harmless in
    `test_the_agent_ships_every_table_it_collects` below, which asks a
    question about every name it finds.
    """
    from tests.test_agent_schema_migration import _load_func

    strip = _load_func(ROOT / "Sentora" / "modules" / "db.py", "_strip_comments")
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS [`\"]?(\w+)",
                          strip(path.read_text(encoding="utf-8"))))


ALLOWED = _set_literal("ALLOWED_TABLES")


@pytest.mark.parametrize("table", sorted(ALLOWED))
def test_every_ingestible_table_has_somewhere_to_land(table):
    """Accepting a batch for a table that does not exist is worse than
    refusing it: refusing says so, and this discarded the rows quietly while
    every layer above reported success."""
    assert table in _schema_tables(SCHEMA), (
        f"server.py accepts '{table}' and db/init.sql has no such table, so "
        f"every row of it fails with 1146 and is discarded"
    )


@pytest.mark.parametrize("table", sorted(_set_literal("DEDUP_TABLES")))
def test_nothing_is_deduplicated_into_a_table_that_does_not_exist(table):
    """Worse than the plain case. The fingerprint is written before the row,
    so a table that cannot accept the row still accumulates the marks that say
    it has already been seen."""
    assert table in _schema_tables(SCHEMA), f"{table} is deduplicated into nothing"


@pytest.mark.parametrize("table", sorted(_set_literal("SNAPSHOT_TABLES")))
def test_nothing_is_snapshotted_into_a_table_that_does_not_exist(table):
    assert table in _schema_tables(SCHEMA), f"{table} is snapshotted into nothing"


def test_the_agent_collects_nothing_the_server_will_not_take():
    """The other direction, and the one that produced the original hole: a
    collector shipping a table ingest has never heard of.

    Reported as a list rather than per-table, because the agent's schema
    legitimately holds local-only tables - a queue the server never sees is
    fine, a collector the server silently discards is not.
    """
    agent_tables = _schema_tables(AGENT_SCHEMA)
    shipped = {t for t in agent_tables if t in ALLOWED}
    missing = sorted(t for t in shipped if t not in _schema_tables(SCHEMA))
    assert not missing, (
        f"the agent collects and ships {missing}, ingest accepts them, and "
        f"there is nowhere to put them"
    )


# Tables in the agent's own schema that it deliberately does not ship, and
# why. Anything not named here has to be on `TABLES` in main.py.
#
# The list is short on purpose. A table the agent creates is a table something
# was expected to write to, so "we do not send this" is a decision, and a
# decision that is not written down is indistinguishable from the bug this
# test exists to catch.
AGENT_LOCAL_ONLY = {
    "automations":
        "A work queue the server pushes down and the agent updates in place. "
        "It travels the other way, through /automations/report.",
    "security_audit":
        "No collector was ever written for it. The table is kept so one can "
        "be added without a schema change; the claim that this agent reports "
        "it is not - see the note on TABLES in main.py.",
}


def test_the_agent_ships_every_table_it_collects():
    """The direction nothing checked, and it had been wrong for months.

    `modules/inventory.py` wrote `software_inventory` and `network_inventory`
    every cycle. Neither was on `TABLES`, so the send loop never offered them.
    `prune_sent` never touched them either, because it will not delete an
    unsent row - so they grew: 368,902 rows and 78,224 rows in the agent's own
    database, none of them ever leaving the host.

    Every layer was consistent with itself. The collector logged "Scanned 326
    apps and 68 open ports". The server had both names in `ALLOWED_TABLES` and
    `DEDUP_TABLES`, ready to receive them. The console showed two empty
    tables, which is what a machine with no software installed looks like.

    So the question this asks is not "does the server accept it" - that test
    is above and it passed throughout. It is "does the agent send it at all".
    """
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    block = re.search(r"^TABLES = \[(.*?)^\]", main, re.S | re.M)
    assert block, "TABLES is no longer a list literal in the agent's main.py"
    shipped = set(re.findall(r"['\"]([a-z_]+)['\"]", block.group(1)))

    unshipped = sorted(_schema_tables(AGENT_SCHEMA) - shipped - AGENT_LOCAL_ONLY.keys())
    assert not unshipped, (
        f"the agent's schema has {unshipped} and TABLES does not, so anything "
        f"written to them stays on the host for ever. Add them to TABLES, or "
        f"to AGENT_LOCAL_ONLY with the reason."
    )


def test_nothing_is_excused_from_shipping_that_no_longer_exists():
    """The excuse list rots the same way any list does."""
    stale = sorted(AGENT_LOCAL_ONLY.keys() - _schema_tables(AGENT_SCHEMA))
    assert not stale, f"AGENT_LOCAL_ONLY names tables the schema dropped: {stale}"


def test_an_unshipped_table_cannot_grow_for_ever():
    """The second half of the same failure.

    `prune_sent` refuses to delete an unsent row - correctly, for a table that
    is being delivered. For one that is not, it means the local database grows
    until the disk does, on a machine this product is supposed to be watching
    rather than filling. `prune_unsent` is the bound.
    """
    db = (ROOT / "Sentora" / "modules" / "db.py").read_text(encoding="utf-8")
    assert "sent = FALSE AND id <" in db, (
        "prune_unsent no longer bounds the unsent backlog"
    )
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(main)
    called = {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "prune_unsent" in called, "the retention loop never calls it"


def test_a_rejected_row_does_not_keep_its_fingerprint():
    """The fingerprint is written before the row it stands for.

    While a failed row rolled the whole batch back this was harmless — the
    fingerprint went with it. Once a batch commits despite a rejected row,
    a fingerprint left behind marks that row as already-seen for ever: it is
    skipped as a duplicate on every future attempt, so fixing the reason it
    failed does not bring it back.

    Visible in the live data at the time: three `registry_logs` fingerprints
    held against a table that did not exist.
    """
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "insert_data")

    # The per-row handler, found by the statement only it contains.
    #
    # Searching for "rejected" matched the batch-level handler first, because
    # its return dict carries `'rejected': 0` - so this test failed against
    # correct code while reading a handler thirty lines away. Anchor on an
    # exact statement, not on a word that appears in both.
    handler = next(h for h in ast.walk(fn)
                   if isinstance(h, ast.ExceptHandler)
                   and "rejected += 1" in ast.unparse(h))
    body = ast.unparse(handler)
    assert "DELETE FROM ingest_fingerprint" in body, (
        "a row that could not be stored keeps the fingerprint that will stop "
        "it ever being stored"
    )
