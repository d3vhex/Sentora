"""A table is a snapshot or it is deduplicated. Never both.

The console showed a host with no network connections and no hardware
inventory. The agent's own log showed it shipping them every cycle:

    [+] network_connections sent (50 rows)
    [+] hardware_inventory sent (50 rows)

Both were telling the truth. `network_connections`, `hardware_inventory`,
`critical_files` and `docker_containers` were in two sets at once, and the two
mechanisms cancel exactly:

    batch 1   DELETE removes nothing, every fingerprint is new, 50 rows land
    batch 2   DELETE removes all 50, every fingerprint is known, 0 rows land
    batch 3+  the same

So the table was full once and then permanently empty, while everything
upstream reported success. "It used to be populated" is not a coincidence -
it is the first batch.

Each mechanism is right on its own. A snapshot holds what is true *now*, so
replacing it is the point and deduplicating it defeats the point: the agent
re-sends the same picture deliberately. A deduplicated table holds a history
of events, so skipping a repeat is the point and emptying it first defeats
that. The bug was not either rule; it was a table subject to both.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"


def _set_literal(name: str) -> set:
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == name:
            return set(ast.literal_eval(node.value))
    raise AssertionError(f"{name} is not a module-level set in server.py")


def test_the_two_modes_do_not_overlap():
    """The bug, stated as an assertion."""
    both = _set_literal("SNAPSHOT_TABLES") & _set_literal("DEDUP_TABLES")
    assert not both, (
        f"{sorted(both)} are both replaced on every batch and skipped as "
        f"duplicates, which leaves them permanently empty after the second "
        f"batch while the agent reports sending rows"
    )


def test_the_overlap_is_refused_at_import():
    """A startup failure rather than a tab that is empty for reasons nobody
    can see from either side. This class of bug is invisible in production
    precisely because every component reports success."""
    source = SERVER.read_text(encoding="utf-8")
    assert "_assert_ingest_modes_are_exclusive()" in source, \
        "nothing enforces the invariant, so the next table added can break it"

    tree = ast.parse(source)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef)
              and n.name == "_assert_ingest_modes_are_exclusive")
    assert "raise" in ast.unparse(fn)


def test_the_guard_actually_fires():
    """Compiled and run against an overlapping pair, because a guard that
    cannot fail is decoration."""
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef)
              and n.name == "_assert_ingest_modes_are_exclusive")
    namespace = {"SNAPSHOT_TABLES": {"clash"}, "DEDUP_TABLES": {"clash"}}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<server.py>", "exec"),
         namespace)
    with pytest.raises(RuntimeError) as info:
        namespace["_assert_ingest_modes_are_exclusive"]()
    assert "clash" in str(info.value)


def test_the_snapshot_list_is_not_written_out_twice():
    """It was a named set in one place and an inline literal in the ingest
    loop. Two copies of the same list is how one of them came to disagree
    with DEDUP_TABLES without anybody noticing."""
    source = SERVER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "insert_data")
    code = ast.unparse(fn)
    assert "SNAPSHOT_TABLES" in code
    assert "'network_connections', 'hardware_inventory'" not in code


@pytest.mark.parametrize("table", [
    "network_connections", "hardware_inventory", "docker_containers",
    "resource_usage", "disk_usage",
])
def test_current_state_tables_are_snapshots(table):
    """These describe what is true on the host right now. The agent re-sends
    the whole picture on purpose, so treating a repeat as a duplicate throws
    away the only copy."""
    assert table in _set_literal("SNAPSHOT_TABLES"), table


@pytest.mark.parametrize("table", [
    "siem_events", "events_alert", "fim_data", "packages",
    "vulnerabilities_report", "portscan_result",
    # `critical_files` was in the snapshot list above, and this line is the
    # correction. `check_permissions` writes a row only when a file's owner,
    # group or mode has changed - it reports deltas, not the current picture -
    # so DELETE-then-insert stored the handful of files that had changed and
    # discarded the twelve hundred that had not. After a server-side database
    # reset it stayed empty for ever: nothing new to send, and a sent row is
    # never re-offered.
    "critical_files",
])
def test_event_history_tables_are_deduplicated(table):
    """These accumulate. Emptying one on every batch would discard the
    history that is the whole reason to keep it."""
    assert table in _set_literal("DEDUP_TABLES"), table


# --------------------------------------------------------------------------
# The signal that decides which mode a table belongs in
# --------------------------------------------------------------------------

AGENT_SCHEMA = ROOT / "Sentora" / "db" / "init.sql"


def _locally_deduplicated() -> set:
    """Tables the agent keeps a UNIQUE index on `dup_fp` for.

    That index is a statement about the collector: it can only hold if the
    collector never writes the same fact twice, which means it reports changes
    rather than the current picture. A table with this index is a delta
    stream, whatever anyone later assumes about it.
    """
    import re

    return set(re.findall(
        r"CREATE UNIQUE INDEX[^\n]*\n?\s*ON (\w+) \(dup_fp\)",
        AGENT_SCHEMA.read_text(encoding="utf-8")))


@pytest.mark.parametrize("table", sorted(_locally_deduplicated()))
def test_a_delta_stream_is_never_a_snapshot(table):
    """The invariant that would have caught `critical_files` on the day it was
    classified, without anyone having to read the collector.

    Snapshot semantics say "the agent re-sends the whole picture, so replace
    what is here". A collector the agent deduplicates locally cannot re-send
    the whole picture - the unique index is what stops it. Pairing the two
    means every batch deletes everything the delta did not mention.

    Six of the seven tables with this index were already deduplicated on the
    server. The seventh was the one showing zero rows against twelve hundred
    on the endpoint.
    """
    assert table not in _set_literal("SNAPSHOT_TABLES"), (
        f"the agent deduplicates {table} locally, so it only ever ships rows "
        f"that changed - but the server empties the table on every batch and "
        f"keeps only those. Everything unchanged is discarded, and after a "
        f"server-side reset the table never refills."
    )


def test_every_ingested_table_has_a_mode():
    """A table in neither set accumulates without deduplication, which is
    almost never what anybody wanted - it is the default you get by
    forgetting, and it grows without bound."""
    allowed = _set_literal("ALLOWED_TABLES")
    classified = _set_literal("SNAPSHOT_TABLES") | _set_literal("DEDUP_TABLES")
    unclassified = sorted(allowed - classified)
    assert not unclassified, (
        f"{unclassified} are accepted from agents but are neither a snapshot "
        f"nor deduplicated, so they accumulate every duplicate for ever"
    )
