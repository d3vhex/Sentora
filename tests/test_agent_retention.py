"""The agent's local database has to stop growing.

Nothing pruned it, and the agent only ever appends, so it grew for the life of
the install. On one host after a few weeks:

    hardware_inventory   530,428 rows
    network_connections  225,145
    fim_data              88,201

every one of them already shipped and never read again. Disk on a monitored
endpoint is the one place a monitoring tool has no business quietly consuming.

It also constrained recovery. `reoffer_recent` has to be bounded, because
replaying half a million rows at fifty a batch takes days - so the backlog was
actively limiting how much could be rescued after a server-side reset.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = ROOT / "Sentora" / "main.py"
AGENT_DB = ROOT / "Sentora" / "modules" / "db.py"


def _function(path: pathlib.Path, name: str):
    return next(n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                if isinstance(n, ast.FunctionDef) and n.name == name)


def _const(path: pathlib.Path, name: str):
    node = next(n for n in ast.parse(path.read_text(encoding="utf-8")).body
                if isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == name for t in n.targets))
    return ast.literal_eval(node.value)


def test_only_shipped_rows_are_deleted():
    """An unsent row has not reached the server. Deleting it is exactly the
    data loss the rest of this work spent the day preventing."""
    body = ast.unparse(_function(AGENT_DB, "prune_sent"))
    assert "sent = TRUE" in body, "retention would delete rows never shipped"


def test_a_floor_is_always_kept():
    """`DELETE FROM table WHERE sent` with no floor empties the table between
    a reset and the re-offer that would have rescued it."""
    body = ast.unparse(_function(AGENT_DB, "prune_sent"))
    assert "ORDER BY id DESC" in body and "OFFSET" in body


def test_the_floor_is_above_what_recovery_needs():
    """Pruning must not eat the material a server-side reset offers again. Set
    it below `_REOFFER_LIMIT` and recovery is quietly capped by whatever the
    cleaner happened to leave behind."""
    keep = _const(MAIN, "_RETENTION_ROWS")
    reoffer = _const(MAIN, "_REOFFER_LIMIT")
    assert keep > reoffer, (
        f"retention keeps {keep} rows and recovery wants {reoffer}"
    )


def test_it_runs_on_its_own():
    """A cleaner nobody calls is a cleaner that does not exist."""
    source = MAIN.read_text(encoding="utf-8")
    start = ast.unparse(_function(MAIN, "start_threads"))
    assert "retention_loop" in start, "the retention loop is never started"
    assert "prune_sent" in source


def test_one_table_failing_does_not_stop_the_rest():
    """The rule every collector in this agent already follows."""
    fn = _function(MAIN, "retention_loop")
    handlers = [h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler)]
    assert handlers, "a single failing table aborts the whole sweep"
    loop = next(n for n in ast.walk(fn) if isinstance(n, ast.For))
    assert any(isinstance(h, ast.ExceptHandler) for h in ast.walk(loop)), \
        "the handler is outside the per-table loop"


def test_it_does_not_run_immediately_on_startup():
    """On an upgrade the first thing this process should do is ship its
    backlog, not delete it."""
    body = ast.unparse(_function(MAIN, "retention_loop"))
    first_sleep = body.index("time.sleep")
    first_prune = body.index("prune_sent")
    assert first_sleep < first_prune, "retention runs before the first send"


# --------------------------------------------------------------------------
# Nothing is shipped that nothing writes
# --------------------------------------------------------------------------

def _shipped_tables() -> list:
    return _const(MAIN, "TABLES")


@pytest.mark.parametrize("table", _shipped_tables())
def test_every_shipped_table_has_something_that_writes_it(table):
    """`security_audit` sat in this list with no collector anywhere - not a
    broken one, none at all. It was shipped empty every cycle and the console
    showed it permanently as NOT COLLECTED, which reads as a sensor that
    failed rather than one that was never built.

    A table here is a promise that this agent reports it.
    """
    import re

    sources = [p for p in (ROOT / "Sentora").rglob("*.py")]
    writers = [
        p.name for p in sources
        if re.search(rf"insert_record(_enc)?\(\s*['\"]{table}['\"]",
                     p.read_text(encoding="utf-8", errors="ignore"))
        or re.search(rf"TABLE\s*=\s*['\"]{table}['\"]",
                     p.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert writers, (
        f"the agent ships '{table}' and nothing writes a row to it, so the "
        f"console will show it as a collector that failed"
    )
