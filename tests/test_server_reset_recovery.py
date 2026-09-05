"""When the server forgets, the agent has to be told.

`sent` lives on the agent and is its only record of what the server holds.
Nothing tells it when the server's database for that agent is dropped and
recreated - a re-enrolment, a deleted agent, a fresh volume - and by design a
row marked sent is never offered again.

The damage lands entirely on the quiet tables. `fim_data` and
`network_connections` produce rows constantly, so the server refills within
minutes and nobody notices anything happened. `portscan_result`,
`process_events` and `soar_actions` do not, so they stay empty for ever. On a
live host that read as:

    portscan_result   LOST IN TRANSIT   held 93   unsent 0   on server 0

with the server holding no fingerprints for it either - not discarded, never
offered. Every layer was behaving correctly and the data was unreachable.

The fix is one value. The server stamps each incarnation of an agent database
with an identity, returns it on every ingest receipt, and an agent that sees
it change knows the server has forgotten and offers its rows again.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"
SCHEMA = ROOT / "db" / "init.sql"
MAIN = ROOT / "Sentora" / "main.py"
AGENT_DB = ROOT / "Sentora" / "modules" / "db.py"


def _function(path: pathlib.Path, name: str):
    return next(n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


# --------------------------------------------------------------------------
# The server has an identity to report
# --------------------------------------------------------------------------

def test_the_schema_carries_an_epoch():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS ingest_epoch" in schema


def test_it_is_stamped_once_per_database():
    """`INSERT IGNORE` on a fixed primary key: a database that already has an
    identity keeps it, and only a freshly created one gets a new value. A
    plain INSERT would change the epoch on every batch and make the agent
    resend its history for ever."""
    source = SERVER.read_text(encoding="utf-8")
    stamp = next(line for line in source.splitlines()
                 if "INSERT IGNORE INTO ingest_epoch" in line)
    assert "id, epoch" in stamp and "UUID()" in stamp


def test_every_receipt_carries_it():
    """The agent has no other way to hear about a reset. A receipt without it
    is a receipt that cannot report the one thing this exists for."""
    body = ast.unparse(_function(SERVER, "insert_data"))
    success = body[body.index("conn.commit()"):]
    success = success[:success.index("except Exception")]
    assert "'epoch'" in success or '"epoch"' in success


def test_an_unreadable_epoch_reads_as_no_information():
    """Not as a reset. The agent treating a failed query as "the server
    forgot" would make it re-ship its whole history on a bad connection."""
    fn = _function(SERVER, "_ingest_epoch")
    handler = next(h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler))
    body = ast.unparse(handler)
    assert "return ''" in body or 'return ""' in body


# --------------------------------------------------------------------------
# The agent acts on it
# --------------------------------------------------------------------------

def test_a_changed_epoch_re_offers_rows():
    body = ast.unparse(_function(MAIN, "_handle_server_epoch"))
    assert "reoffer_recent" in body
    assert "TABLES" in body, "only some tables would be recovered"


def test_the_first_sighting_also_re_offers():
    """The obvious rule - "nothing to compare against, so do nothing" - is
    wrong, and this test exists because it was written that way first.

    The agents that most need recovery are exactly the ones that have been
    running since before the epoch existed, holding rows marked sent against a
    server that may never have received them. Skipping the first sighting
    fixes the next reset and leaves the current damage in place, which on the
    host this was written for meant 93 port-scan rows that were never coming
    back.

    It is safe because it costs nothing where it does not apply: a fresh
    install has an empty local database and the sweep finds no rows, and an
    agent already in sync offers rows the server recognises and skips.
    """
    body = ast.unparse(_function(MAIN, "_handle_server_epoch"))
    guard = body[:body.index("reoffer_recent")]
    assert "return" not in guard.split("if not epoch")[-1].split("previous")[0] \
        or "if previous" in guard, \
        "a first sighting still returns early, so stranded rows stay stranded"
    assert "if previous" in body, \
        "the two cases are no longer distinguished in the message"


def test_an_absent_epoch_changes_nothing():
    """A server older than this sends no epoch, and that has to keep
    working."""
    body = ast.unparse(_function(MAIN, "_handle_server_epoch"))
    assert "if not epoch" in body


def test_it_survives_a_restart():
    """A reset that happens while the agent is stopped is the likeliest case -
    that is when somebody deletes an agent and reinstalls it. Holding the
    epoch only in memory would miss exactly that."""
    source = MAIN.read_text(encoding="utf-8")
    assert "_load_epoch()" in source
    main_body = ast.unparse(_function(MAIN, "main"))
    assert "_load_epoch()" in main_body, \
        "the remembered epoch is never loaded at startup"


def test_the_resend_is_bounded():
    """`hardware_inventory` on one host held 530,000 rows. Re-offering all of
    them at fifty a batch is a replay measured in days, during which nothing
    current gets through - a recovery that costs more than the loss."""
    source = MAIN.read_text(encoding="utf-8")
    assign = next(n for n in ast.parse(source).body
                  if isinstance(n, ast.Assign)
                  and any(getattr(t, "id", "") == "_REOFFER_LIMIT"
                          for t in n.targets))
    limit = ast.literal_eval(assign.value)
    assert 0 < limit <= 5000, f"_REOFFER_LIMIT is {limit}"

    body = ast.unparse(_function(AGENT_DB, "reoffer_recent"))
    assert "LIMIT" in body, "the re-offer is unbounded"
    assert "ORDER BY id DESC" in body, \
        "an unordered LIMIT re-offers arbitrary rows rather than the newest"


def test_resending_cannot_duplicate():
    """The resend is only safe because the server deduplicates. If a table
    were ever re-offered into a server that stores blindly, recovery would
    become corruption."""
    dedup = next(n for n in ast.parse(SERVER.read_text(encoding="utf-8")).body
                 if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") == "DEDUP_TABLES" for t in n.targets))
    deduplicated = set(ast.literal_eval(dedup.value))
    snapshot = next(n for n in ast.parse(SERVER.read_text(encoding="utf-8")).body
                    if isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == "SNAPSHOT_TABLES" for t in n.targets))
    snapshotted = set(ast.literal_eval(snapshot.value))

    # Every table the agent ships is one or the other, so a re-offered row is
    # either skipped as a duplicate or replaces the previous picture.
    allowed = next(n for n in ast.parse(SERVER.read_text(encoding="utf-8")).body
                   if isinstance(n, ast.Assign)
                   and any(getattr(t, "id", "") == "ALLOWED_TABLES" for t in n.targets))
    unprotected = set(ast.literal_eval(allowed.value)) - deduplicated - snapshotted
    assert not unprotected, (
        f"{sorted(unprotected)} would accumulate duplicates on a re-offer"
    )


# --------------------------------------------------------------------------
# The bounded update itself
# --------------------------------------------------------------------------

def test_reoffer_reports_what_it_changed():
    """Silence here is how a recovery that did nothing looks like one that
    worked."""
    fn = _function(AGENT_DB, "reoffer_recent")
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert returns and all(n.value is not None for n in returns)
    assert "rowcount" in ast.unparse(fn)


def test_the_operator_is_told_it_happened():
    """Rows quietly reappearing is indistinguishable from a bug. The log has
    to name the event, because it explains a burst of traffic somebody will
    otherwise investigate."""
    body = ast.unparse(_function(MAIN, "_handle_server_epoch"))
    assert "recreated" in body


# --------------------------------------------------------------------------
# The console has to name the right cause
# --------------------------------------------------------------------------

def test_a_reset_is_not_reported_as_discarded():
    """"the agent has shipped 93 row(s) and this server holds none - accepted
    and discarded" is one of two situations, and only one of them is a fault:

        the server took the rows and threw them away
        the server's database was recreated after they were sent

    Reporting the second as the first sent somebody hunting a bug that was not
    there, twice in one day. The timestamp that separates them costs one
    query.
    """
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(app_py))
              if isinstance(n, ast.FunctionDef) and n.name == "_classify_link")
    body = ast.unparse(fn)
    assert "server reset" in body
    assert "_shipped_before" in body


def test_the_comparison_refuses_to_guess():
    """A missing timestamp on either side has to mean "cannot tell", not
    "reset". Claiming a reset that did not happen is a worse error than the
    vague verdict it replaces."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(app_py))
              if isinstance(n, ast.FunctionDef) and n.name == "_shipped_before")
    namespace: dict = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "app.py", "exec"),
         namespace)
    shipped_before = namespace["_shipped_before"]

    import datetime as dt
    assert shipped_before(None, dt.datetime(2026, 1, 1)) is False
    assert shipped_before(1000.0, None) is False
    assert shipped_before(1000.0, "not a datetime") is False

    created = dt.datetime(2026, 9, 4, 12, 0, 0)
    assert shipped_before(created.timestamp() - 60, created) is True
    assert shipped_before(created.timestamp() + 60, created) is False


def test_a_reset_does_not_keep_the_banner_red():
    """The rows are gone and nothing is wrong now. Counting it as broken would
    hold the console at a warning over a condition that resolves itself on the
    next re-offer."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(app_py))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "get_telemetry_health")
    broken = ast.unparse(fn)
    broken = broken[broken.index("broken ="):]
    assert "server reset" not in broken.split("]")[0]


def test_the_console_knows_the_new_state():
    """A state the API can return and the UI has never heard of renders as a
    neutral chip with no meaning - which is how it looked before any of this
    had names."""
    page = (ROOT / "frontend" / "src" / "pages" / "TelemetryHealth.tsx").read_text(
        encoding="utf-8")
    assert "'server reset'" in page
    tone = page[page.index("const STATE_TONE"):page.index("const STATE_RANK")]
    assert "'server reset'" in tone
    rank = page[page.index("const STATE_RANK"):]
    rank = rank[:rank.index("};")]
    assert "'server reset'" in rank, "the new state sorts to the bottom by default"
