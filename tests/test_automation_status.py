"""`automations.status` must be able to say 'cancelled'.

Stopping a runaway dispatch is not the same as the action failing, but the
ENUM had no value for it - so a cancellation was written as 'failed' with the
real reason in a comment prefix. Status is what queries and the UI filter on;
burying it in free text means nothing can count cancellations.

`playbook_runs` already had 'cancelled', which is what made the omission look
deliberate rather than missing.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

SCHEMAS = {
    "mysql (server)": ROOT / "db" / "init.sql",
    "postgres (agent)": ROOT / "Sentora" / "db" / "init.sql",
    "sqlite (agent fallback)": ROOT / "Sentora" / "db" / "init_sqlite.sql",
}

EXPECTED = {"pending", "active", "paused", "completed", "failed", "cancelled"}


def _automations_block(text: str) -> str:
    m = re.search(r"CREATE TABLE IF NOT EXISTS automations\s*\((.*?)\n\)", text, re.S)
    assert m, "automations table not found"
    return m.group(1)


@pytest.mark.parametrize("label,path", SCHEMAS.items())
def test_cancelled_is_an_allowed_status(label, path):
    block = _automations_block(path.read_text(encoding="utf-8"))
    values = set(re.findall(r"'([a-z]+)'", block))
    missing = EXPECTED - values
    assert not missing, f"{label}: automations.status cannot express {sorted(missing)}"


def test_mysql_migration_is_guarded_and_not_in_the_schema_file():
    """CREATE TABLE IF NOT EXISTS does not widen an existing ENUM, so a
    migration is needed - but it must not live in init.sql.

    That file is re-executed on every call to create_tables_if_not_exist. An
    unconditional ALTER there took a metadata lock on `automations` each time.
    With one leaked connection holding an open transaction on the table, the
    ALTER queued behind it, and in MySQL a waiting DDL blocks every reader
    that arrives after it. Agents polling /automations/pending got no answer
    at all until Sanic returned 500 ten seconds later, and killing the blocked
    ALTER did not help because the next call re-issued it.
    """
    schema = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    code = "\n".join(l for l in schema.splitlines()
                     if not l.strip().startswith("--"))
    assert "ALTER TABLE automations" not in code, (
        "an unconditional ALTER in init.sql takes a metadata lock on every "
        "schema pass"
    )

    server = (ROOT / "server.py").read_text(encoding="utf-8")
    i = server.index("def _migrate_automation_status")
    body = server[i:i + 2200]
    assert "information_schema.columns" in body, "the migration is not guarded"
    assert "'cancelled' in str(row[0])" in body or "cancelled" in body
    assert "lock_wait_timeout" in body, (
        "without a lock timeout the migration can block the polling endpoints"
    )
    assert "_migrate_automation_status(cursor" in server, "never called"


def test_postgres_has_an_idempotent_migration():
    """apply_schema re-runs this file on every agent start, so it must be safe."""
    text = (ROOT / "Sentora" / "db" / "init.sql").read_text(encoding="utf-8")
    assert "DROP CONSTRAINT IF EXISTS automations_status_check" in text
    add = re.search(r"ADD CONSTRAINT automations_status_check\s*\n?\s*CHECK \(status IN \(([^)]*)\)", text)
    assert add and "cancelled" in add.group(1)


def test_playbook_runs_still_allows_cancelled():
    """The value it already had, and the reason the gap was visible."""
    text = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    m = re.search(r"CREATE TABLE IF NOT EXISTS playbook_runs\s*\((.*?)\n\)", text, re.S)
    assert m and "cancelled" in m.group(1)
