"""The agent's module reference has to describe the agent that exists.

Nothing checked it, and it had drifted into naming three tables that were
never in the schema:

    installed_software      the real one is software_inventory
    resource_log            the real one is resource_usage
    disk_info               the real one is disk_usage

A reader following any of those writes a query that returns "relation does not
exist" and concludes the agent is broken. The failure mode is the same one this
codebase keeps meeting from the other side - a name that reads as authoritative
and refers to nothing - and a document is the one place it can persist for
months without a single error anywhere.

`network_inventory` was the reverse: a table the agent has written since it was
written, absent from the document entirely. It was also, not coincidentally,
one of the two tables nothing ever shipped.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "Sentora"
DOC = AGENT / "docs" / "MODULES.md"
SCHEMA = AGENT / "db" / "init.sql"


def _schema_tables() -> set[str]:
    from tests.test_agent_schema_migration import _load_func

    strip = _load_func(AGENT / "modules" / "db.py", "_strip_comments")
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS\s+(\w+)",
                          strip(SCHEMA.read_text(encoding="utf-8"))))


def _output_lines(text: str) -> list[str]:
    """Each `- Output table(s):` entry, wrapped continuations rejoined.

    The file wraps at 72 columns, so `edr_enforcer`'s five tables and
    `inventory`'s three run onto a second line. Reading line by line found the
    first table of each and silently missed the rest - which is the same shape
    of bug as the ones this file is being checked for.
    """
    entries: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- Output table"):
            if current:
                entries.append(" ".join(current))
            current = [stripped]
        elif current:
            # A continuation is indented and starts no new bullet.
            if line.startswith("  ") and not stripped.startswith("- "):
                current.append(stripped)
            else:
                entries.append(" ".join(current))
                current = []
    if current:
        entries.append(" ".join(current))
    return entries


def _documented_tables() -> set[str]:
    """Table names from the `Output table(s):` lines only.

    Deliberately not every backticked word in the file. The prose names
    functions, files and columns too, and a check that flags those produces so
    much noise it gets deleted - which is how the document came to be unchecked
    in the first place.
    """
    text = DOC.read_text(encoding="utf-8")
    names: set[str] = set()
    for entry in _output_lines(text):
        stripped = entry.strip()
        # These lines name columns as well as tables: `siem_events`
        # (encrypted `message`), `hardware_inventory` (enc) for `name` and
        # `serial_number`, and the portscanner's full column list after an
        # em-dash. Reporting `message` and `name` as missing tables is noise,
        # in the one test whose value is that its output is worth reading.
        #
        # So: drop anything after an em-dash, split the rest on the separators
        # the file actually uses, and take the first backticked token of each
        # part - which is the table, with its annotations trailing it.
        head = stripped.split("—")[0]
        head = head.split(":", 1)[-1]
        for part in re.split(r"[;,]", head):
            found = re.search(r"`([a-z_]+)`", part)
            if found:
                names.add(found.group(1))
    return names


def test_the_document_exists_and_lists_outputs():
    assert DOC.exists()
    assert _documented_tables(), "no `Output table:` lines were parsed"


@pytest.mark.parametrize("table", sorted(_documented_tables()))
def test_every_documented_table_is_in_the_schema(table):
    """The check that was missing. Three names failed this for months."""
    assert table in _schema_tables(), (
        f"MODULES.md names `{table}` as an output table and "
        f"Sentora/db/init.sql has no such table"
    )


def test_the_tables_that_were_wrong_stay_gone():
    """Named individually, because a rename is exactly the edit that would
    reintroduce one while the generic check above still passed."""
    text = DOC.read_text(encoding="utf-8")
    for wrong, right in (("installed_software", "software_inventory"),
                         ("resource_log", "resource_usage"),
                         ("disk_info", "disk_usage")):
        # The corrected entries mention the old name to explain the change, so
        # this looks only at the machine-readable output lines.
        assert wrong not in _documented_tables(), (
            f"`{wrong}` is documented as an output table again; it is "
            f"`{right}`"
        )


def test_a_table_the_agent_ships_is_described_somewhere():
    """The other direction. `network_inventory` was written every cycle and
    appeared nowhere in the document - which is how a table nothing shipped
    stayed invisible from both ends at once."""
    import ast

    main = (AGENT / "main.py").read_text(encoding="utf-8")
    block = re.search(r"^TABLES = \[(.*?)^\]", main, re.S | re.M)
    assert block, "TABLES is no longer a list literal"
    shipped = set(re.findall(r"['\"]([a-z_]+)['\"]", block.group(1)))

    text = DOC.read_text(encoding="utf-8")
    # Not every shipped table has its own module section - several are written
    # by the same collector - so the bar is that the name appears at all.
    missing = sorted(t for t in shipped if f"`{t}`" not in text)
    assert not missing, (
        f"the agent ships {missing} and the module reference never names them"
    )


def test_the_shipping_rule_is_stated():
    """A module author who writes a table and does not add it to `TABLES`
    produces a collector whose output never leaves the host, and every layer
    reports success. That has happened twice; the document says so now."""
    text = DOC.read_text(encoding="utf-8")
    assert "TABLES" in text, "the list that decides what ships is not mentioned"
    assert "main.py" in text


def test_the_document_is_text():
    """A NUL byte got into this file while it was being corrected — from an
    escape that collapsed one layer too far while writing about `scrub_nuls`,
    of all things.

    One byte is enough to make `grep` call the file binary and stop printing
    matches, so every text tool silently goes quiet on it. That is the same
    failure this whole document was just audited for, in the tooling rather
    than the content.
    """
    raw = DOC.read_bytes()
    assert bytes([0]) not in raw, "MODULES.md contains a NUL byte; grep will treat it as binary"


def test_security_audit_is_not_claimed_as_an_output():
    """Three modules were documented as writing it and none ever did. The
    table exists so a collector can be added without a schema change; until
    one is, claiming it is what made an empty tab read as a broken sensor."""
    assert "security_audit" not in _documented_tables(), (
        "a module claims security_audit as an output again — check that "
        "something actually writes it, and add it back to TABLES in main.py"
    )
