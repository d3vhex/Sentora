"""An encrypted column has to be wide enough for the ciphertext.

The Network tab was empty for days. The agent's log said

    [+] network_connections sent (50 rows)

and the ingest log said

    [!] Data insertion error: 1406 (22001): Data too long for column
        'local_addr' at row 1

`local_addr` is `VARCHAR(64)` and is one of the fields `enc_db` encrypts. A
Fernet token carries a version byte, a timestamp, a 16-byte IV, the padded
ciphertext and a 32-byte HMAC, base64-encoded - so even a value like
`10.0.0.7` comes out over a hundred characters, plus the `enc::` prefix.
Every batch failed on its first row.

Worse than a rejected batch: `network_connections` is a snapshot table, so
`DELETE FROM` had already run before the insert failed. Each cycle emptied the
table and then failed to refill it.

Nothing connected the two logs. The agent reported success because `sendall`
returned, the server reported an error into a log nobody was reading, and the
console showed an empty tab that reads as "this host has no connections".

This test compares the two declarations that have to agree - which fields are
encrypted, and how wide the columns are - and fails on the mismatch rather
than on the empty tab three layers away.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "db" / "init.sql"
APP = ROOT / "app.py"

#: The shortest Fernet token, base64, plus the `enc::` marker.
#:
#: A token is 1 + 8 + 16 + 16 + 32 = 73 bytes before the plaintext is padded
#: in, which is 100 base64 characters; `enc::` makes 105. Anything narrower
#: cannot hold the encryption of even an empty string. 200 leaves room for a
#: short value without being so generous that a genuinely small column passes
#: by accident.
MIN_ENCRYPTED_WIDTH = 200

#: Types with no length to check.
UNBOUNDED = {"TEXT", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT", "BLOB", "JSON"}


def _encrypted_fields() -> dict:
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", "") == "ENCRYPTED_FIELDS_MAP"):
            return ast.literal_eval(node.value)
    raise AssertionError("ENCRYPTED_FIELDS_MAP is not a literal in app.py")


def _column_type(table: str, column: str):
    """(type, declared length) for one column, or None if it is not there."""
    schema = SCHEMA.read_text(encoding="utf-8")
    block = re.search(
        rf"CREATE TABLE IF NOT EXISTS {re.escape(table)}\s*\((.*?)\n\)",
        schema, re.S)
    if not block:
        return None
    match = re.search(
        rf"[`\s]{re.escape(column)}[`\s]+([A-Za-z]+)(?:\((\d+)\))?",
        block.group(1))
    if not match:
        return None
    return match.group(1).upper(), (int(match.group(2)) if match.group(2) else None)


CASES = [
    pytest.param(table, column, id=f"{table}.{column}")
    for table, columns in _encrypted_fields().items()
    for column in columns
]


@pytest.mark.parametrize("table,column", CASES)
def test_an_encrypted_column_can_hold_its_ciphertext(table, column):
    declared = _column_type(table, column)
    if declared is None:
        pytest.skip(f"{table}.{column} is not in db/init.sql")

    kind, width = declared
    if kind in UNBOUNDED:
        return
    assert width is not None, f"{table}.{column} is {kind} with no length"
    assert width >= MIN_ENCRYPTED_WIDTH, (
        f"{table}.{column} is {kind}({width}) and holds Fernet ciphertext, "
        f"which is at least {MIN_ENCRYPTED_WIDTH} characters. Every insert "
        f"fails with 'Data too long', and on a snapshot table the DELETE has "
        f"already run - so the table is emptied and never refilled, while the "
        f"agent reports the rows as sent."
    )


def test_the_two_declarations_are_actually_compared():
    """The premise. If either list stops being a literal this file starts
    passing vacuously, which is the failure mode of every test that reads
    source."""
    assert _encrypted_fields(), "no encrypted fields found"
    assert len(CASES) >= 20, f"only {len(CASES)} encrypted columns found"


def test_encrypted_reads_decrypt():
    """A route reading an encrypted table has to be given its fields.

    `get_network_inventory` was not, and nowhere else was missing them - so
    the Network tab rendered `enc::gAAAAAB...` where the process name should
    be. Ciphertext in a column reads as data rather than as a fault: the page
    looked populated and was unusable, which is a worse failure than an empty
    one because nothing about it says something is wrong.
    """
    source = APP.read_text(encoding="utf-8")
    tree = ast.parse(source)
    encrypted = _encrypted_fields()

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", "")
        if name not in ("stream_from_db", "stream_from_db_dec"):
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        table = node.args[0].value
        if table not in encrypted:
            continue
        passes = any(kw.arg == "encrypted_fields" for kw in node.keywords)
        if name == "stream_from_db" or not passes:
            offenders.append(table)

    assert not offenders, (
        f"{sorted(set(offenders))} hold encrypted columns and are read "
        f"without decrypting them; the console will show `enc::...`"
    )


def test_an_encrypted_field_names_a_real_column():
    """A field encrypted on the agent and absent from the server's schema is
    written nowhere and read as plaintext - the mirror of this bug."""
    missing = []
    for table, columns in _encrypted_fields().items():
        schema = SCHEMA.read_text(encoding="utf-8")
        if f"CREATE TABLE IF NOT EXISTS {table}" not in schema:
            continue                      # the table lives elsewhere
        for column in columns:
            if _column_type(table, column) is None:
                missing.append(f"{table}.{column}")
    assert not missing, f"encrypted fields with no column: {missing}"
