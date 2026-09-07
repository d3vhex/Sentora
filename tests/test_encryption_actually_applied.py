"""A field declared encrypted has to be written through the encrypting insert.

`enc_db.ENCRYPT_FIELDS_MAP` said fim_data's `path` and `hash_sha256` were
encrypted. `core.telemetry_crypto.ENCRYPTED_FIELDS` said the same, so the
server was ready to decrypt them. And `fim.py` - which produces almost every
fim_data row there is - called the plain `insert_record`.

So the file paths of every monitored host were stored in the clear, in the
agent's database and on the server, while both ends of the design said
otherwise. 1,081 rows on one host, none of them encrypted.

Nothing could see it. The server's `decrypt_value` hands anything without the
`enc::` prefix straight back, by design - that is what makes a mixed table
readable - so plaintext and ciphertext render *identically* in the console.
The table looked perfect. The only way to notice was to ask what the stored
bytes actually begin with.

This file removes the need to notice.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "Sentora"
ENC_DB = AGENT / "modules" / "enc_db.py"
SERVER_CRYPTO = ROOT / "core" / "telemetry_crypto.py"


def _map(path: pathlib.Path, name: str) -> dict:
    node = next(n for n in ast.parse(path.read_text(encoding="utf-8")).body
                if isinstance(n, (ast.Assign, ast.AnnAssign))
                and name in ast.unparse(n.target if isinstance(n, ast.AnnAssign)
                                        else n.targets[0]))
    return ast.literal_eval(node.value)


AGENT_MAP = _map(ENC_DB, "ENCRYPT_FIELDS_MAP")


def _inserts() -> list[tuple[pathlib.Path, int, str, str]]:
    """(file, line, table, which insert) for every insert in the agent."""
    found = []
    for path in AGENT.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if fn not in ("insert_record", "insert_record_enc"):
                continue
            if node.args and isinstance(node.args[0], ast.Constant):
                found.append((path, node.lineno, node.args[0].value, fn))
    return found


ENCRYPTED_WRITES = [
    pytest.param(path, line, table, fn,
                 id=f"{path.name}:{line}:{table}")
    for path, line, table, fn in _inserts()
    if table in AGENT_MAP
]


@pytest.mark.parametrize("path,line,table,fn", ENCRYPTED_WRITES)
def test_an_encrypted_table_is_written_through_the_encrypting_insert(
        path, line, table, fn):
    """The plain insert stores exactly what it is given. For a table with
    declared encrypted fields that means storing a secret in the clear, and
    nothing downstream can tell."""
    assert fn == "insert_record_enc", (
        f"{path.name}:{line} writes '{table}' with {fn}(), and "
        f"{sorted(AGENT_MAP[table])} are declared encrypted - so those values "
        f"are stored in the clear and render identically to encrypted ones"
    )


def test_there_is_at_least_one_such_write():
    """A parametrised test over an empty list passes silently. If the scan
    stops finding inserts - a rename, a helper, a different import style -
    this is the only thing that says so."""
    assert ENCRYPTED_WRITES, "the insert scan found nothing to check"


# --------------------------------------------------------------------------
# The two maps have to agree
# --------------------------------------------------------------------------

SERVER_MAP = _map(SERVER_CRYPTO, "ENCRYPTED_FIELDS")


@pytest.mark.parametrize("table", sorted(AGENT_MAP))
def test_everything_the_agent_encrypts_the_server_decrypts(table):
    """The agent encrypting a field the server does not decrypt is the worst
    of the four combinations: the console shows `enc::gAAAA...` and the data
    is there and unreadable, with nothing saying why."""
    assert table in SERVER_MAP, f"the server never decrypts anything in {table}"
    missing = sorted(set(AGENT_MAP[table]) - set(SERVER_MAP[table]))
    assert not missing, (
        f"the agent encrypts {table}.{missing} and the server does not "
        f"decrypt it, so the console will show ciphertext"
    )


def test_the_server_side_extras_are_deliberate():
    """The reverse - the server decrypting a field the agent leaves alone - is
    harmless, because `decrypt_value` returns anything without the `enc::`
    prefix untouched. It is recorded rather than asserted away, so the drift
    stays visible instead of accumulating.
    """
    drift = {}
    for table, fields in SERVER_MAP.items():
        extra = sorted(set(fields) - set(AGENT_MAP.get(table, ())))
        if extra:
            drift[table] = extra
    # Harmless today. If this ever grows past the known pair, somebody has
    # changed one map and not the other.
    assert set(drift) <= {"siem_events", "events_alert"}, (
        f"the two encryption maps have drifted further apart: {drift}"
    )
