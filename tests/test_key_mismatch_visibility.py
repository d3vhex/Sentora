"""How much of the stored history can this server actually read?

The answer was invisible. A key mismatch printed one line per field name -
guarded by a `set`, so once each for the life of the process - and then
returned `<decryption failed - key mismatch>` per value. Which meant a table
where 86% of the messages could not be read produced exactly the same output
as a table with one bad row.

Measured on a live host: 173 of 200 `siem_events` messages, 197 of 200
`events_alert` messages, 172 of 200 `critical_files` paths. The Fernet key
comes from the server's bootstrap and there is no rotation path, so everything
encrypted under a previous key is gone - that is not fixable, and it is
exactly why the *quantity* has to be visible rather than the fact.

The second half of this file is about not making it worse. Offering rows again
after a server reset was importing rows the agent itself can no longer read.
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
AGENT_DB = ROOT / "Sentora" / "modules" / "db.py"
ENC_DB = ROOT / "Sentora" / "modules" / "enc_db.py"


# --------------------------------------------------------------------------
# The scale, not just the fact
# --------------------------------------------------------------------------

def _health():
    """`decryption_health` and its counters, compiled on their own."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "decryption_health")
    counters = next(n for n in tree.body
                    if isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == "_decrypt_counters"
                            for t in n.targets))
    namespace: dict = {}
    exec(compile(ast.Module(body=[counters, fn], type_ignores=[]), "app.py", "exec"),
         namespace)
    return namespace


def test_nothing_read_is_not_a_problem():
    """Zero of zero has to say so rather than divide."""
    ns = _health()
    assert ns["decryption_health"]()["unreadable_percent"] == 0.0


def test_the_proportion_is_reported():
    """"3 failures" is meaningless without the denominator; the number that
    matters is what fraction of the history is readable."""
    ns = _health()
    ns["_decrypt_counters"]["decrypted"] = 27
    ns["_decrypt_counters"]["undecryptable"] = 173
    health = ns["decryption_health"]()
    assert health["unreadable_percent"] == 86.5
    assert health["undecryptable"] == 173


def test_a_healthy_server_says_so_differently():
    """An operator should be able to tell "nothing unreadable" from "not
    measured", which is the same distinction this whole codebase keeps
    getting wrong."""
    ns = _health()
    ns["_decrypt_counters"]["decrypted"] = 100
    clean = ns["decryption_health"]()["detail"]
    ns["_decrypt_counters"]["undecryptable"] = 1
    broken = ns["decryption_health"]()["detail"]
    assert clean != broken
    assert "no rotation path" in broken or "cannot be recovered" in broken


def test_successes_are_counted_too():
    """Counting only failures gives a denominator of failures, and every
    deployment then reads as 100% unreadable."""
    source = APP.read_text(encoding="utf-8")
    assert '_decrypt_counters["decrypted"] += 1' in source


def test_the_console_shows_it():
    """Counted and never surfaced is where this started."""
    page = (ROOT / "frontend" / "src" / "pages" / "AuditLogs.tsx").read_text(
        encoding="utf-8")
    assert "unreadable_percent" in page
    assert "undecryptable" in page


# --------------------------------------------------------------------------
# Recovery must not import what nobody can read
# --------------------------------------------------------------------------

def test_the_agent_can_tell_whether_it_still_reads_a_row():
    sys.path.insert(0, str(ROOT / "Sentora"))
    from cryptography.fernet import Fernet
    from modules import enc_db

    enc_db.set_encrypt_fields_map({"siem_events": ["message"]}, merge=True)

    enc_db.set_fernet_key(Fernet.generate_key())
    old_row = {"message": enc_db._enc_value("under the previous key")}
    enc_db.set_fernet_key(Fernet.generate_key())
    new_row = {"message": enc_db._enc_value("under the current key")}

    assert enc_db.is_readable("siem_events", old_row) is False
    assert enc_db.is_readable("siem_events", new_row) is True
    assert enc_db.is_readable("siem_events", {"message": "plaintext"}) is True
    assert enc_db.is_readable("disk_usage", {"percent": 12}) is True


def test_the_re_offer_skips_what_it_cannot_read():
    """Offering them again imports rows that render as
    `<decryption failed - key mismatch>` for ever, and spends a bounded
    recovery budget on data nobody can read. The first re-offer on a live host
    moved about two thousand of them onto the server."""
    body = ast.unparse(next(
        n for n in ast.walk(ast.parse(AGENT_DB.read_text(encoding="utf-8")))
        if isinstance(n, ast.FunctionDef) and n.name == "reoffer_recent"))
    assert "is_readable" in body


def test_an_unknown_shape_is_offered_rather_than_dropped():
    """No key configured yet, or a row this does not understand. The cost of
    offering it is an unreadable row; the cost of dropping it is a lost one,
    and this whole module exists to stop the second."""
    fn = next(n for n in ast.walk(ast.parse(AGENT_DB.read_text(encoding="utf-8")))
              if isinstance(n, ast.FunctionDef) and n.name == "reoffer_recent")
    handler = next(h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler))
    assert "keep.append" in ast.unparse(handler)
