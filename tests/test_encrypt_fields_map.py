"""Guards on which agent fields get encrypted at rest.

The bug these exist for: `set_encrypt_fields_map` defaulted to *replace*, and
four modules called it — one from inside a periodic scan. Import order decided
what was encrypted, and after the first permission scan the map was reduced to
`critical_files` alone, so SIEM events, alerts, FIM data and process telemetry
all started writing plaintext. Nothing surfaced it: rows just stopped carrying
the `enc::` prefix.

Parsed from source rather than imported. Sentora/modules/enc_db.py pulls in the
agent's DB layer at import time, which has no business running in a server-side
test.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parent.parent / "Sentora"
ENC_DB = AGENT / "modules" / "enc_db.py"
APP_PY = Path(__file__).resolve().parent.parent / "app.py"


def _module_level_dict(path: Path, name: str) -> dict:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == name:
            return ast.literal_eval(node.value)
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found at module level in {path.name}")


@pytest.fixture(scope="module")
def agent_map() -> dict:
    return _module_level_dict(ENC_DB, "ENCRYPT_FIELDS_MAP")


@pytest.fixture(scope="module")
def server_map() -> dict:
    return _module_level_dict(APP_PY, "ENCRYPTED_FIELDS_MAP")


def test_merge_is_the_default(agent_map):
    """The whole bug in one line: a replace-by-default setter shared by four
    callers."""
    src = ENC_DB.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src)

    fn = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "set_encrypt_fields_map"
    )
    merge_default = next(
        (d for kw, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults) if kw.arg == "merge"),
        None,
    )
    assert merge_default is not None, "merge is no longer a keyword-only arg"
    assert merge_default.value is True, "merge must default to True"


def test_no_agent_module_replaces_the_map():
    """Any call without merge=True silently discards other modules' fields.

    Now that merge defaults to True a stray call is harmless, but an explicit
    merge=False would bring the bug straight back.
    """
    offenders = []
    for py in AGENT.rglob("*.py"):
        if py.name == "enc_db.py":
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        if "merge=False" in text and "set_encrypt_fields_map" in text:
            offenders.append(py.name)
    assert not offenders, f"these replace the encryption map: {offenders}"


def test_map_is_not_set_from_inside_a_function(agent_map):
    """check_permissions called it from its periodic scan, so the map was
    rewritten every few minutes for the life of the process."""
    for py in AGENT.rglob("*.py"):
        if py.name == "enc_db.py":
            continue
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Call)
                        and getattr(inner.func, "attr", getattr(inner.func, "id", None))
                        == "set_encrypt_fields_map"):
                    pytest.fail(
                        f"{py.name}:{node.name} sets the encryption map at call time; "
                        f"declare fields in enc_db.ENCRYPT_FIELDS_MAP instead"
                    )


@pytest.mark.parametrize("table,field", [
    ("siem_events", "message"),
    ("events_alert", "source"),
    ("events_alert", "message"),
    ("critical_files", "path"),
    ("fim_data", "path"),
    ("fim_data", "hash_sha256"),
    ("process_events", "cmdline"),
    ("registry_logs", "value_data"),
    ("network_connections", "remote_addr"),
    ("hardware_inventory", "serial_number"),
    ("security_audit", "details"),
])
def test_sensitive_fields_are_registered(agent_map, table, field):
    """Every field a module used to declare, plus the enc_db defaults that
    module-level replacement was wiping out."""
    assert field in agent_map.get(table, []), f"{table}.{field} is no longer encrypted"


def test_indexed_columns_stay_in_the_clear(agent_map):
    """`siem_events.source` is indexed in the agent schema. Encrypting it
    would make the index useless and break any WHERE on it."""
    assert "source" not in agent_map.get("siem_events", [])


def test_server_map_covers_everything_the_agent_encrypts(agent_map, server_map):
    """The asymmetry that is allowed is server ⊇ agent. A field the agent
    encrypts but the server does not decrypt renders as raw ciphertext.
    """
    missing = []
    for table, fields in agent_map.items():
        server_fields = server_map.get(table)
        if server_fields is None:
            missing.append(f"{table} (table absent server-side)")
            continue
        for f in fields:
            if f not in server_fields:
                missing.append(f"{table}.{f}")
    assert not missing, f"the server will not decrypt: {missing}"
