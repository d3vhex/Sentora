"""The AI was triaging ciphertext.

The agent encrypts `message` before sending, and it stays encrypted through
the database and the queue - correctly. What nothing did was decrypt it again
before use, so `ai_worker` serialised `enc::gAAAA...` straight into the prompt.

The model answered anyway. Shown a Fernet blob it produced "Procdump executed
against lsass" on an alert categorised LateralMovement, at confidence 0.50 -
which `ai/gating` had already measured as the model's "I have nothing" output.
Every insight looked like an insight, which is why this survived so long.

The eval never caught it: `evals/corpus_attacks.jsonl` holds plaintext
messages, so the harness measured the model on logs it could read while
production fed it blobs.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from core import telemetry_crypto as tc

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def keyed(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    path = tmp_path / "fernet.key"
    path.write_bytes(key)
    monkeypatch.setattr(tc, "_KEY_PATH", str(path))
    monkeypatch.setattr(tc, "_fernet", None)
    monkeypatch.setattr(tc, "_load_error", None)
    return Fernet(key)


def enc(fernet, value: str) -> str:
    """As the agent writes it: json-encoded, then Fernet, then prefixed."""
    return tc.ENC_PREFIX + fernet.encrypt(json.dumps(value).encode()).decode()


def test_an_encrypted_message_comes_back_as_the_log(keyed):
    row = {"message": enc(keyed, r"reg.exe save HKLM\SAM C:\out.hive"),
           "severity": "HIGH"}
    out = tc.decrypt_item("siem_events", row)
    assert out["message"] == r"reg.exe save HKLM\SAM C:\out.hive"


def test_the_json_layer_is_stripped(keyed):
    """`enc_db._enc_value` json-encodes before encrypting. A consumer that
    skips that layer gets a JSON string containing JSON, and everything
    downstream sees escaped quotes where an event should be."""
    out = tc.decrypt_item("siem_events", {"message": enc(keyed, 'a "quoted" thing')})
    assert out["message"] == 'a "quoted" thing'
    assert not out["message"].startswith('"')


def test_the_original_row_is_not_modified(keyed):
    """The caller still needs the ciphertext, to store and to forward.
    Decrypting in place would turn the row being written to the database into
    plaintext - the opposite of what the encryption is for."""
    original = {"message": enc(keyed, "secret")}
    before = original["message"]
    tc.decrypt_item("siem_events", original)
    assert original["message"] == before
    assert original["message"].startswith(tc.ENC_PREFIX)


def test_plaintext_passes_through_untouched(keyed):
    """Older agents, and tables that were never encrypted."""
    out = tc.decrypt_item("siem_events", {"message": "already readable"})
    assert out["message"] == "already readable"


def test_an_undecryptable_value_is_kept_not_dropped(keyed):
    """A row encrypted under a key that no longer exists is still a row that
    happened. Dropping it turns "events under the wrong key" into "no events",
    and those call for different actions."""
    from cryptography.fernet import Fernet

    other = Fernet(Fernet.generate_key())
    row = {"message": tc.ENC_PREFIX + other.encrypt(b'"x"').decode()}
    out = tc.decrypt_item("siem_events", row)
    assert out["message"].startswith(tc.ENC_PREFIX)
    assert tc.stats["undecryptable"] >= 1


def test_a_missing_key_is_reported_rather_than_generated(tmp_path, monkeypatch):
    """A worker that generated its own key would hold one nothing was
    encrypted with, decrypt nothing, and look like it was working."""
    monkeypatch.setattr(tc, "_KEY_PATH", str(tmp_path / "absent.key"))
    monkeypatch.setattr(tc, "_fernet", None)
    monkeypatch.setattr(tc, "_load_error", None)

    assert tc.available() is False
    error = tc.load_error()
    assert "sentora_data" in error
    assert "not" in error and "FERNET_KEY" in error
    assert not (tmp_path / "absent.key").exists()


def test_events_alert_decrypts_source_as_well_as_message(keyed):
    """The alerts table encrypts both, and `source` is what the correlation
    check keys on."""
    row = {"source": enc(keyed, "Security/Auditing"),
           "message": enc(keyed, "An account failed to log on")}
    out = tc.decrypt_item("events_alert", row)
    assert out["source"] == "Security/Auditing"
    assert out["message"] == "An account failed to log on"


def test_an_unknown_table_is_returned_as_a_copy(keyed):
    row = {"anything": "here"}
    out = tc.decrypt_item("not_a_table", row)
    assert out == row
    assert out is not row


# --------------------------------------------------------------------------
# The two places it has to be called
# --------------------------------------------------------------------------

def test_the_worker_decrypts_before_building_the_prompt():
    worker = (ROOT / "ai_worker.py").read_text(encoding="utf-8")
    decrypt_at = worker.index("telemetry_crypto.decrypt_item(table, data)")
    prompt_at = worker.index("log_text = json.dumps(data, indent=2)")
    assert decrypt_at < prompt_at


def test_the_ingest_path_decrypts_before_correlating():
    """A correlation window counting ciphertext counts nothing: Fernet's
    random IV makes every encryption of the same text different, so no two
    events ever look related."""
    server = (ROOT / "server.py").read_text(encoding="utf-8")
    assert "telemetry_crypto.decrypt_item(table, item)" in server
    assert 'agent_event_fields(plain.get("message")' in server


def test_the_database_write_still_stores_ciphertext():
    """Decrypting for use must not become decrypting at rest."""
    server = (ROOT / "server.py").read_text(encoding="utf-8")
    insert = server[server.index("sql = f\"INSERT INTO"):]
    insert = insert[:insert.index("\n\n")]
    assert "plain" not in insert


def test_every_container_that_decrypts_can_reach_the_key():
    """The key lives in a named volume only `app` mounted. Without it the
    others read nothing, generate nothing, and hand the model ciphertext."""
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
    for name in ("ingest", "ai-worker-automation", "ai-worker-manual",
                 "ai-worker-defensive"):
        volumes = compose["services"][name].get("volumes") or []
        assert any("sentora_data:/app/data" in str(v) for v in volumes), name


def test_the_workers_mount_it_read_only():
    """`app` creates the key. A worker that could write there might generate a
    different one and silently decrypt nothing."""
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
    for name in ("ingest", "ai-worker-automation", "ai-worker-manual",
                 "ai-worker-defensive"):
        volumes = compose["services"][name]["volumes"]
        mount = next(v for v in volumes if "sentora_data" in str(v))
        assert str(mount).endswith(":ro"), name
