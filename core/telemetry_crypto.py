"""Decrypt agent telemetry at the point it is read, not at rest.

The agent encrypts before sending. `Sentora/modules/enc_db.ENCRYPT_FIELDS_MAP`
lists which columns: `siem_events.message`, `events_alert.source` and
`.message`, and others. Those arrive as `enc::gAAAA...` and are stored that
way, which is the point.

Nothing decrypted them again before use, so `ai_worker` serialised
`enc::gAAAA...` straight into the prompt - **the model was triaging Fernet
blobs** on every automation verdict for an encrypted table.

It stayed invisible because the model answers anyway. Shown a blob it produced
"Procdump executed against lsass" on an alert categorised LateralMovement, at
confidence 0.50 - the output `ai/gating` measured as its "I have nothing"
response. The eval could not catch it either: the corpus holds plaintext
messages, so the harness measured the model on logs it could read while
production fed it blobs.

Where this decrypts, and where it does not
------------------------------------------
At the point of use, in memory, on a copy:

    the database row          stays encrypted
    the RabbitMQ message      stays encrypted
    the prompt                gets plaintext
    correlation fields        get plaintext

Decrypting once at ingest would be less code and would put every log line on
the broker in the clear. A queue is data at rest for as long as it is queued.

A value that will not decrypt is kept and counted, not dropped: "no events"
and "events under the wrong key" call for different actions.
"""

from __future__ import annotations

import json
import os
import threading

ENC_PREFIX = "enc::"

# What the agent encrypts, from Sentora/modules/enc_db.ENCRYPT_FIELDS_MAP.
# Duplicated rather than imported: `core/` is shared by the server and the
# agent, and the server must not need the agent package on its path to read
# its own telemetry.
ENCRYPTED_FIELDS = {
    "siem_events": ("source", "timestamp", "message"),
    "events_alert": ("source", "timestamp", "severity", "score",
                     "categories", "message"),
    "fim_data": ("path", "hash_sha256"),
    "registry_logs": ("hive", "key_path", "value_name", "value_data"),
    "network_connections": ("process_name", "local_addr", "remote_addr"),
    "process_events": ("name", "cmdline", "username"),
    "hardware_inventory": ("name", "serial_number"),
    "security_audit": ("finding", "details"),
    "critical_files": ("path", "owner", "grp", "permissions", "last_opened"),
}

_KEY_PATH = os.getenv(
    "FERNET_KEY_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "data", "fernet.key"),
)

_lock = threading.Lock()
_fernet = None
_load_error: str | None = None

stats = {"decrypted": 0, "plaintext": 0, "undecryptable": 0}


def _load():
    """The agent telemetry key. Read only - never created here.

    A worker that generated its own would hold a key nothing was encrypted
    with, decrypt nothing, and look like it was working, so a missing key is
    reported rather than filled in.

    Not `FERNET_KEY` from `.env`, which protects server-side secrets. The two
    are easy to confuse and the failure is silent in both directions.
    """
    global _fernet, _load_error
    if _fernet is not None or _load_error is not None:
        return
    with _lock:
        if _fernet is not None or _load_error is not None:
            return
        try:
            from cryptography.fernet import Fernet
            with open(_KEY_PATH, "rb") as fh:
                _fernet = Fernet(fh.read().strip())
        except Exception as e:
            _load_error = (
                f"{type(e).__name__}: {e} (looked in {_KEY_PATH}). Agent "
                f"telemetry will be handled as ciphertext. This is not "
                f"FERNET_KEY from .env - it is data/fernet.key, which the "
                f"container needs the sentora_data volume to reach.")


def available() -> bool:
    _load()
    return _fernet is not None


def load_error() -> str | None:
    _load()
    return _load_error


def decrypt_value(value):
    """One field. Anything that is not `enc::...` comes back untouched."""
    if not isinstance(value, str) or not value.startswith(ENC_PREFIX):
        stats["plaintext"] += 1
        return value
    _load()
    if _fernet is None:
        stats["undecryptable"] += 1
        return value
    try:
        plain = _fernet.decrypt(value[len(ENC_PREFIX):].encode()).decode()
    except Exception:
        stats["undecryptable"] += 1
        return value

    # `enc_db._enc_value` json-encodes before encrypting. Skipping this layer
    # yields a JSON string containing JSON, and escaped quotes downstream.
    stats["decrypted"] += 1
    try:
        decoded = json.loads(plain)
        return decoded if isinstance(decoded, str) else plain
    except ValueError:
        return plain


def decrypt_item(table: str, item: dict) -> dict:
    """A plaintext **copy** of one row. The original is not modified.

    The caller still needs the ciphertext to store and forward; decrypting in
    place would write plaintext to the database.
    """
    fields = ENCRYPTED_FIELDS.get(table)
    if not fields or not isinstance(item, dict):
        return dict(item) if isinstance(item, dict) else item

    out = dict(item)
    for name in fields:
        if name in out:
            out[name] = decrypt_value(out[name])
    return out
