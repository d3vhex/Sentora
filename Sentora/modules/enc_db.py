from __future__ import annotations

import os
import json
import time
import threading
from typing import Dict, Any, List, Optional, Union
from cryptography.fernet import Fernet, InvalidToken

import modules.db as _db


FERNET_REFRESH_SEC: int = int(os.getenv("FERNET_REFRESH_SEC", "600"))

# The single source of truth for what the agent encrypts at rest.
#
# This used to hold six tables that individual modules then REPLACED at import
# time, because set_encrypt_fields_map defaulted to overwrite. The effective
# map therefore depended on import order, and check_permissions called it from
# inside its periodic scan — so after the first permission scan the map was cut
# down to `critical_files` alone and every other table started writing
# plaintext. That is why some events_alert rows carry `enc::` and others do
# not.
#
# Every table lives here now. Modules must not replace it; they may add to it
# with add_encrypted_fields().
#
# Adding a field here is not free: encrypted columns cannot be used in a WHERE
# clause or an index. `siem_events.source` is deliberately left in the clear
# for that reason — init.sql indexes it.
ENCRYPT_FIELDS_MAP: Dict[str, List[str]] = {
    "fim_data": ["path", "hash_sha256"],
    "registry_logs": ["hive", "key_path", "value_name", "value_data"],
    "network_connections": ["process_name", "local_addr", "remote_addr"],
    "process_events": ["name", "cmdline", "username"],
    "hardware_inventory": ["name", "serial_number"],
    "security_audit": ["finding", "details"],
    "siem_events": ["message"],
    "events_alert": ["source", "message"],
    "critical_files": ["path", "owner", "grp", "permissions", "last_opened"],
}

_LOCK = threading.RLock()
__FERNET_OBJ: Optional[Fernet] = None
__FERNET_TS: float = 0.0
__FERNET_KEY_STR: Optional[str] = None

ENC_PREFIX = "enc::"


def set_encrypt_fields_map(mapping: Dict[str, List[str]], *, merge: bool = True) -> None:
    """Register fields to encrypt at rest.

    `merge` defaults to True. It used to default to False, which meant any
    module calling this wiped every table another module had registered — and
    four modules did, one of them from inside a periodic scan. The result was
    that most telemetry silently stopped being encrypted after the agent had
    been running for a few minutes.

    Passing merge=False is still possible but should be reserved for tests;
    nothing in the agent has a reason to discard another module's fields.
    """
    global ENCRYPT_FIELDS_MAP
    if not merge:
        ENCRYPT_FIELDS_MAP = {k: list(dict.fromkeys(v)) for k, v in (mapping or {}).items()}
        return

    for table, fields in (mapping or {}).items():
        cur = ENCRYPT_FIELDS_MAP.get(table, [])
        ENCRYPT_FIELDS_MAP[table] = list(dict.fromkeys(cur + list(fields or [])))


def add_encrypted_fields(table: str, fields: List[str]) -> None:
    set_encrypt_fields_map({table: fields}, merge=True)


def set_fernet_key(key: Union[str, bytes]) -> None:
    """Inject a Fernet key. The agent receives it from the main server's
    /api/agents/bootstrap endpoint and pushes it here."""
    global __FERNET_OBJ, __FERNET_TS, __FERNET_KEY_STR
    if isinstance(key, bytes):
        key_bytes = key
        key_str = key.decode("utf-8")
    else:
        key_str = key
        key_bytes = key.encode("utf-8")

    cipher = Fernet(key_bytes)
    with _LOCK:
        __FERNET_OBJ = cipher
        __FERNET_TS = time.time()
        __FERNET_KEY_STR = key_str


def get_fernet_key() -> Optional[str]:
    with _LOCK:
        return __FERNET_KEY_STR


class ConfigError(RuntimeError):
    pass


def _get_fernet() -> Fernet:
    """Return the cached Fernet cipher. The agent must call set_fernet_key()
    at startup (via the server bootstrap) before any encrypted IO is
    attempted."""
    with _LOCK:
        if __FERNET_OBJ is None:
            raise ConfigError(
                "Fernet key not initialised. Call set_fernet_key() with the "
                "value returned by the server's /api/agents/bootstrap endpoint."
            )
        return __FERNET_OBJ


def _should_encrypt(table: str, field: str) -> bool:
    fields = ENCRYPT_FIELDS_MAP.get(table) or []
    return field in fields


def _enc_value(v: Any) -> str:
    f = _get_fernet()
    payload = json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ct = f.encrypt(payload).decode("utf-8")
    return ENC_PREFIX + ct


def _dec_value(v: Any) -> Any:
    if not isinstance(v, str) or not v.startswith(ENC_PREFIX):
        return v
    token = v[len(ENC_PREFIX):].encode("utf-8")
    try:
        pt = _get_fernet().decrypt(token)
        return json.loads(pt.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError):
        return v


def _encrypt_row(table: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (_enc_value(v) if _should_encrypt(table, k) else v) for k, v in data.items()}


def _decrypt_row(table: str, row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (_dec_value(v) if _should_encrypt(table, k) else v) for k, v in row.items()}


def _decrypt_rows(table: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_decrypt_row(table, r) for r in rows]


# Fields that vary between two sightings of the same event, or that the
# server adds on the way in. Mirrors core/triage.FINGERPRINT_IGNORE.
FINGERPRINT_IGNORE = {
    "id", "sent", "dup_fp", "created_at", "ai_analyzed", "ai_analyzed_at",
    "timestamp", "@timestamp", "TimeGenerated", "time",
    "PID", "ProcessID", "process_id",
}

# Tables the server deduplicates before spending an inference on them.
FINGERPRINTED_TABLES = ("siem_events", "events_alert")


def content_fingerprint(table: str, data: dict) -> str:
    """A stable hash of an event's content, computed before encryption.

    This has to happen here, on the agent, because **the server cannot do it.**

    The server used to fingerprint the row it received, but `source` and
    `message` arrive as `enc::gAAAA...`. Fernet uses a random IV and embeds a
    timestamp, so encrypting the same plaintext twice produces different
    ciphertext - and the fingerprint of an encrypted row is therefore unique
    by construction. Deduplication was structurally incapable of matching
    anything: 517 fingerprints, every one seen exactly once, over a night in
    which the same two alerts repeated hundreds of times.

    Giving the server the decryption key would have fixed it too, at the cost
    of widening what a compromise of the ingest service yields. The party that
    already holds the plaintext is the right one to hash it.

    Written into `dup_fp`, which is not an encrypted column, so the server can
    read it without a key.
    """
    import hashlib

    payload = {k: v for k, v in data.items() if k not in FINGERPRINT_IGNORE}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{table}|{blob}".encode("utf-8")).hexdigest()


def insert_record_enc(table: str, data: dict):
    # Only when the producer has not set one. Several modules compute a
    # narrower dup_fp of their own for local deduplication (alert.py hashes
    # event type, source and IP), and those are also plaintext-derived and
    # stable, so they serve equally well. Overwriting them would break the
    # local dedup that depends on their exact semantics.
    if table in FINGERPRINTED_TABLES and not data.get("dup_fp"):
        data = dict(data, dup_fp=content_fingerprint(table, data))
    return _db.insert_record(table, _encrypt_row(table, data))


def delete_all_enc(table: str):
    return _db.delete_all(table)


def fetch_unsent_dec(table: str, limit: int = 100):
    rows = _db.fetch_unsent(table, limit)
    return _decrypt_rows(table, [dict(r) for r in rows])


def mark_sent_enc(table: str, ids: list):
    return _db.mark_sent(table, ids)


def fetch_one_dec(table: str, where: str = "1=1", params: tuple = (), order_by: Optional[str] = None):
    row = _db.fetch_one(table, where, params, order_by)
    return _decrypt_row(table, dict(row)) if row else None


def fetch_recent_dec(table: str, limit: int = 100):
    rows = _db.fetch_recent(table, limit)
    return _decrypt_rows(table, [dict(r) for r in rows])


def fetch_where_dec(
    table: str,
    where: str = "1=1",
    params: tuple = (),
    order_by: Optional[str] = None,
    limit: Optional[int] = None,
):
    rows = _db.fetch_where(table, where, params, order_by, limit)
    return _decrypt_rows(table, [dict(r) for r in rows])


def update_record_enc(table: str, data: dict, where: str, params: tuple = ()):
    return _db.update_record(table, _encrypt_row(table, data), where, params)
