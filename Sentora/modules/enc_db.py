from __future__ import annotations

import os
import json
import time
import threading
from typing import Dict, Any, List, Optional, Union
from cryptography.fernet import Fernet, InvalidToken

import modules.db as _db


FERNET_REFRESH_SEC: int = int(os.getenv("FERNET_REFRESH_SEC", "600"))

ENCRYPT_FIELDS_MAP: Dict[str, List[str]] = {
    "fim_data": ["path", "hash_sha256"],
    "registry_logs": ["hive", "key_path", "value_name", "value_data"],
    "network_connections": ["process_name", "local_addr", "remote_addr"],
    "process_events": ["name", "cmdline", "username"],
    "hardware_inventory": ["name", "serial_number"],
    "security_audit": ["finding", "details"]
}

_LOCK = threading.RLock()
__FERNET_OBJ: Optional[Fernet] = None
__FERNET_TS: float = 0.0
__FERNET_KEY_STR: Optional[str] = None

ENC_PREFIX = "enc::"


def set_agent_config(
    refresh_sec: Optional[int] = None,
    **_legacy_kwargs,
) -> None:
    """Configure refresh cadence. Extra keyword args are silently
    ignored so older callers don't break."""
    global FERNET_REFRESH_SEC
    if refresh_sec is not None:
        FERNET_REFRESH_SEC = max(60, int(refresh_sec))


def set_encrypt_fields_map(mapping: Dict[str, List[str]], *, merge: bool = False) -> None:
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


def has_key() -> bool:
    with _LOCK:
        return __FERNET_OBJ is not None


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


def encrypt_str(plaintext: str) -> str:
    f = _get_fernet()
    token = f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return ENC_PREFIX + token


def decrypt_maybe(val: Union[str, bytes]) -> str:
    if isinstance(val, bytes):
        try:
            val = val.decode("utf-8")
        except Exception:
            return val.decode("utf-8", errors="ignore")

    if not isinstance(val, str):
        return str(val)

    if not val.startswith(ENC_PREFIX):
        return val

    token = val[len(ENC_PREFIX):].encode("utf-8")
    try:
        pt = _get_fernet().decrypt(token)
        return pt.decode("utf-8")
    except InvalidToken:
        return val


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


def insert_record_enc(table: str, data: dict):
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
