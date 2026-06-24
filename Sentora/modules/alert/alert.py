import os
import time
import json
import hashlib
import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict, deque

try:
    import modules.enc_db as enc_db
    enc_db.set_encrypt_fields_map({
        "siem_events": ["message"],
        "events_alert": ["source", "message"]
    })
    fetch_unsent_dec = enc_db.fetch_recent_dec
    insert_record_enc = enc_db.insert_record_enc
    mark_sent_enc     = enc_db.mark_sent_enc
    fetch_where_dec   = enc_db.fetch_where_dec
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    print("[!] WARNING: modules.enc_db not found. Running in mock mode.")
    def fetch_unsent_dec(table, limit=100): return []
    def insert_record_enc(table, data): print(f" [MOCK DB INSERT] {table}: {data}")
    def mark_sent_enc(table, ids): print(f" [MOCK DB MARK SENT] {ids}")
    def fetch_where_dec(table, where, params, limit): return []
    class enc_db:
        @staticmethod
        def set_encrypt_fields_map(m): pass


DEBUG_MODE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

MIN_ALERT_RANK = 2
FETCH_LIMIT = 500


@dataclass
class AlertContext:
    row_id: int
    timestamp: float
    source: str
    message: str
    event_type: str
    severity: str
    ip_address: Optional[str]
    user: Optional[str]
    raw_json: Dict
    threat_hits: int



FALSE_POSITIVE_PATTERNS = [
    r"System Idle Process",
    r"svchost\.exe",
    r"SearchIndexer\.exe",
    r"taskmgr\.exe"
]

def parse_siem_event(row) -> AlertContext:
    try:
        raw_msg = str(row.get("message", "{}"))
        if raw_msg.strip().startswith("{") and raw_msg.strip().endswith("}"):
            try:
                msg_json = json.loads(raw_msg)
            except:
                msg_json = {}
        else:
            msg_json = {}
        
        source = str(row.get("source", "Unknown"))
        msg_str = msg_json.get("message", raw_msg) if isinstance(msg_json, dict) else raw_msg
        
        severity = msg_json.get("severity", "MEDIUM") if isinstance(msg_json, dict) else "MEDIUM"
        event_type = msg_json.get("event_type", source) if isinstance(msg_json, dict) else source
        ip_addr = msg_json.get("ip_address", None) if isinstance(msg_json, dict) else None
        user = msg_json.get("user", None) if isinstance(msg_json, dict) else None
        threat_hits = int(msg_json.get("threat_hits", 0)) if isinstance(msg_json, dict) else 0

        ts_val = row.get("timestamp", time.time())
        
        return AlertContext(
            row_id=row["id"],
            timestamp=ts_val,
            source=source,
            message=msg_str,
            event_type=event_type,
            severity=severity,
            ip_address=ip_addr,
            user=user,
            raw_json=msg_json,
            threat_hits=threat_hits
        )
    except Exception as e:
        return AlertContext(
            row_id=row.get("id", 0),
            timestamp=time.time(),
            source="Error",
            message=str(row),
            event_type="ParsingError",
            severity="LOW",
            ip_address=None,
            user=None,
            raw_json={},
            threat_hits=0
        )

def get_rank(severity: str) -> int:
    s = str(severity).upper()
    if s == "CRITICAL": return 5
    if s == "HIGH": return 4
    if s == "MEDIUM": return 3
    if s == "LOW": return 2
    return 1

def calculate_risk(severity: str) -> int:
    rank = get_rank(severity)
    db = {5: 90, 4: 70, 3: 40, 2: 20, 1: 0}
    return db.get(rank, 0)

def make_alert_fingerprint(event_type: str, source: str, ip: str) -> str:
    s = f"{event_type}_{source}_{ip}"
    return hashlib.md5(s.encode()).hexdigest()

recent_alert_fps = deque(maxlen=5000)

def process_alerts() -> int:
    rows = fetch_unsent_dec("siem_events", limit=FETCH_LIMIT)
    
    if not rows:
        return 0

    if DEBUG_MODE:
        print(f"[DEBUG] Pulled {len(rows)} logs. Starting analysis...")

    alerts_to_insert = []
    processed_ids = []
    batch_dup_fps = set()

    stats = {"whitelisted": 0, "low_rank": 0, "duplicate": 0, "alerted": 0}

    for row in rows:
        ctx = parse_siem_event(row)
        
        is_whitelisted = False
        for fp_pattern in FALSE_POSITIVE_PATTERNS:
            if re.search(fp_pattern, ctx.message, re.IGNORECASE):
                is_whitelisted = True
                break
        
        if is_whitelisted:
            stats["whitelisted"] += 1
            processed_ids.append(ctx.row_id)
            continue

        rank = get_rank(ctx.severity)
        if rank < MIN_ALERT_RANK:
            stats["low_rank"] += 1
            processed_ids.append(ctx.row_id)
            if DEBUG_MODE:
                print(f"[SKIP] Rank too low ({ctx.severity}): {ctx.message[:50]}...")
            continue

        dup_fp = make_alert_fingerprint(ctx.event_type, ctx.source, ctx.ip_address)
        if dup_fp in batch_dup_fps or dup_fp in recent_alert_fps:
            stats["duplicate"] += 1
            processed_ids.append(ctx.row_id)
            continue
            
        batch_dup_fps.add(dup_fp)
        recent_alert_fps.append(dup_fp)

        stats["alerted"] += 1
        risk_score = calculate_risk(ctx.severity)
        
        if ctx.threat_hits >= 2:
            risk_score = 100
            ctx.severity = "CRITICAL"
            ctx.event_type = "COMPOUND_THREAT_DETECTED"

        enriched_msg = ctx.message
        prefixes = []
        if ctx.ip_address: prefixes.append(f"Src:{ctx.ip_address}")
        if ctx.user: prefixes.append(f"Usr:{ctx.user}")
        
        if prefixes:
            enriched_msg = f"[{' | '.join(prefixes)}] {ctx.message}"

        ts_val = ctx.timestamp
        try:
            parsed_ts = datetime.fromtimestamp(float(ts_val)).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            parsed_ts = str(ts_val)

        alert_record = {
            "source": ctx.source,
            "timestamp": parsed_ts,
            "severity": ctx.severity,
            "score": risk_score,
            "categories": ctx.event_type,
            "message": enriched_msg,
            "dup_fp": dup_fp
        }
        
        alerts_to_insert.append(alert_record)
        processed_ids.append(ctx.row_id)
        
        icon = "🔴" if risk_score >= 75 else "🟠" if risk_score >= 50 else "🔵"
        print(f"{icon} [ALARM] {ctx.severity} ({risk_score}) | {ctx.event_type} | {ctx.message[:100]}")

    if alerts_to_insert:
        count = 0
        for alert in alerts_to_insert:
            try:
                insert_record_enc("events_alert", alert)
                count += 1
            except Exception as e:
                if "unique constraint" in str(e).lower(): continue
                print(f"[ERROR] DB write error: {e}")

        print(f">> {count} alerts saved to DB.")

    if processed_ids:
        mark_sent_enc("siem_events", processed_ids)
        
    if DEBUG_MODE and len(rows) > 0:
        print(f"[SUMMARY] Total: {len(rows)} | Alerts: {stats['alerted']} | Whitelist: {stats['whitelisted']} | LowRank: {stats['low_rank']} | Dup: {stats['duplicate']}")

    return len(rows)

def main():
    logging.info(f"Hunter Mode Active. Min Rank: {MIN_ALERT_RANK} (CATCH-ALL)")
    
    try:
        while True:
            processed = process_alerts()
            sleep_time = 0.1 if processed > 0 else 2
            time.sleep(sleep_time)
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(f"Fatal Error: {e}", exc_info=True)
