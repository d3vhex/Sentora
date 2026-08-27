import asyncio
import struct
import os
import mysql.connector
import json
import hashlib
import re
import time
from datetime import datetime
from dotenv import load_dotenv
import pathlib

ENV_PATH = pathlib.Path(".env")
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)


debug = True


SERVER_IP = os.getenv('INGEST_BIND', '0.0.0.0')
SERVER_PORT = int(os.getenv('INGEST_PORT', '5001'))
BUFFER_SIZE = 16 * 1024

DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'my-secret-pw')
DB_PORT = int(os.getenv('DB_PORT', '3306'))

DEDUP_TABLES = {
    "critical_files", "portscan_result", "packages",
    "vulnerabilities_report", "siem_events", "events_alert", "soar_actions",
    "fim_data", "registry_logs", "network_connections", "process_events", "hardware_inventory", "security_audit", "docker_containers",
    "software_inventory", "network_inventory"
}

ALLOWED_TABLES = {
    "critical_files", "portscan_result", "resource_usage",
    "disk_usage", "packages", "vulnerabilities_report",
    "siem_events", "events_alert", "soar_actions",
    "fim_data", "registry_logs", "network_connections", "process_events", "hardware_inventory", "security_audit", "docker_containers",
    "software_inventory", "network_inventory"
}

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")

# RECENT_AI_TASKS / AI_DEDUP_WINDOW used to live here: a process-local dict
# with a 30-second window, wiped wholesale at 1000 entries. Deduplication
# therefore stopped working precisely when volume made it matter, divided by
# the Sanic worker count, and reset on every restart. Replaced by the
# database-backed counter in core/triage.py.

# asyncio holds only a *weak* reference to a running task, so a fire-and-forget
# `create_task` can be garbage collected before it finishes. On the ingest path
# that means telemetry silently not reaching the AI queue or the search index,
# with nothing anywhere to say it happened.
_background_tasks: set = set()


def _spawn(coro, *, label: str = "background"):
    """Fire-and-forget a coroutine while keeping it alive until it finishes."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    def _report(t: asyncio.Task):
        if not t.cancelled() and t.exception() is not None:
            print(f"[!] {label} task failed: {t.exception()}", flush=True)

    task.add_done_callback(_report)
    return task


def connect_db(db_name):
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        database=db_name,
    )

def _sanitize_db_name(agent: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9_]', '_', agent or 'agent')
    safe = safe.strip('_') or 'agent'
    return f"{safe}_db"

def create_agent_db_if_not_exists(agent: str) -> str:
    db_name = _sanitize_db_name(agent)
    conn = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT
    )
    cursor = conn.cursor()
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    return db_name

def _split_sql_statements(sql: str) -> list[str]:
    """Split a schema file into statements, with comment lines removed.

    Deliberately duplicated from the agent's `modules/db.py`: the agent ships
    as a standalone binary and cannot import from here. Both had the same
    trap, in different forms - see the note at the call site.
    """
    out: list[str] = []
    for chunk in sql.split(';'):
        body = "\n".join(
            line for line in chunk.splitlines()
            if not line.strip().startswith("--")
        ).strip()
        if body:
            out.append(body)
    return out


AUTOMATION_STATUSES = ("pending", "active", "paused", "completed", "failed", "cancelled")


def _migrate_automation_status(cursor, db_name: str) -> None:
    """Widen `automations.status` to include 'cancelled', at most once.

    Kept out of init.sql and guarded, because that file is re-executed on
    every call to create_tables_if_not_exist. An unconditional
    `ALTER TABLE ... MODIFY` there took a metadata lock on `automations` each
    time; with one leaked connection holding an open transaction on the table,
    the ALTER queued behind it - and a *waiting* DDL in MySQL blocks every
    reader that arrives after it, not just writers.

    The result was total: agents polling /automations/pending got no answer
    at all, and a 500 ten seconds later when Sanic gave up. Killing the
    blocked ALTER did not help, because the next call re-issued it.

    Reading information_schema costs nothing and takes no lock, so the normal
    path - the column is already correct - never touches the table.
    """
    cursor.execute(
        "SELECT column_type FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = 'automations' "
        "AND column_name = 'status'",
        (db_name,),
    )
    row = cursor.fetchone()
    if not row:
        return                      # no table yet; init.sql creates it correct
    if "cancelled" in str(row[0]):
        return                      # already migrated

    values = ",".join(f"'{v}'" for v in AUTOMATION_STATUSES)
    try:
        # Never wait on a metadata lock. If the table is busy, skipping is
        # correct: the next start tries again, and blocking here would take
        # the polling endpoints down with it.
        cursor.execute("SET SESSION lock_wait_timeout = 3")
        cursor.execute(
            f"ALTER TABLE automations "
            f"MODIFY status ENUM({values}) NOT NULL DEFAULT 'pending'"
        )
        print(f"[+] {db_name}: automations.status widened to include 'cancelled'")
    except mysql.connector.Error as e:
        print(f"[!] {db_name}: could not widen automations.status ({e}); "
              f"will retry on the next start")


# One engine for the whole fleet, built once. The per-host engine lives in the
# agent (core.correlation.default_engine); this one only sees shapes that
# span machines, which no agent can.
#
# Optional on purpose: a broken import here must not stop ingestion. Losing
# correlation costs detections, and refusing to accept telemetry costs all of
# them.
try:
    from core import telemetry_crypto
    from core.correlation import fleet_engine
    from core.sigma_loader import agent_event_fields
    _FLEET = fleet_engine()
except Exception as _corr_err:                        # pragma: no cover
    print(f"[Correlation] disabled: {_corr_err}", flush=True)
    _FLEET = None
    agent_event_fields = None


def correlate_across_hosts(agent, table, item, cursor):
    """Feed one stored event to the fleet engine; store whatever fired.

    A fired window becomes an `events_alert` row rather than a label on the
    event that completed it. It is a finding about the estate, and the fifth
    failed logon is no more interesting than the first.

    Returns the rows it wrote so the caller can put them through the AI queue.
    They have to go: `events_alert` normally reaches the workers because the
    ingest loop publishes what it inserts, and rows written from inside that
    loop are not items the loop iterates. Without this a correlation finding
    lands in the database, appears in the alerts view, and never becomes an AI
    insight - which was the state that made the model look blind to password
    spray when the platform had in fact detected it.

    Failures are contained: this runs inside the ingest transaction, and a
    correlation bug must cost a detection rather than the telemetry.
    """
    if _FLEET is None or table != "siem_events":
        return []

    written = []
    try:
        # Decrypted here and nowhere else: the row written to the database
        # and the message published to the broker both stay encrypted. A
        # correlation window counting ciphertext counts nothing, because
        # Fernet's random IV makes every encryption of the same text different.
        plain = telemetry_crypto.decrypt_item(table, item)
        fields = agent_event_fields(plain.get("message") or "")
        fields["agent"] = agent
        for found in _FLEET.observe(fields):
            # `dup_fp` comes from the detection's own sequence, not a hash of
            # the text. Two firings of the same window say the same words, so
            # a content hash would let the existing dedup swallow the second
            # as a repeat - the opposite of what a spray resuming after its
            # cooldown should do.
            row = {
                "source": f"Correlation/{found.rule}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": found.severity,
                "categories": ",".join(found.techniques),
                "message": found.summary(),
                "dup_fp": hashlib.sha256(
                    f"{found.rule}|{found.group}|{found.seq}".encode()
                ).hexdigest(),
            }
            cursor.execute(
                "INSERT INTO events_alert "
                "(source, `timestamp`, severity, categories, message, dup_fp) "
                "VALUES (%(source)s, %(timestamp)s, %(severity)s, "
                "%(categories)s, %(message)s, %(dup_fp)s)", row)
            written.append(row)
            print(f"[Correlation] {found.title}: {found.detail}", flush=True)
    except Exception as e:
        print(f"[Correlation] failed for {agent}/{table}: {e}", flush=True)
    return written


def create_tables_if_not_exist(db_name):
    conn = connect_db(db_name)
    cursor = conn.cursor()
    try:
        # Resolved against this file, not the working directory. It used to be
        # a bare relative "init.sql" whose FileNotFoundError was swallowed, so
        # running the server from anywhere but the repo root created no tables
        # at all and said nothing about it.
        schema_path = pathlib.Path(__file__).resolve().parent / "db" / "init.sql"
        try:
            sql = schema_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Loud: every agent table comes from this file.
            print(f"[!] Schema {schema_path} is missing — agent tables will not "
                  f"be created. This is not recoverable at runtime.")
            sql = ""
        # Comment lines are stripped rather than the chunk being skipped when
        # it starts with one. Splitting on ';' leaves a statement's leading
        # comment attached to it, so "skip chunks beginning with --" silently
        # discards every documented statement - that bug cost 19 of 52
        # statements in the agent's copy of this loop. Here the risk was the
        # milder one: a chunk that is only a comment was sent to MySQL and
        # produced a syntax error on every startup.
        for statement in _split_sql_statements(sql):
            try:
                cursor.execute(statement)
            except mysql.connector.Error as e:
                print(f"[!] SQL Execution Error: {e}")

        # Guarded, and after the CREATEs so the table exists on a fresh DB.
        try:
            _migrate_automation_status(cursor, db_name)
        except mysql.connector.Error as e:
            print(f"[!] automations.status migration skipped: {e}")

        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_info (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    agent_name VARCHAR(255) NOT NULL,
                    public_ip VARCHAR(45),
                    os_info VARCHAR(255) NULL,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_agent (agent_name)
                ) ENGINE=InnoDB
            """)
            try:
                cursor.execute("ALTER TABLE agent_info ADD COLUMN IF NOT EXISTS os_info VARCHAR(255) NULL")
            except mysql.connector.Error:
                pass
        except mysql.connector.Error as e:
            print(f"[!] Agent info table creation/alter error: {e}")

        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ingest_fingerprint (
                    table_name VARCHAR(64) NOT NULL,
                    fp CHAR(64) NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (table_name, fp)
                ) ENGINE=InnoDB
            """)
        except mysql.connector.Error as e:
            print(f"[!] Fingerprint table creation error: {e}")

        conn.commit()
    finally:
        cursor.close()
        conn.close()

def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)

def compute_fingerprint(table: str, item: dict) -> str:
    clean = {k: v for k, v in item.items() if k not in ("id", "sent")}
    blob = json.dumps(clean, sort_keys=True, separators=(",", ":"), default=_json_default).encode("utf-8")
    return hashlib.sha256(table.encode() + b"|" + blob).hexdigest()

# Defined in core/triage.py so the defensive sweep in app.py computes exactly
# the same value - see the note there.
from core.triage import compute_ai_fingerprint  # noqa: E402,F401

def update_agent_info(agent: str, public_ip: str, os_info: str = None, hostname: str = None,
                      mac_address: str = None, reported_ip: str = None):
    """Record where this agent is, from both vantage points.

    `public_ip` is what we observed the connection coming from; `reported_ip`
    is what the agent worked out about itself. They are usually the same, and
    where they differ neither one is simply right:

      - Cloud VM behind NAT: the agent sees 172.31.x, we see the elastic IP.
        Ours is the one worth showing an operator.
      - Server in Docker on the same machine as the agent: the connection
        arrives from the bridge gateway (172.18.0.1), which is a *router*, not
        the agent. Calling back to it reaches nothing - the agent's own
        address is the only usable one.

    Overwriting one with the other threw away the address that worked, and
    server->agent features (VNC, SOAR dispatch) failed with `Connection
    refused` against an IP that never had a listener on it. Both are kept so
    the caller can try them in order instead of us guessing here.
    """
    db_name = create_agent_db_if_not_exists(agent)
    create_tables_if_not_exist(db_name)
    conn = connect_db(db_name)
    cursor = conn.cursor()
    try:
        for col, ddl in (
            ("hostname", "ALTER TABLE agent_info ADD COLUMN hostname VARCHAR(255) NULL"),
            ("mac_address", "ALTER TABLE agent_info ADD COLUMN mac_address VARCHAR(48) NULL"),
            ("reported_ip", "ALTER TABLE agent_info ADD COLUMN reported_ip VARCHAR(45) NULL"),
        ):
            try:
                cursor.execute(ddl)
            except Exception:
                pass
        cursor.execute("""
            INSERT INTO agent_info (agent_name, public_ip, reported_ip, os_info, hostname, mac_address, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            public_ip = VALUES(public_ip),
            reported_ip = COALESCE(VALUES(reported_ip), reported_ip),
            os_info = VALUES(os_info),
            hostname = COALESCE(VALUES(hostname), hostname),
            mac_address = COALESCE(VALUES(mac_address), mac_address),
            last_seen = VALUES(last_seen)
        """, (agent, public_ip, reported_ip, os_info, hostname, mac_address, datetime.now()))
        conn.commit()
    except Exception as e:
        print(f"! Error updating agent info: {e}")
    finally:
        cursor.close()
        conn.close()

from core import mq as mq_utils
from core import triage
import core.opensearch as os_utils

async def publish_to_ai_queue(agent: str, table: str, item: dict):
    """Publish a log entry to RabbitMQ for both automation and defensive (SOAR) analysis"""
    await mq_utils.publish_to_queue(mq_utils.AI_AUTOMATION, agent, table, item)

    if table == "events_alert":
        await mq_utils.publish_to_queue(mq_utils.AI_SOAR, agent, table, item)
        print(f"[AI-Trigger] Published {table} task for {agent} to SOAR (Defensive) queue.")

def _parse_os_info_tail(os_info: str | None):
    """Agent appends |HOST=<hostname>|MAC=<addr> to OS_INFO so the server
    can recover the real machine identifiers without changing the TCP
    wire format. Returns (clean_os_info, hostname, mac_address)."""
    if not os_info or "|" not in os_info:
        return os_info, None, None
    parts = os_info.split("|")
    base = parts[0]
    hostname = mac = None
    for p in parts[1:]:
        if p.startswith("HOST="):
            hostname = p[5:].strip() or None
        elif p.startswith("MAC="):
            mac = p[4:].strip() or None
    return base, hostname, mac


async def insert_data(agent: str, table: str, data: list, public_ip: str = None, os_info: str = None,
                      reported_ip: str = None):
    db_name = create_agent_db_if_not_exists(agent)
    create_tables_if_not_exist(db_name)

    clean_os, hostname, mac_address = _parse_os_info_tail(os_info)
    if public_ip or clean_os:
        update_agent_info(agent, public_ip, clean_os, hostname=hostname,
                          mac_address=mac_address, reported_ip=reported_ip)

    conn = connect_db(db_name)
    cursor = conn.cursor()
    try:
        if table not in ALLOWED_TABLES:
            print(f"[!] Unknown table '{table}' received. Skipping.")
            return

        if table in {"resource_usage", "disk_usage", "critical_files", "network_connections", "hardware_inventory", "docker_containers"}:
            cursor.execute(f"DELETE FROM `{table}`")

        for item in data:
            item = dict(item)
            item.pop("id", None)
            item["sent"] = False

            if table in DEDUP_TABLES:
                fp = compute_fingerprint(table, item)
                cursor.execute(
                    "INSERT IGNORE INTO ingest_fingerprint (table_name, fp) VALUES (%s, %s)",
                    (table, fp)
                )
                if cursor.rowcount == 0:
                    continue

            keys = ', '.join(f"`{k}`" for k in item.keys())
            values = ', '.join(['%s'] * len(item))
            sql = f"INSERT INTO `{table}` ({keys}) VALUES ({values})"
            cursor.execute(sql, list(item.values()))

            for _alert in correlate_across_hosts(agent, table, item, cursor):
                _spawn(publish_to_ai_queue(agent, "events_alert", _alert),
                       label=f"ai-publish {agent}/correlation")

            if table in {"siem_events", "events_alert"}:
                # Gate 1 — severity floor. Cheap, and happens before anything
                # touches the dedup table.
                send, why = triage.passes_severity(item)
                if not send:
                    # Recorded in the agent's database, not a module counter:
                    # this process is not the one that serves the stats
                    # endpoint, so an in-memory tally would always read zero
                    # there — an answer-shaped number measuring nothing.
                    triage.record_drop(cursor, item.get("severity") or item.get("level") or "UNKNOWN")
                    if debug:
                        print(f"[Triage] skipped {agent}/{table}: {why}")
                else:
                    # Gate 2 — deduplication, counted in the database so it
                    # survives restarts and is shared across Sanic workers.
                    ai_fp = compute_ai_fingerprint(table, item)
                    try:
                        cursor.execute(triage.DEDUP_DDL)
                        is_new, seen = triage.record_occurrence(cursor, table, ai_fp)
                    except Exception as dedup_err:
                        # Fail open: a broken counter must not stop analysis.
                        if debug:
                            print(f"[Triage] dedup unavailable ({dedup_err}), analysing anyway")
                        is_new, seen = True, 1

                    if is_new:
                        # This is the whole AI pipeline's entry point. The task
                        # was previously assigned to a local that went out of
                        # scope immediately, leaving only asyncio's weak
                        # reference — so an event could be dropped before it
                        # ever reached the queue, while the log line below
                        # claimed it had been sent.
                        item["_ai_fingerprint"] = ai_fp
                        _spawn(publish_to_ai_queue(agent, table, item),
                               label=f"ai-publish {agent}/{table}")
                    elif debug:
                        print(f"[Triage] duplicate {agent}/{table} (x{seen}), "
                              f"attached to the existing verdict")

            _spawn(os_utils.index_log(agent, table, item),
                   label=f"index {agent}/{table}")

        conn.commit()
    except Exception as e:
        if debug:
            print(f"[!] Data insertion error: {e}")
    finally:
        cursor.close()
        conn.close()


async def recv_all(reader, length):
    data = b''
    while len(data) < length:
        more = await reader.read(length - len(data))
        if not more:
            raise EOFError(f"Expected {length} bytes but received {len(data)} bytes.")
        data += more
    return data


def observed_peer_ip(writer) -> str | None:
    """The address this connection actually came from, when it tells us more
    than the agent already did.

    Returns None when the peer is loopback or link-local, because that means
    the agent is on this host or reaching us through something local, and its
    own idea of its address is the better one.

    Private ranges are *kept*. On a flat corporate LAN 10.x is the real
    address of the machine and there is nothing more public to have; the case
    this exists for is a cloud VM, where the agent sees 172.31.x and the
    server sees the elastic IP.
    """
    try:
        peer = writer.get_extra_info("peername")
    except Exception:
        return None
    if not peer:
        return None

    host = peer[0] if isinstance(peer, (tuple, list)) else str(peer)
    if not host:
        return None

    # IPv4-mapped IPv6, which is what a dual-stack listener reports.
    if host.startswith("::ffff:"):
        host = host[len("::ffff:"):]

    try:
        import ipaddress
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return None
    return host


async def handle_client(reader, writer):
    try:
        raw_len = await recv_all(reader, 4)
        (agent_name_len,) = struct.unpack('!I', raw_len)
        agent_name = (await recv_all(reader, agent_name_len)).decode('utf-8')

        raw_ip_len = await recv_all(reader, 4)
        (ip_len,) = struct.unpack('!I', raw_ip_len)
        claimed_ip = (await recv_all(reader, ip_len)).decode('utf-8')

        # What we observed beats what we were told.
        #
        # The agent works its own address out from a UDP route lookup, which
        # is the right thing to do - it contacts nothing and works air-gapped.
        # On a cloud VM behind NAT it returns the private address: an EC2 host
        # reported 172.31.42.49 while the world saw 16.171.42.197, and the
        # console labelled the private one "Primary IP".
        #
        # The peer address of an established TCP connection is the one thing
        # here that cannot be wrong, and cannot be forged by the agent either.
        public_ip = observed_peer_ip(writer) or claimed_ip

        raw_os_len = await recv_all(reader, 4)
        (os_len,) = struct.unpack('!I', raw_os_len)
        os_info = (await recv_all(reader, os_len)).decode('utf-8')

        raw_fname_len = await recv_all(reader, 4)
        (fname_len,) = struct.unpack('!I', raw_fname_len)
        fname = (await recv_all(reader, fname_len)).decode('utf-8')

        raw_fsize = await recv_all(reader, 8)
        (fsize,) = struct.unpack('!Q', raw_fsize)

        data_bytes = await recv_all(reader, fsize)
        try:
            data = json.loads(data_bytes.decode('utf-8'))
        except Exception as e:
            if debug:
                print(f"[ERROR] JSON decode failed from {agent_name}@{public_ip}: {e}")
                return

        await insert_data(agent_name, fname.replace(".json", ""), data, public_ip, os_info,
                          reported_ip=claimed_ip)
        if debug:
            print(f"[INFO] Data received from {agent_name}@{public_ip} ({os_info}) - File: {fname}, Size: {fsize} bytes")

    except Exception as e:
        if debug:
            print(f"[ERROR] Client handling failed: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    server = await asyncio.start_server(
        handle_client, SERVER_IP, SERVER_PORT,
        reuse_address=True, reuse_port=False
    )
    addr = server.sockets[0].getsockname()
    print(f"[*] TCP ingest server listening on: {addr}")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
