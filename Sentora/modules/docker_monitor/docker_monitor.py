import threading
import logging
import json
import time
from datetime import datetime
import hashlib
import os

try:
    import docker
except ImportError:
    docker = None

import modules.enc_db as enc_db
import modules.db as _db

enc_db.set_encrypt_fields_map({
    "siem_events": ["message"]
})

insert_record_enc = enc_db.insert_record_enc

logger = logging.getLogger("docker_monitor")

_DOCKER_CONTAINERS_DDL = """
CREATE TABLE IF NOT EXISTS docker_containers (
    id           SERIAL PRIMARY KEY,
    container_id TEXT,
    name         TEXT,
    image        TEXT,
    status       TEXT,
    state        TEXT,
    created_at   TEXT,
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);
"""

_table_ensured = False
_table_lock = threading.Lock()


def _ensure_table():
    """Idempotently create docker_containers if missing. Existing agent DBs
    were initialised before this table was added to init.sql, and PostgreSQL
    only runs init scripts on first volume init."""
    global _table_ensured
    if _table_ensured:
        return
    with _table_lock:
        if _table_ensured:
            return
        try:
            with _db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(_DOCKER_CONTAINERS_DDL)
                conn.commit()
            _table_ensured = True
            logger.info("[+] docker_containers table ensured.")
        except Exception as e:
            logger.error(f"Failed to ensure docker_containers table: {e}")


def make_dup_fp(message: str) -> str:
    """Generate a unique fingerprint for the event to avoid duplicate inserts."""
    return hashlib.md5(message.encode('utf-8')).hexdigest()

def is_duplicate(dup_fp: str) -> bool:
    res = enc_db.fetch_where_dec("siem_events", "dup_fp = ?", (dup_fp,))
    return len(res) > 0

def format_event(event: dict) -> str:
    """Format a Docker event into a SIEM-like log line."""
    action = event.get('Action', 'unknown')
    type_ = event.get('Type', 'unknown')
    actor = event.get('Actor', {})
    attrs = actor.get('Attributes', {})

    name = attrs.get('name', actor.get('ID', 'unknown')[:12])
    image = attrs.get('image', 'unknown')

    msg = f"docker event: {action} type={type_} container={name} image={image}"

    if action in ('exec_create', 'exec_start'):
        exec_id = attrs.get('execID', '')
        msg += f" exec_id={exec_id}"

    if action == 'die':
        exit_code = attrs.get('exitCode', 'unknown')
        msg += f" exit_code={exit_code}"

    return msg

def collect_container_inventory(client):
    """Fetch current list of containers and update the docker_containers table."""
    _ensure_table()
    try:
        containers = client.containers.list(all=True)
        for c in containers:
            try:
                state_str = (c.attrs.get('State') or {}).get('Status', '') or c.status
                item = {
                    'container_id': c.id,
                    'name': c.name,
                    'image': c.image.tags[0] if c.image.tags else c.image.id,
                    'status': c.status,
                    'state': str(state_str)[:64],
                    'created_at': c.attrs.get('Created', ''),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                }
                item['dup_fp'] = make_dup_fp(f"{item['container_id']}-{item['status']}-{item['timestamp']}")
                insert_record_enc('docker_containers', item)
            except Exception as e:
                logger.error(f"Error inserting container inventory: {e}")
    except Exception as e:
        logger.error(f"Failed to collect docker inventory: {e}")


def _inventory_loop(client, stop_evt, interval=60):
    """Runs container inventory snapshots on a fixed cadence in its own thread,
    so the events loop never has to break out of the streaming generator."""
    while not stop_evt.is_set():
        try:
            collect_container_inventory(client)
        except Exception as e:
            logger.error(f"Inventory loop error: {e}")
        stop_evt.wait(interval)


def monitor_docker_events():
    if not docker:
        logger.warning("[!] Docker module not installed. Docker monitoring disabled.")
        return

    while True:
        client = None
        stop_evt = threading.Event()
        inv_thread = None
        try:
            client = docker.from_env()
            client.ping()
            logger.info("[+] Docker monitor connected to Docker daemon.")

            collect_container_inventory(client)
            inv_thread = threading.Thread(
                target=_inventory_loop,
                args=(client, stop_evt),
                kwargs={'interval': 60},
                name="DockerInventoryThread",
                daemon=True,
            )
            inv_thread.start()

            for event in client.events(decode=True):
                type_ = event.get('Type')
                action = event.get('Action')

                if type_ == 'container' and action in (
                    'create', 'start', 'stop', 'kill', 'die',
                    'pause', 'unpause', 'exec_create', 'exec_start', 'oom',
                ):
                    msg = format_event(event)
                    dup_fp = make_dup_fp(msg + str(event.get('time', time.time())))
                    timestamp = datetime.fromtimestamp(
                        event.get('time', time.time())
                    ).strftime('%Y-%m-%d %H:%M:%S')

                    try:
                        insert_record_enc('siem_events', {
                            'timestamp': timestamp,
                            'message': msg,
                            'source': 'DockerMonitor',
                            'dup_fp': dup_fp,
                        })
                    except Exception as db_err:
                        logger.error(f"Error inserting docker event to DB: {db_err}")

                    if action in ('create', 'start', 'stop', 'kill', 'die'):
                        try:
                            collect_container_inventory(client)
                        except Exception as e:
                            logger.error(f"Immediate inventory refresh failed: {e}")

        except docker.errors.APIError as e:
            logger.error(f"Docker API error: {e}")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Docker monitor loop error: {e}. Reconnecting in 10s...")
            time.sleep(10)
        finally:
            stop_evt.set()
            if inv_thread is not None:
                inv_thread.join(timeout=5)
            try:
                if client is not None:
                    client.close()
            except Exception:
                pass

def start_docker_monitor_thread():
    t = threading.Thread(target=monitor_docker_events, name="DockerMonitorThread", daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_docker_monitor_thread().join()
