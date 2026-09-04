import socket
import ssl
import struct
import time
import asyncio
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
import subprocess
import os
import signal
import requests
import sys
import platform
import re
from datetime import datetime, timedelta
import ipaddress

from modules.db import insert_record, fetch_unsent, mark_sent, fetch_one
import modules.enc_db as enc_db
import modules.screen_capture as screen_capture
import modules.agent_paths as agent_paths
import modules.console as console
import modules.link as link
import modules.telemetry_health as telemetry_health

import logging
import builtins
import traceback

if getattr(sys, "frozen", False):
    AGENT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_LOG_PATH = os.path.join(AGENT_DIR, "agent.log")

for h in logging.root.handlers[:]: logging.root.removeHandler(h)
_log_fmt = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
try:
    # Rotating, not append-forever. A plain FileHandler in mode="a" took
    # agent.log to 55 MB on an endpoint that had been running for a few weeks:
    # about 5 MB a day, on a machine the agent is supposed to be unobtrusive
    # on, and nothing ever reclaimed it.
    #
    # 5 MB x 3 caps the total at 20 MB including the live file. That is enough
    # to cover roughly the last four days at the current rate, which is the
    # window anyone actually reads back when diagnosing something.
    from logging.handlers import RotatingFileHandler
    fh = RotatingFileHandler(
        AGENT_LOG_PATH,
        maxBytes=int(os.getenv("AGENT_LOG_MAX_BYTES", str(5 * 1024 * 1024))),
        backupCount=int(os.getenv("AGENT_LOG_BACKUPS", "3")),
        encoding="utf-8",
    )
    fh.setFormatter(_log_fmt)
    logging.root.addHandler(fh)
except Exception as _log_err:
    sys.stderr.write(f"[agent] could not open log file {AGENT_LOG_PATH}: {_log_err}\n")
sh = logging.StreamHandler(sys.stderr)
sh.setFormatter(_log_fmt)
logging.root.addHandler(sh)
logging.root.setLevel(logging.INFO)
logging.root.propagate = False

original_print = builtins.print

def trapped_print(*args, **kwargs):
    """Route every print() through the logging stack so the message lands
    in both stderr and agent.log. Without this, prints from main.py go
    to stdout/stderr which the Windows Scheduled Task does not capture,
    making the agent appear silent in its own log file."""
    stack = traceback.extract_stack()
    tag = ""
    for frame in reversed(stack[:-1]):
        fname = frame.filename.replace("\\", "/")
        if "/modules/" in fname or "log_extractor" in fname or "fim" in fname:
            tag = "[MODULE] "
            break
        if "main.py" in fname:
            break
    msg = " ".join(map(str, args)).encode('utf-8', 'ignore').decode('utf-8')
    logging.info(f"{tag}{msg}")

builtins.print = trapped_print

from modules.log_extractor.log_extractor import main as log_extractor_main
from modules.check_permissions.check_permissions import main as check_permissions_main
from modules.resource_checker.resource_checker import main as resource_checker_main
from modules.find_vulns import info_collector
from modules.alert.alert import main as alert_main
from modules.portscanner.portscanner import main as portscanner_main
from modules.resource_checker.disks import get_and_save_disk_info as disks
from modules.edr_enforcer import main as edr_enforcer_main
from modules.docker_monitor.docker_monitor import start_docker_monitor_thread
from modules.fim import main as fim_main
from modules.inventory import main as inventory_main
from modules.lateral_movement import LateralMovementDetector
from modules.persistence_hunter import PersistenceHunter

from modules.soar.soar import (
    SOARAutomation,
    SOARConfig,
    SOARLogger,
    SystemCommandExecutor,
    FirewallManager,
    UserAccountManager,
    ActionType
)

debug = True


def automations_cycle(agent_name: str, api_base: str, max_batch: int = 25) -> dict:
    api = AutomationsClient(api_base, timeout=10)

    tasks = api.fetch_pending_tasks(agent_name) or []
    if max_batch:
        tasks = tasks[:max_batch]

    stats = {
        "leased": len(tasks),
        "executed": 0,
        "ok": 0,
        "failed": 0,
    }

    for t in tasks:
        tid = str(t.get("id") or "")
        ok, msg = _exec_local_action(t)
        stats["executed"] += 1
        if ok:
            stats["ok"] += 1
            status = "success"
        else:
            stats["failed"] += 1
            status = "failed"

        api.report_result(
            tid,
            status=status,
            output=msg,
            metadata={
                "agent": agent_name,
                "type": t.get("type"),
            }
        )

    return stats



class AgentBootstrapError(Exception):
    pass


class ServerBootstrapClient:
    """Pulls the shared Fernet key from the main server's /api/agents/bootstrap
    endpoint, authenticated by the per-agent key issued at enrolment. This is
    the only supported way for the agent to acquire its encryption key.
    """

    def __init__(self, server_url: str, agent_key: str, timeout: int = 6):
        self.base_url = server_url.rstrip("/")
        self.agent_key = agent_key
        self.timeout = timeout
        self.cache = {
            "active": False,
            "tier": None,
            "expires_at": None,
            "fernet_key": None,
        }

    def status(self, reveal_key: bool = False) -> dict:
        del reveal_key
        url = f"{self.base_url}/api/agents/bootstrap"
        r = requests.get(url, headers={"X-Agent-Key": self.agent_key}, timeout=self.timeout)
        if r.status_code in (401, 403):
            raise AgentBootstrapError(f"Agent key rejected by server ({r.status_code}).")
        r.raise_for_status()
        data = r.json() or {}
        if not data.get("ok"):
            raise AgentBootstrapError(f"Server bootstrap failed: {data.get('error')}")
        return {
            "is_active": data.get("is_active", True),
            "tier": data.get("tier", "Community"),
            "expires_at": data.get("expires_at"),
            "fernet_key": data.get("fernet_key"),
        }

    def get_fernet_key(self) -> str:
        data = self.status(reveal_key=True)
        fk = data.get("fernet_key")
        if not fk:
            raise AgentBootstrapError("Server bootstrap returned no fernet_key.")
        self.cache.update({
            "active": bool(data.get("is_active")),
            "tier": data.get("tier"),
            "expires_at": data.get("expires_at"),
            "fernet_key": fk,
        })
        return fk

    def validate_or_wait(self, max_delay: int = 60):
        """Block until the server hands over a bootstrap, retrying forever.

        This used to `sys.exit(1)` on any failure, which is why the agent did
        not come back after a reboot. The scheduled task fires AtStartup as
        SYSTEM — before the network stack settles, before Docker Desktop is
        up, before a VPN connects. The first bootstrap call failed, the agent
        died, and the task's three restarts were consumed inside the first
        three minutes. After that the endpoint stayed blind until somebody
        logged in and started it by hand.

        A security agent must not take itself off the network because a
        dependency was slow. The only genuinely fatal condition is missing
        local enrolment config, which is checked before we ever get here.

        Backoff is 2s doubling to `max_delay`, then steady — so a server that
        comes back an hour later still gets picked up, without hammering it.
        """
        delay = 2
        attempt = 0
        while True:
            attempt += 1
            try:
                data = self.status(reveal_key=True)
                if not data.get("is_active"):
                    raise AgentBootstrapError("Server reported inactive bootstrap.")
                self.cache.update({
                    "active": True,
                    "tier": data.get("tier") or "Community",
                    "expires_at": data.get("expires_at"),
                    "fernet_key": data.get("fernet_key"),
                })
                if attempt > 1:
                    print(f"[+] Agent bootstrap OK ({self.cache['tier']}) after {attempt} attempts")
                else:
                    print(f"[+] Agent bootstrap OK ({self.cache['tier']})")
                return
            except Exception as e:
                # A rejected key is reported differently because retrying will
                # not fix a genuinely wrong one — but we still keep trying,
                # since it is also what a server whose identity table has not
                # finished loading looks like, and a dead agent is worse than
                # a noisy one.
                hint = ""
                if isinstance(e, AgentBootstrapError) and "rejected" in str(e).lower():
                    hint = "  (re-enrol this host if this persists)"
                print(f"[!] Agent bootstrap attempt {attempt} failed: {e}{hint}"
                      f" — retrying in {delay}s", flush=True)
                time.sleep(delay)
                delay = min(delay * 2, max_delay)

    # Old name kept so any external caller or fork does not break. It no
    # longer exits; the rename is the point.
    validate_or_exit = validate_or_wait


def _apply_fernet_key_to_enc_db(key: str) -> None:
    """Install the Fernet key into enc_db.

    This used to try six APIs in turn - `set_fernet_key`, then `setattr` for
    four possible attribute names, then `set_encrypt_key`, then a `_fernet_cache`
    dict - on the stated grounds that "the setter has been named three ways
    across versions". It cannot have been: `modules.enc_db` is imported from
    the agent's own package and PyInstaller bundles both into one binary, so
    there is no version either of them can be skewed against.

    Only the first rung was ever real. The rest were shapes that report
    success without doing anything - `setattr` in particular always succeeds,
    so a vestigial attribute would have absorbed the key and returned, leaving
    telemetry encrypted with a key the server does not hold and nothing
    anywhere saying so.

    Called by the refresher thread, `/reload_auth`, the SOAR handler and
    bootstrap, all four of which catch and report. A missing setter is a
    broken build, and raising is how they get to say so.
    """
    enc_db.set_fernet_key(key)


# `_is_valid_ipv4` and `_is_valid_username` were here, validating SOAR targets
# arriving on the agent's own HTTP routes. The routes are gone, and the
# validation the agent still performs lives where the action does -
# `SoarExecutor` and `UserAccountManager` each carry their own, checked
# against the target they are about to act on rather than against a request
# body.


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


class FernetKeyRefresher(threading.Thread):
    def __init__(self, client: ServerBootstrapClient, refresh_sec: int = 600, daemon: bool = True):
        super().__init__(daemon=daemon)
        self.client = client
        self.refresh_sec = max(60, int(refresh_sec))
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            try:
                fk = self.client.get_fernet_key()
                _apply_fernet_key_to_enc_db(fk)
            except Exception as e:
                print(f"[!] Fernet key refresh failed: {e}")
            finally:
                self._stop.wait(self.refresh_sec)



AGENT_NAME = None
SERVER_IP = None
SERVER_PORT = 5001

#: Telemetry transport. Derived at startup from the enrolment config's
#: `server_url` scheme - see `_resolve_ingest_transport`. An https console
#: means an https-grade ingest channel, because the two carry the same data
#: and there is nothing to be gained from encrypting the smaller half.
INGEST_TLS = False
INGEST_TLS_PORT = 5011
#: PEM bundle for a self-signed server. Verification is not optional: an
#: unverified TLS connection is encrypted to whoever answered, which against
#: an attacker on the path is what not encrypting it would have achieved.
INGEST_CA = None
#: The name in the server's certificate. Separate from SERVER_IP because the
#: certificate is issued for a hostname and the connection is usually made to
#: an address, and TLS checks the name.
SERVER_HOSTNAME = None
#: An unbounded blocking read is how a collector thread disappears for good.
INGEST_TIMEOUT_S = 30
AUTOMATIONS_API_URL = None
AUTOMATIONS_MODE = "auto"
AGENT_SHARED_SECRET = None
OS_INFO = platform.platform()

_HOSTNAME = ""
_MAC_ADDRESS = ""
try:
    import socket as _socket
    _HOSTNAME = (_socket.gethostname() or "")[:255]
except Exception:
    pass
try:
    import uuid as _uuid
    _node = _uuid.getnode()
    _MAC_ADDRESS = ':'.join(f"{(_node >> i) & 0xff:02x}" for i in range(40, -1, -8))
except Exception:
    pass

if _HOSTNAME:
    OS_INFO = f"{OS_INFO}|HOST={_HOSTNAME}"
if _MAC_ADDRESS:
    OS_INFO = f"{OS_INFO}|MAC={_MAC_ADDRESS}"

TABLES = [
    'critical_files',
    'portscan_result',
    'resource_usage',
    'packages',
    'vulnerabilities_report',
    'siem_events',
    'events_alert',
    'soar_actions',
    'disk_usage',
    'fim_data',
    'registry_logs',
    'network_connections',
    'process_events',
    'hardware_inventory',
    'security_audit',
    'docker_containers',
]

MAX_WORKERS = 6

_soar_logger = SOARLogger("soar_actions.log")
_executor = SystemCommandExecutor(_soar_logger, timeout=30, retry_attempts=3, retry_delay=2)
_firewall = FirewallManager(_soar_logger, _executor)
_user_mgr = UserAccountManager(_soar_logger, _executor)

_soar = SOARAutomation(SOARConfig())

_bootstrap_client: ServerBootstrapClient | None = None
_key_refresher: FernetKeyRefresher | None = None



def get_public_ip() -> str:
    """The local address the server will see, without asking anyone.

    Opens a UDP socket towards SERVER_IP and reads back the local address the
    kernel chose - no packet is sent and no external service is contacted, so
    this works air-gapped and cannot leak the host's existence.

    That address is the interface the server will connect back on, which is
    the one worth reporting. Falls back to 8.8.8.8 as the route target when
    SERVER_IP is not set yet.
    """
    ip = None

    target_ip = SERVER_IP or "8.8.8.8"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 80))
            ip = s.getsockname()[0]
    except Exception:
        ip = None

    if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
        return ip

    try:
        candidates = []
        import psutil
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    if not addr.address.startswith("127."):
                        candidates.append(addr.address)

        if candidates:
            public_candidates = [a for a in candidates if not _is_private_ip(a) and not a.startswith("169.254.")]
            if public_candidates:
                return public_candidates[0]
            lan_candidates = [a for a in candidates if not a.startswith("169.254.")]
            if lan_candidates:
                return lan_candidates[0]
            return candidates[0]
    except Exception:
        pass

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip and not host_ip.startswith("127.") and not host_ip.startswith("169.254."):
            return host_ip
    except Exception:
        pass

    return ip or "127.0.0.1"

# How long an identical alert stays suppressed. The detectors that use
# send_alert re-scan on a timer and re-report conditions that are still true,
# so without this the same finding is written on every pass forever.
ALERT_REPEAT_WINDOW_SEC = int(os.getenv("ALERT_REPEAT_WINDOW_SEC", "3600"))

# fingerprint -> monotonic time it was last written
_recent_alerts: dict = {}
_recent_alerts_lock = threading.Lock()


def _alert_recently_sent(fingerprint: str) -> bool:
    """True if this exact alert was written inside the repeat window.

    In memory rather than a database query: send_alert runs on several
    detector threads and this is on their hot path. The cost of forgetting on
    restart is one duplicate alert per finding, which is acceptable; the cost
    of a query per alert is not.

    The dict is pruned rather than left to grow, and pruning is what the
    previous in-process dedup got wrong - it cleared the whole thing at 1000
    entries, so deduplication stopped exactly when volume made it matter.
    """
    now = time.monotonic()
    with _recent_alerts_lock:
        seen = _recent_alerts.get(fingerprint)
        if seen is not None and now - seen < ALERT_REPEAT_WINDOW_SEC:
            return True
        # Drop only what has actually expired.
        if len(_recent_alerts) > 512:
            for fp, ts in list(_recent_alerts.items()):
                if now - ts >= ALERT_REPEAT_WINDOW_SEC:
                    _recent_alerts.pop(fp, None)
        _recent_alerts[fingerprint] = now
        return False


def send_alert(source, severity, message, metadata=None):
    """Write an alert to the local DB for ingestion, at most once per window.

    The detectors behind this report *state*, not events: `lateral_movement`
    lists established connections on sensitive ports every 300s, so a normal
    persistent loopback SMB connection produced an identical alert roughly 288
    times a day, per agent. 370 of 430 stored alerts on one endpoint were
    repeats of two findings.

    Nothing downstream could absorb that either: the alerts are encrypted
    before they reach the server, so the server's deduplication could not see
    that they were identical.
    """
    try:
        rec = {
            "source": source,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "message": message,
            "categories": source
        }
        if metadata:
            rec["message"] += f" | {json.dumps(metadata)}"

        # Computed before the timestamp is considered, so two sightings of the
        # same condition at different times produce the same value. This is
        # also the value the server deduplicates on, so the agent and the
        # platform agree on what "the same alert" means.
        fingerprint = enc_db.content_fingerprint("events_alert", rec)
        if _alert_recently_sent(fingerprint):
            return
        rec["dup_fp"] = fingerprint

        if hasattr(enc_db, "insert_record_enc"):
            enc_db.insert_record_enc("events_alert", rec)
        else:
            insert_record("events_alert", rec)
    except Exception as e:
        print(f"[Alert] Failed to send alert: {e}")


def _ingest_socket():
    """A connected socket to the ingest listener, TLS when the server is https.

    Derived from the enrolment config's `server_url` rather than configured
    separately - the same reasoning `modules/link.channel_url` gives for the
    control channel. A second setting is a second thing to get wrong, and it
    would be wrong in exactly the deployments where the first one was right.

    The certificate is verified. A self-signed server needs its CA here
    (`server_ca` in config.json, or SENTORA_CA_CERT); without it the
    connection fails, and it should - an unverified TLS connection encrypts
    the traffic to whoever answered, which against an attacker on the path is
    the same as not encrypting it.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(INGEST_TIMEOUT_S)
    try:
        raw.connect((SERVER_IP, SERVER_PORT))
        if not INGEST_TLS:
            return raw
        context = ssl.create_default_context(cafile=INGEST_CA or None)
        return context.wrap_socket(raw, server_hostname=SERVER_HOSTNAME or SERVER_IP)
    except Exception:
        raw.close()
        raise


def _read_receipt(sock):
    """The server's reply, or None if it did not send one.

    None is a real answer and not a failure: a server built before the reply
    frame stores the batch and closes, which arrives here as a clean EOF. It
    must not be reported as data loss, and it must not be reported as success
    either - `record_send` keeps the difference.
    """
    try:
        header = _recv_exactly(sock, 4)
        if header is None:
            return None
        (length,) = struct.unpack('!I', header)
        # A sane bound. Nothing legitimate sends a megabyte of receipt, and
        # allocating on a length an attacker chose is how a reply frame turns
        # into a denial of service against the agent.
        if length == 0 or length > 64 * 1024:
            return None
        body = _recv_exactly(sock, length)
        if body is None:
            return None
        return json.loads(body.decode('utf-8'))
    except Exception:
        # A malformed or truncated reply is treated as no reply. The batch is
        # already stored or already lost by this point; guessing which from a
        # broken frame would be worse than saying "unacknowledged".
        return None


def _recv_exactly(sock, n: int):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_table(table: str):
    rows = fetch_unsent(table, limit=50)
    if not rows:
        return
    fname = f"{table}.json"
    public_ip = get_public_ip()
    data_bytes = json.dumps([dict(r) for r in rows], default=str).encode()
    fsize = len(data_bytes)

    try:
        with _ingest_socket() as s:

            agent_bytes = AGENT_NAME.encode('utf-8')
            s.sendall(struct.pack('!I', len(agent_bytes)))
            s.sendall(agent_bytes)

            ip_bytes = public_ip.encode('utf-8')
            s.sendall(struct.pack('!I', len(ip_bytes)))
            s.sendall(ip_bytes)

            os_bytes = OS_INFO.encode('utf-8')
            s.sendall(struct.pack('!I', len(os_bytes)))
            s.sendall(os_bytes)

            fname_bytes = fname.encode()
            s.sendall(struct.pack('!I', len(fname_bytes)))
            s.sendall(fname_bytes)

            s.sendall(struct.pack('!Q', fsize))
            s.sendall(data_bytes)

            # Read before the socket closes. This used to mark rows sent the
            # moment `sendall` returned, which only ever meant the bytes
            # reached the operating system's socket buffer - a server that
            # accepted a batch and stored none of it looked identical from
            # here. That is how four tables stayed permanently empty for days
            # while this function logged "sent (50 rows)" every cycle.
            receipt = _read_receipt(s)

        if receipt is not None and receipt.get("error"):
            # The server took the bytes and could not store them. Leaving the
            # rows unsent is the entire point of the reply frame: they are
            # retried, and the reason is on the endpoint where somebody
            # asking "why is this table empty" will find it.
            telemetry_health.record_send_failure(
                table, f"server refused the batch: {receipt['error']}")
            if debug:
                print(f"[!] {table}: server stored nothing "
                      f"({receipt['error']}); rows kept for retry")
            return

        mark_sent(table, [r['id'] for r in rows])
        telemetry_health.record_send(table, len(rows), receipt=receipt)
        if debug:
            # The IP/OS/HOST/MAC banner used to be repeated here. It is
            # constant for the life of the process and was the single largest
            # thing in agent.log: 4376 copies of the same 120-character string
            # in thirteen hours. It is logged once at startup instead.
            if receipt is None:
                # An older server. Said as much rather than printed as a
                # success, because "sent" here means the same weak thing it
                # always did.
                print(f"[+] {table} sent ({len(rows)} rows, unacknowledged - "
                      f"server did not reply)")
            else:
                rejected = receipt.get("rejected", 0)
                note = (f", {rejected} REJECTED" if rejected else "")
                print(f"[+] {table} sent ({len(rows)} rows, "
                      f"{receipt.get('stored', 0)} stored, "
                      f"{receipt.get('duplicates', 0)} already held{note})")

    except Exception as e:
        telemetry_health.record_send_failure(table, e)
        if debug:
            print(f"[!] Sending error ({table}): {e}")


def db_sender_loop():
    while True:
        for table in TABLES:
            try:
                send_table(table)
            except Exception as e:
                if debug:
                    print(f"[!] db_sender error on {table}: {e}")
        time.sleep(10)


#: How many consecutive failures between repeat reports, once a collector has
#: announced itself broken. Loud on the first, then rare - a collector that
#: has been failing for a day should not be writing a line every two minutes.
_FAILURE_REPEAT_EVERY = 30


def periodic_wrapped(func, interval: int, name: str):
    """Run a collector forever, and say when it stops working.

    The failure report used to be behind `if debug`, which nothing sets. A
    collector that raised on its first line failed silently every interval
    for the life of the agent, and the only symptom was an empty table in the
    console - indistinguishable from a host that genuinely has nothing to
    report. Hardware and network inventory were both empty for exactly this
    reason, and nothing anywhere said so.

    Rate-limited rather than unconditional, because the same argument that
    makes silence wrong makes a line every two minutes useless: it would bury
    the schema errors and the auth rejections that also live in this log.
    """
    failures = 0
    while True:
        try:
            func()
            if failures:
                print(f"[+] {name} recovered after {failures} failure(s)", flush=True)
            failures = 0
        except SystemExit as e:
            # A library calling `sys.exit` must not end the collector.
            #
            # SystemExit inherits from BaseException, so `except Exception`
            # does not see it - and in a thread Python discards it silently.
            # `portscanner` and `info_collector` both did this on their error
            # paths, so each died on its first failure and never ran again:
            # `portscan_result sent` appeared zero times in the log of a host
            # that had been up for days, and the Ports tab was empty with
            # nothing anywhere saying why.
            #
            # Both are fixed to raise instead. This stays because the next
            # module to do it should be a reported failure, not a thread that
            # quietly stops existing.
            failures += 1
            print(f"[!] {name} called sys.exit({e.code}) - treating it as a "
                  f"failure rather than ending the collector", flush=True)
        except Exception as e:
            failures += 1
            if failures == 1 or failures % _FAILURE_REPEAT_EVERY == 0:
                print(f"[!] {name} failed ({failures} consecutive): "
                      f"{type(e).__name__}: {e}", flush=True)
                if debug:
                    traceback.print_exc()
        time.sleep(interval)


def handle_sigterm(signum, frame):
    print("[*] Received SIGTERM, exiting gracefully...", flush=True)
    os._exit(0)


# Held for the lifetime of the process. Module-level so it is never garbage
# collected — closing it would release the lock while the agent still runs.
_instance_lock = None


def acquire_single_instance_lock(port: int = 9098, wait_seconds: int = 10) -> bool:
    """Return True if this process is the only agent, False if one is already up.

    A bound socket is used rather than a PID file because it cannot go stale:
    the OS releases it when the process dies, however it dies. SO_REUSEADDR is
    deliberately *not* set — the bind failing is the signal we want.

    This matters because the installer now registers a watchdog task that
    launches the agent every 15 minutes. Without a guard, each tick would
    start a second agent that runs the whole of startup — monitor threads,
    telemetry sends — before dying on the port bind at the very end of main().
    Worse, an instance that cannot reach the server now waits in the bootstrap
    retry instead of exiting, so the duplicates would stack up indefinitely.

    `wait_seconds` covers the deliberate-restart path: the outgoing agent may
    still hold the socket for a moment after being signalled.
    """
    global _instance_lock

    deadline = time.time() + wait_seconds
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            s.listen(1)
            _instance_lock = s
            return True
        except OSError:
            s.close()
            if time.time() >= deadline:
                return False
            time.sleep(1)


def kill_old_agent_if_exists():
    old_pid = os.environ.get("OLD_AGENT_PID")
    if old_pid and int(old_pid) != os.getpid():
        try:
            print(f"[*] Killing old agent with PID {old_pid}", flush=True)
            if platform.system() == "Windows":
                subprocess.call(["taskkill", "/F", "/PID", str(old_pid)])
            else:
                os.kill(int(old_pid), signal.SIGTERM)
        except Exception as e:
            print(f"[!] Could not kill old agent: {e}", flush=True)



class AutomationsClient:
    def __init__(self, base_url: str, timeout: int = 8):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _get_json(self, path: str, params=None):
        url = f"{self.base_url}{path}"
        r = requests.get(url, params=params, timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def _post_json(self, path: str, payload: dict):
        url = f"{self.base_url}{path}"
        r = requests.post(url, json=payload, timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"ok": True}

    def fetch_pending_tasks(self, agent_name: str):
        candidates = [
            (f"/{agent_name}/automations/pending", None),
            (f"/api/agents/{agent_name}/automations/pending", None),
        ]
        last_err = None
        for path, params in candidates:
            try:
                data = self._get_json(path, params=params)
                if data is None:
                    continue
                if isinstance(data, dict) and "tasks" in data:
                    return data["tasks"]
                if isinstance(data, list):
                    return data
            except Exception as e:
                last_err = e
                continue
        # This loop runs every 5s. If *every* candidate path failed we
        # silently treat that as "no pending tasks" so the agent log
        # doesn't drown in fetch errors. Set AGENT_DEBUG_AUTOMATIONS=1
        # in the env when actually diagnosing.
        if last_err and os.getenv("AGENT_DEBUG_AUTOMATIONS"):
            print(f"[!] fetch_pending_tasks exhausted all candidates: {last_err}")
        return []

    def report_result(self, task_id: str, status: str, output: str = "", metadata: dict = None):
        payload = {
            "task_id": task_id,
            "status": status,
            "output": output[-2000:],
            "metadata": metadata or {},
        }
        candidates = [
            f"/{metadata.get('agent')}/automations/report" if metadata and metadata.get('agent') else None,
            f"/automations/{task_id}/report",
            "/automations/report",
        ]
        candidates = [c for c in candidates if c]
        for path in candidates:
            try:
                res = self._post_json(path, payload)
                if res is not None:
                    return True
            except Exception as e:
                if debug:
                    print(f"[!] report_result failed on {path}: {e}")
                    continue
        return False


def _exec_local_action(task: dict) -> (bool, str):
    ttype = (task.get("type") or "").lower()
    params = task.get("params") or {}

    if ttype == "block_ip":
        ip = params.get("ip") or params.get("target")
        if not ip:
            return False, "missing ip"
        ok, msg = _firewall.block_ip(ip)
        return ok, msg

    if ttype == "unblock_ip":
        ip = params.get("ip") or params.get("target")
        if not ip:
            return False, "missing ip"
        ok, msg = _firewall.unblock_ip(ip)
        return ok, msg

    if ttype == "disable_user":
        user = params.get("user") or params.get("target")
        if not user:
            return False, "missing user"
        ok, msg = _user_mgr.disable_user(user)
        return ok, msg

    if ttype == "enable_user":
        user = params.get("user") or params.get("target")
        if not user:
            return False, "missing user"
        ok, msg = _user_mgr.enable_user(user)
        return ok, msg

    if ttype == "run_cmd":
        # Pending automations arrive as {"params": {"target": "<json or argv>"}}
        # while direct pushes use {"params": {"cmd": [...]}}. Accept both,
        # and recover a list from a JSON-encoded string like '["dir"]' or
        # nested escapes from a buggy upstream.
        cmd = params.get("cmd")
        if cmd is None:
            cmd = params.get("target")
        if isinstance(cmd, str):
            s = cmd.strip()
            parsed_ok = False
            for _ in range(6):
                if not (s.startswith('[') and s.endswith(']')):
                    break
                try:
                    parsed = json.loads(s)
                except Exception:
                    break
                if not isinstance(parsed, list):
                    break
                if len(parsed) == 1 and isinstance(parsed[0], str) and parsed[0].startswith('[') and parsed[0].endswith(']'):
                    s = parsed[0]
                    continue
                cmd = [str(x) for x in parsed if x is not None and str(x) != ""]
                parsed_ok = True
                break
            if not parsed_ok and isinstance(cmd, str):
                try:
                    import shlex as _shlex
                    cmd = _shlex.split(s, posix=False) or [s]
                except Exception:
                    cmd = [s]
        if not cmd or not isinstance(cmd, list):
            return False, "cmd must be a non-empty list (no shell)"
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=params.get("timeout", 30), encoding='utf-8', errors='replace')
            if result.returncode == 0:
                return True, ((result.stdout or "").strip() or "Command executed")
            else:
                return False, ((result.stderr or "").strip() or (result.stdout or "").strip() or f"exit={result.returncode}")
        except subprocess.TimeoutExpired:
            return False, "timeout"
        except FileNotFoundError:
            return False, f"not found: {cmd[0]}"
        except Exception as e:
            return False, str(e)

    if ttype == "restart_service" or ttype == "restart_agent":
        print("[*] SOAR: Triggering agent restart...")
        threading.Thread(target=lambda: os.system("python main.py"), daemon=True).start() 
        return True, "Restart initiated"

    if ttype == "self_destruct":
        print("[!] SOAR: Triggering self-destruction!")
        threading.Thread(target=perform_destruction, daemon=True).start()
        return True, "Destruction initiated"

    if ttype == "reload_auth":
        try:
            fk = _bootstrap_client.get_fernet_key()
            _apply_fernet_key_to_enc_db(fk)
            return True, "Auth reloaded"
        except Exception as e:
            return False, str(e)

    return False, f"unknown task type: {ttype}"


def automations_loop(api: AutomationsClient, agent_name: str, interval_sec: int = 5):
    while True:
        try:
            tasks = api.fetch_pending_tasks(agent_name) or []
            if tasks:
                print(f"[*] Automations: {len(tasks)} pending task(s)")
            for t in tasks:
                tid = str(t.get("id") or "")
                ok, msg = _exec_local_action(t)
                status = "success" if ok else "failed"
                api.report_result(tid, status=status, output=msg, metadata={"agent": agent_name, "type": t.get("type")})
        except Exception as e:
            if debug:
                print(f"[!] automations_loop error: {e}")
        time.sleep(interval_sec)


def soar_events_loop(interval_sec: int = 30):
    """Take SOAR actions from the agent's own events_alert rows.

    Local, and deliberately so: the agent keeps responding when the server is
    unreachable, which is exactly when an intrusion is most likely to be
    cutting it off.
    """
    while True:
        try:
            stats = _soar.process_events()
            # Only when the cycle did something. process_events already logs
            # its own summary on the same condition; this printed
            # unconditionally, duplicating it and adding a fourth line to
            # every idle cycle.
            if any(stats.get(k, 0) for k in
                   ("events_processed", "actions_taken", "expired_resolved", "errors")):
                print(f"[*] SOAR cycle: events={stats.get('events_processed', 0)} "
                      f"actions={stats.get('actions_taken', 0)} "
                      f"expired_resolved={stats.get('expired_resolved', 0)} "
                      f"errors={stats.get('errors', 0)}")
        except Exception as e:
            print(f"[!] soar_events_loop error: {e}")
        time.sleep(interval_sec)


def cmd_self_destruct() -> tuple[dict, int]:
    """Uninstall this agent. Shared with the channel - see cmd_get_config.

    The autostart goes first and synchronously, because it is the half whose
    outcome the caller can still be told: once the process exits there is
    nobody left to report anything. It is also the half that decides the rest,
    since with the watchdog still armed the agent comes back, and deleting
    files first would only make it come back damaged.
    """
    removed, detail = disable_autostart()
    if not removed:
        _uninstall_log(f"REFUSED: could not remove autostart ({detail})")
        return {
            "ok": False,
            "status": "failed",
            "error": f"could not remove the agent's autostart, so it would "
                     f"restart after deletion: {detail}. Nothing was deleted "
                     f"and this agent is still installed.",
        }, 500

    threading.Thread(target=perform_destruction, daemon=True).start()
    return {
        "ok": True,
        "status": "uninstalling",
        "message": f"Autostart removed ({detail}); files are being deleted "
                   f"and the agent is exiting.",
    }, 200


def cmd_restart() -> tuple[dict, int]:
    """Relaunch this process. Shared with the channel - see cmd_get_config."""
    def restart():
        old_pid = os.getpid()
        print(f"[*] Restarting agent. Old PID: {old_pid}", flush=True)

        # A frozen build re-executes *itself*: `sys.executable` is the binary
        # and `sys.argv[0]` is that same path. `[sys.executable] + sys.argv`
        # therefore handed the new process its own path as a positional
        # argument - and `_parse_args` uses `parse_args`, not
        # `parse_known_args`, so argparse answered `unrecognized arguments`
        # and exited 2 before the agent started. This process then exited a
        # second later regardless, so Restart was a stop button. The watchdog
        # task firing fifteen minutes on is what made it look merely slow.
        argv = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
        args = [sys.executable] + argv
        env = os.environ.copy()
        env["OLD_AGENT_PID"] = str(old_pid)

        try:
            child = subprocess.Popen(args, env=env, close_fds=True)
        except Exception as e:
            print(f"[!] Restart aborted: could not launch {args[0]}: {e}",
                  flush=True)
            return

        # Never stand down until the replacement is standing up.
        #
        # The old code exited on a timer, so a child that died immediately -
        # a bad argv, a missing config, a DLL it could not load - was
        # indistinguishable from a clean handover. Both left the host with no
        # agent; only one of them said so. The healthy path does not reach the
        # exit below at all, because the new process kills this one by
        # OLD_AGENT_PID as soon as it starts.
        time.sleep(2)
        if child.poll() is not None:
            print(f"[!] Restart aborted: the replacement exited "
                  f"{child.returncode} immediately. Staying up rather than "
                  f"leaving this host unmonitored.", flush=True)
            return

        print("[*] Replacement is up; this process is exiting.", flush=True)
        if platform.system() == "Windows":
            # `app.stop()` was here, to shut the HTTP listener down first.
            # There is no listener now, and `os._exit` takes the threads with
            # it, which is the whole of what has to stop.
            os._exit(0)
        else:
            os.kill(old_pid, signal.SIGTERM)

    threading.Thread(target=restart, daemon=True).start()
    return {"status": "Agent restart initiated"}, 200


def cmd_reload_auth() -> tuple[dict, int]:
    """Re-fetch the telemetry encryption key."""
    try:
        fk = _bootstrap_client.get_fernet_key()  # type: ignore
        _apply_fernet_key_to_enc_db(fk)
        return {"ok": True, "message": "Fernet key reloaded"}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


# Directories that must never be the target of an uninstall, whatever the
# agent thinks its own location is. If AGENT_DIR resolves to one of these,
# something is wrong and deleting is not the safe response.
_UNDELETABLE = {
    "/", "/usr", "/bin", "/sbin", "/lib", "/etc", "/var", "/opt", "/home",
    "/root", "/boot", "/dev", "/proc", "/sys",
    "c:\\", "c:\\windows", "c:\\windows\\system32", "c:\\program files",
    "c:\\program files (x86)", "c:\\users",
}


def _destruction_target() -> str | None:
    """The directory to remove, or None if it cannot be established safely."""
    target = os.path.abspath(AGENT_DIR)
    normalised = target.rstrip("\\/").lower() or target.lower()
    if normalised in _UNDELETABLE or os.path.dirname(target) == target:
        return None
    # The agent's own binary or main.py must be in there. If it is not, this
    # is not the install directory and we have the wrong path.
    marker = os.path.join(target, "main.py")
    binary = os.path.join(target, "SentoraAgent.exe")
    if not (os.path.exists(marker) or os.path.exists(binary)):
        return None
    return target


# ---------------------------------------------------------------------------
# Uninstalling means removing what starts the agent, not just its files
# ---------------------------------------------------------------------------
#
# Self-destruct deleted the install directory and exited, and the agent came
# straight back. It was never a race it could win: the Windows scheduled task
# it is registered under carries
#
#     -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)
#     New-ScheduledTaskTrigger -Once -RepetitionInterval (New-TimeSpan -Minutes 15)
#
# - a watchdog whose stated purpose is to start the agent again whenever it is
# not running. Uninstalling by exiting is exactly the condition that watchdog
# exists to reverse. The Linux unit is the same shape: `Restart=on-failure`
# and enabled at boot.
#
# Worse on Windows, quietly: a running executable is locked, so once the
# watchdog had relaunched `main.exe`, `Remove-Item -Recurse -Force` on the
# install directory failed - and it was written `-ErrorAction SilentlyContinue`,
# so the failure went nowhere. The console said the action completed.
#
# So the order below is deliberate: **disable autostart first, verify it is
# gone, and only then touch any files.** If the autostart cannot be removed
# the agent deletes nothing and says so. A stale install that still runs is
# recoverable; a live watchdog relaunching a half-deleted binary is not, and
# an operator who has been told the endpoint is clean when it is not has been
# given the worst possible answer.

WINDOWS_TASK_NAME = "SentoraAgent"
LINUX_UNIT_NAME = "sentora-agent"
UNINSTALL_LOG = (
    os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Sentora", "uninstall.log")
    if platform.system().lower() == "windows"
    else "/var/log/sentora-uninstall.log"
)


def _uninstall_log(message: str) -> None:
    """Leave evidence somewhere that outlives the install directory.

    Everything the agent normally logs goes through a directory this function
    is in the business of deleting, so a failed uninstall would explain itself
    into a file that no longer exists.
    """
    line = f"{datetime.now().isoformat(timespec='seconds')} {message}"
    print(f"[uninstall] {message}", flush=True)
    try:
        os.makedirs(os.path.dirname(UNINSTALL_LOG), exist_ok=True)
        with open(UNINSTALL_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception as e:
        print(f"[uninstall] could not write {UNINSTALL_LOG}: {e}", flush=True)


def _oem_encoding() -> str:
    """The codepage Windows console tools write in. Asked once, not per call.

    Computed at import rather than inside the decoder: the decoder runs on
    every command the uninstall path issues, and a ctypes call per line is
    both wasteful and a failure that would be reported over and over.
    """
    if platform.system().lower() != "windows":
        return ""
    try:
        import ctypes
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception as e:
        print(f"[!] could not read the OEM codepage ({e}); console output "
              f"from Windows tools may be shown with the wrong characters",
              flush=True)
        return ""


_OEM_ENCODING = _oem_encoding()


def _decode_console(raw: bytes) -> str:
    """Decode output from a Windows console tool.

    `text=True` decodes with the locale codepage, and console tools write in
    the *OEM* one - so on a Turkish install `schtasks` produced "Sistem
    belirtilen dosyayÄ± bulamÄ±yor", which then travelled all the way to the
    operator's screen. The reason for a failed uninstall is not a place to
    show mojibake.
    """
    if not raw:
        return ""
    encodings = ([_OEM_ENCODING] if _OEM_ENCODING else []) + ["utf-8", "cp1252"]
    for encoding in encodings:
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _run(argv: list[str], timeout: int = 30) -> tuple[int, str]:
    """Run a command and return `(returncode, combined output)`."""
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout)
        return done.returncode, _decode_console(
            (done.stdout or b"") + (done.stderr or b"")).strip()
    except Exception as e:
        return -1, str(e)


def _autostart_still_present() -> bool:
    """Whether anything is still configured to start this agent."""
    if platform.system().lower() == "windows":
        code, _ = _run(["schtasks", "/Query", "/TN", WINDOWS_TASK_NAME])
        return code == 0
    code, out = _run(["systemctl", "list-unit-files", f"{LINUX_UNIT_NAME}.service",
                      "--no-legend", "--no-pager"])
    if code == 0 and LINUX_UNIT_NAME in out:
        return True
    return os.path.exists(f"/etc/systemd/system/{LINUX_UNIT_NAME}.service")


def disable_autostart() -> tuple[bool, str]:
    """Remove whatever relaunches this agent. Returns `(removed, detail)`.

    Verified rather than assumed: both `schtasks /Delete` and `systemctl
    disable` report success in situations where the unit survives, and the
    whole point of this step is that the next one is irreversible.
    """
    system = platform.system().lower()

    # Looked at for the wording, never to decide whether to act.
    #
    # A previous version returned early here when the autostart appeared to be
    # absent, to avoid reporting the error that deleting a missing task
    # prints. That traded a confusing message for a silent failure to remove:
    # `_autostart_still_present` answers False for any non-zero exit, not only
    # for genuine absence - `schtasks` missing from PATH, a permissions
    # refusal, output this cannot read - and on any of those the agent deleted
    # its files, exited, and was restarted by the watchdog it had never
    # touched.
    #
    # The removal now always runs. The check only chooses between "removed"
    # and "was already absent", and the verification at the end is what
    # decides success.
    was_present = _autostart_still_present()

    if system == "windows":
        code, out = _run(["schtasks", "/Delete", "/TN", WINDOWS_TASK_NAME, "/F"])
        detail = out or f"schtasks exited {code}"
        # Older installers opened inbound 9099 for the agent's API, and the
        # current one removes that rule rather than adding it - but an
        # uninstall has to clear it too, or a host that is never reinstalled
        # keeps a hole named after software that is no longer here, which is
        # exactly the kind of thing nobody goes looking for later.
        _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
              "Get-NetFirewallRule -DisplayName 'Sentora Agent API' "
              "-ErrorAction SilentlyContinue | Remove-NetFirewallRule "
              "-ErrorAction SilentlyContinue"])
    else:
        # `disable --now` stops it and removes the enablement symlink; the
        # unit file itself has to go too, or `systemctl start` still works and
        # a later `enable` brings the whole thing back.
        _run(["systemctl", "disable", "--now", LINUX_UNIT_NAME])
        unit_path = f"/etc/systemd/system/{LINUX_UNIT_NAME}.service"
        # Already absent is the state we want, so it is not an error worth
        # catching - and the verification below covers the case where it
        # disappears between this check and the removal.
        if os.path.exists(unit_path):
            try:
                os.remove(unit_path)
            except Exception as e:
                return False, f"could not remove the unit file: {e}"
        code, out = _run(["systemctl", "daemon-reload"])
        detail = out or "systemd reloaded"

    if _autostart_still_present():
        return False, f"still registered after removal ({detail})"
    return True, "removed" if was_present else "was already absent"


def perform_destruction():
    """Remove the agent's own installation directory.

    This used to delete `$(pwd)` - `Remove-Item -Recurse -Force
    (Get-Item -Path .).FullName` on Windows, `rm -rf "$(pwd)"` elsewhere.

    The working directory is not the install directory. A Scheduled Task
    registered without a start-in path runs with the working directory it
    inherits, which for a SYSTEM task is `C:\\Windows\\System32`. The agent
    runs elevated, so the command would have been carried out. An uninstall
    feature that can take out the host is worse than no uninstall feature.

    AGENT_DIR is derived from the executable (or this file), checked against a
    list of paths nothing may ever delete, and required to actually contain
    the agent. If any of that does not hold, the agent exits without deleting
    anything and says why - leaving a stale install behind is recoverable,
    the alternative is not.
    """
    system = platform.system().lower()
    target = _destruction_target()
    if not target:
        _uninstall_log(f"REFUSED: {AGENT_DIR!r} does not look like an agent "
                       f"installation directory. Nothing was deleted.")
        os._exit(1)

    # First, and only then anything else. See the note above disable_autostart:
    # deleting files while a watchdog is still armed does not uninstall the
    # agent, it just makes it restart from a damaged install.
    removed, detail = disable_autostart()
    if not removed:
        _uninstall_log(
            f"REFUSED: could not remove autostart ({detail}). Nothing was "
            f"deleted - the agent is still installed and will keep running. "
            f"Remove it by hand: "
            f"{'schtasks /Delete /TN ' + WINDOWS_TASK_NAME + ' /F' if system == 'windows' else 'systemctl disable --now ' + LINUX_UNIT_NAME}")
        os._exit(1)
    _uninstall_log(f"autostart removed ({detail})")

    _uninstall_log(f"removing {target}")

    try:
        if system == "windows":
            # -LiteralPath so a directory containing [ ] or ` is treated as a
            # name rather than a wildcard pattern.
            #
            # Not SilentlyContinue. A running executable is locked on Windows,
            # so this is a command that genuinely can fail - and it used to
            # fail exactly when the watchdog had relaunched the agent, which
            # is the case an operator most needs to hear about. The result is
            # appended to the uninstall log, which lives outside the directory
            # being removed.
            script = (
                f"Start-Sleep -Seconds 5; "
                f"try {{ Remove-Item -LiteralPath '{target}' -Recurse -Force -ErrorAction Stop; "
                f"Add-Content -LiteralPath '{UNINSTALL_LOG}' -Value 'removed {target}' }} "
                f"catch {{ Add-Content -LiteralPath '{UNINSTALL_LOG}' "
                f"-Value \"FAILED to remove {target}: $($_.Exception.Message)\" }}"
            )
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                close_fds=True,
            )
        else:
            # No shell expansion of the path: it is an argument, not a string
            # the shell re-parses. `sh -c "rm -rf $(pwd)"` would split on
            # spaces. The outcome is recorded for the same reason as above.
            subprocess.Popen(
                ["/bin/sh", "-c",
                 'sleep 5; if rm -rf -- "$0"; then echo "removed $0" >> "$1"; '
                 'else echo "FAILED to remove $0" >> "$1"; fi',
                 target, UNINSTALL_LOG],
                close_fds=True,
            )

        _uninstall_log("autostart removed and deletion scheduled; agent exiting")
        if system == "windows":
            os._exit(0)
        else:
            os.kill(os.getpid(), signal.SIGKILL)
    except Exception as e:
        _uninstall_log(f"ERROR during destruction: {e}. Autostart was already "
                       f"removed, so the agent will not restart, but files may "
                       f"remain in {target}.")
        os._exit(1)



def _init_agent_bootstrap(server_url: str, agent_key: str):
    global _bootstrap_client, _key_refresher
    _bootstrap_client = ServerBootstrapClient(server_url, agent_key)
    _bootstrap_client.validate_or_wait()
    fk = _bootstrap_client.cache.get("fernet_key") or _bootstrap_client.get_fernet_key()
    _apply_fernet_key_to_enc_db(fk)
    refresh_sec = int(os.getenv("FERNET_REFRESH_SEC", "600"))
    _key_refresher = FernetKeyRefresher(_bootstrap_client, refresh_sec=refresh_sec, daemon=True)
    _key_refresher.start()


def start_lateral_movement_check():
    detector = LateralMovementDetector()
    while True:
        try:
            findings = detector.run()
            for finding in findings:
                send_alert(
                    source="LateralMovement",
                    severity=finding["severity"],
                    message=finding["message"],
                    metadata=finding["details"]
                )
        except Exception as e:
            print(f"[Main] Lateral movement check error: {e}")
        time.sleep(300)

def start_persistence_hunt():
    hunter = PersistenceHunter()
    while True:
        try:
            findings = hunter.run()
            for finding in findings:
                send_alert(
                    source="PersistenceHunter",
                    severity=finding["severity"],
                    message=finding["message"],
                    metadata=finding["details"]
                )
        except Exception as e:
            print(f"[Main] Persistence hunt error: {e}")
        time.sleep(1200)

def start_threads():
    threading.Thread(target=start_lateral_movement_check, daemon=True).start()
    threading.Thread(target=start_persistence_hunt, daemon=True).start()
    start_docker_monitor_thread()

    threading.Thread(
        target=periodic_wrapped,
        args=(log_extractor_main, 600, "log_extractor"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(check_permissions_main, 600, "check_permissions"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(resource_checker_main, 120, "resource_checker"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(disks, 120, "disks"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(info_collector.main, 200, "info_collector"),
        daemon=True
    ).start()


    threading.Thread(
        target=periodic_wrapped,
        args=(alert_main, 10, "alert"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(portscanner_main, 3600, "portscanner"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(edr_enforcer_main, 120, "edr_enforcer"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(fim_main, 300, "fim"),
        daemon=True
    ).start()

    threading.Thread(
        target=periodic_wrapped,
        args=(inventory_main, 600, "inventory"),
        daemon=True
    ).start()

    threading.Thread(
        target=soar_events_loop,
        args=(30,),
        daemon=True
    ).start()

    api = AutomationsClient(AUTOMATIONS_API_URL, timeout=10)
    threading.Thread(
        target=automations_loop,
        args=(api, AGENT_NAME, 5),
        daemon=True
    ).start()

    start_automations_worker()

    threading.Thread(
        target=db_sender_loop,
        daemon=True
    ).start()

    start_server_channel()


def open_channel_stream(kind: str, args: dict):
    """Start a console or a screen for a request that arrived on the channel.

    Returns an object with `read(timeout) -> bytes | None`, `write(data)` and
    `close(why)` - which is what `modules/console` already produces, and what
    the screen capture is wrapped to produce below. `modules/link` drives it
    without knowing what either one is.

    Raising is how a refusal is reported: the caller turns it into the
    `stream_failed` frame the server is waiting on, so "no console on this
    host" arrives as a sentence rather than as a stream that opens and never
    produces a frame.
    """
    if kind == "console":
        return _ConsoleStream()
    if kind == "screen":
        return _ScreenStream(args or {})
    raise ValueError(f"this agent does not serve a {kind!r} stream")


class _ConsoleStream:
    """A console shell, speaking the frame protocol the browser already speaks.

    The direct `/console/ws` handler parses what arrives - `decode_input`
    turns `{"t":"i","d":"ls\\n"}` into the two characters the shell should
    receive - and frames what it sends back. Handing the raw session to the
    channel instead skipped both: every keystroke frame, and the resize the
    browser sends on connect, went into the shell's stdin *as JSON text*, and
    nothing ever announced the session mode.

    So the console connected, showed nothing, and eventually died - while the
    screen, which is bytes either way, worked perfectly. Two transports had
    grown two behaviours, which is exactly what the shared `cmd_*` functions
    exist to prevent; this is the same idea for the streaming half.
    """

    def __init__(self):
        # `open_session`, not `new_session`: the one-session-per-agent guard
        # lives in the former, and going round it would have let the channel
        # open concurrent root shells on one host - the thing the guard exists
        # to prevent, reintroduced by the new transport.
        self.session = console.open_session()
        self.exit_reason = ""
        self._closed = False
        # Sent before anything else, the way the direct handler does: the
        # browser has to know whether it is driving a terminal or a pipe
        # before the first keystroke, not after.
        self._pending = [console.encode_mode(self.session)]

    def read(self, timeout: float = 0.2):
        if self._pending:
            return self._pending.pop(0).encode("utf-8")
        if self._closed:
            return None

        chunk = self.session.read(timeout)
        if chunk is None:
            self.exit_reason = (getattr(self.session, "exit_reason", "")
                                or "the shell exited")
            self._closed = True
            # One last frame, so the browser prints why rather than simply
            # going quiet.
            return console.encode_exit(
                self.session.proc.poll(), self.exit_reason).encode("utf-8")
        if not chunk:
            return b""
        return console.encode_output(chunk).encode("utf-8")

    def write(self, data) -> None:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8", "replace")
        kind, payload = console.decode_input(data)
        if kind == "input":
            self.session.write(payload["data"])
        elif kind == "resize":
            self.session.resize(payload["cols"], payload["rows"])

    def close(self, why: str = "") -> None:
        # `_closed` decides what this reports, never whether the cleanup runs.
        # `read` sets it the moment the shell exits on its own, so the early
        # return this replaces skipped `close_active` on the most ordinary
        # ending there is - typing `exit`. The module-level session stayed
        # registered, and because a console is one per host, every later
        # request was refused as a duplicate of a shell that had already died.
        # Nothing said so: the server fell back to the direct addresses and
        # reported those as unreachable instead.
        self._closed = True
        self.exit_reason = why or self.exit_reason
        # Through the module, so the registered session is cleared too.
        console.close_active(self.exit_reason)


class _ScreenStream:
    """The screen capture, in the shape the channel drives.

    `screen_capture` hands back JPEG frames one at a time; this puts them
    behind the same `read`/`write`/`close` the console already has, so the
    channel has one thing to pump rather than two special cases.
    """

    def __init__(self, args: dict):
        self.fps = max(1, min(int(args.get("fps", 10)), 30))
        self.quality = max(20, min(int(args.get("q", 60)), 95))
        self.width = max(320, min(int(args.get("w", 1280)), 2560))
        self.exit_reason = ""
        self._closed = False
        self._helper = None
        self._capture = None

        # Same two paths the direct websocket already chooses between: a
        # helper in the user's session when this process cannot see a desktop,
        # and `mss` here when it can. Wiring only the first would have made
        # the channel work on session-0 Windows and silently not on anything
        # else - including the headless Linux hosts, which have neither.
        if screen_capture.in_session_zero():
            self._helper = screen_capture.spawn_helper(
                self.fps, self.quality, self.width)
        else:
            self._capture = _DirectCapture(self.fps, self.quality, self.width)

    def read(self, timeout: float = 0.2):
        if self._closed:
            return None
        if self._helper is not None:
            return self._helper.read_frame()
        return self._capture.read()

    def write(self, data) -> None:
        """Nothing to write to a screen. Said rather than silently ignored."""
        print("[screen] ignoring input on a one-way stream", flush=True)

    def close(self, why: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        self.exit_reason = why or self.exit_reason
        for source in (self._helper, self._capture):
            if source is not None:
                source.close()


class _DirectCapture:
    """`mss` in this process, one JPEG at a time, paced to the frame rate.

    Opened eagerly so a host with no display says so at `open_stream` time -
    which becomes the `stream_failed` frame the server is waiting on - rather
    than connecting successfully and then producing nothing. A stream that
    opens and stays black is the hardest failure here to attribute; the direct
    websocket path learned that the slow way.
    """

    def __init__(self, fps: int, quality: int, width: int):
        try:
            import mss as _mss
            from PIL import Image
        except ImportError as e:
            raise screen_capture.CaptureUnavailable(
                f"the screen stack is missing from this build ({e})")

        self._Image = Image
        self.interval = 1.0 / fps
        self.quality = quality
        self.width = width
        self._last = 0.0

        try:
            self._sct = _mss.mss()
        except Exception as e:
            detail = str(e) or type(e).__name__
            if not screen_capture.IS_WINDOWS and not os.environ.get("DISPLAY"):
                detail = screen_capture.describe_unavailable()
            raise screen_capture.CaptureUnavailable(f"no screen available - {detail}")

        if not self._sct.monitors:
            raise screen_capture.CaptureUnavailable("no monitors detected")
        self._monitor = self._sct.monitors[1] if len(self._sct.monitors) > 1 \
            else self._sct.monitors[0]

    def read(self):
        # Paced here rather than by the caller: the channel pumps as fast as
        # it can, and without this a screen would saturate the link the
        # commands share.
        now = time.monotonic()
        if now - self._last < self.interval:
            time.sleep(max(0.0, self.interval - (now - self._last)))
        self._last = time.monotonic()

        import io as _io

        shot = self._sct.grab(self._monitor)
        img = self._Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        if img.width > self.width:
            ratio = self.width / img.width
            img = img.resize((self.width, int(img.height * ratio)))
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=self.quality, optimize=False)
        return buf.getvalue()

    def close(self) -> None:
        try:
            self._sct.close()
        except Exception as e:
            print(f"[screen] capture would not close: {e}", flush=True)


def start_server_channel() -> None:
    """Open the channel the server answers over, if we know where to reach it.

    Started alongside the collectors rather than in place of the HTTP
    listener: both are live during the migration, and an agent whose channel
    cannot be established keeps working exactly as before.
    """
    server_url = AUTOMATIONS_API_URL or ""
    if not server_url or not AGENT_SHARED_SECRET:
        print("[link] no server URL or key yet; the channel stays closed and "
              "the server will reach this agent over HTTP.", flush=True)
        return

    client = link.AgentLinkClient(
        server_url, AGENT_SHARED_SECRET, dispatch_channel_request,
        agent_name=AGENT_NAME, open_stream=open_channel_stream)
    threading.Thread(target=client.run_forever, daemon=True).start()
    print(f"[link] channel opening to {client.channel_url()}", flush=True)


def server_automations_loop(agent_name: str, api_base: str, interval_sec: int = 5):
    while True:
        try:
            stats = automations_cycle(agent_name, api_base, max_batch=25)
            if stats.get("executed", 0):
                print(f"[*] Automations (SERVER): leased={stats.get('leased', 0)} "
                      f"executed={stats.get('executed', 0)} ok={stats.get('ok', 0)} "
                      f"failed={stats.get('failed', 0)}")
        except Exception as e:
            print(f"[!] server_automations_loop error: {e}")
        time.sleep(interval_sec)


def start_automations_worker():
    mode = (AUTOMATIONS_MODE or "auto").lower()
    if mode == "server":
        threading.Thread(
            target=server_automations_loop,
            args=(AGENT_NAME, AUTOMATIONS_API_URL, 5),
            daemon=True
        ).start()
    elif mode == "db":
        threading.Thread(
            target=due_automations_loop,
            args=(AGENT_NAME, 5, 50),
            daemon=True
        ).start()
    else:
        if AUTOMATIONS_API_URL:
            threading.Thread(
                target=server_automations_loop,
                args=(AGENT_NAME, AUTOMATIONS_API_URL, 5),
                daemon=True
            ).start()
        else:
            threading.Thread(
                target=due_automations_loop,
                args=(AGENT_NAME, 5, 50),
                daemon=True
            ).start()


def due_automations_loop(agent_name: str, interval_sec: int = 5, batch: int = 50):
    while True:
        try:
            stats = _soar.process_due_automations(agent_name=agent_name, max_batch=batch)
            executed = stats.get("executed", 0)
            if executed:
                print(f"[*] Automations (DB): executed={executed} ok={stats.get('ok', 0)} "
                      f"failed={stats.get('failed', 0)}")
        except Exception as e:
            print(f"[!] due_automations_loop error: {e}")
        time.sleep(interval_sec)


def _parse_args():
    parser = argparse.ArgumentParser(description="Sentora Agent")
    parser.add_argument('--automations-mode', type=str, default=os.getenv("AUTOMATIONS_MODE", "server"),
                        choices=['auto', 'server', 'db'],
                        help='Automations backend: server (API), db (local table), or auto (default).')
    parser.add_argument('--server', '-s', type=str, default=None,
                        help='Server IP or FQDN (override config.server_url)')
    parser.add_argument('--agent', '-a', type=str, default=None,
                        help='Agent name (override config.agent_name)')
    parser.add_argument('--config', '-c', type=str, default=None,
                        help='Path to enrolment JSON config (agent_name, agent_key, server_url). '
                             'Generated by the server installer; required for the agent to run.')
    parser.add_argument('--api', '-p', type=str, default=None,
                        help='Automations API base (Default: http://<server>:8000)')
    parser.add_argument('--ingest-port', type=int, default=None,
                        help='Ingest TCP port. Default follows the server URL '
                             'scheme: 5011 for https, 5001 for http.')
    parser.add_argument('--ca', type=str, default=None,
                        help='PEM bundle used to verify the server certificate. '
                             'Needed when the server uses the self-signed CA '
                             'from certs/generate_certs.py.')
    return parser.parse_args()


def _resolve_ingest_transport(cfg: dict, args) -> tuple[bool, int, str | None, str | None]:
    """Whether telemetry goes over TLS, and to which port.

    Derived from `server_url`, the same rule `modules/link.channel_url` uses
    for the control channel: an `https://` console means an encrypted ingest
    channel. Deriving beats configuring here because the two settings would
    have to agree, nothing would make them, and the deployment where they
    disagreed would be the one that thought it was encrypted.

    An explicit `--ingest-port` still wins. Somebody port-forwarding through a
    bastion has a real reason to override this, and the derivation is a
    default rather than a rule.
    """
    server_url = str(cfg.get("server_url") or "")
    tls = server_url.lower().startswith("https://")

    if args.ingest_port is not None:
        port = int(args.ingest_port)
    elif cfg.get("ingest_port"):
        port = int(cfg["ingest_port"])
    else:
        port = INGEST_TLS_PORT if tls else 5001

    ca = (args.ca or cfg.get("server_ca") or os.getenv("SENTORA_CA_CERT") or "").strip()
    if ca and not os.path.exists(ca):
        print(f"[!] server_ca points at {ca!r}, which does not exist. TLS "
              f"verification will use the system trust store and will fail "
              f"against a self-signed server.", flush=True)
        ca = ""

    # The name the certificate is issued for. Taken from the URL rather than
    # from SERVER_IP: `certs/generate_certs.py` puts a hostname in the SAN,
    # and verifying an address against it fails with a message that reads
    # like a certificate problem when it is an addressing one.
    host = server_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0] or None

    return tls, port, (ca or None), host


def _load_identity_from_config(path: str) -> dict:
    """Load agent identity (agent_name, agent_key, server_url) from JSON config."""
    with open(path, "r", encoding="utf-8-sig") as f:
        cfg = json.load(f)
    required = ("agent_name", "agent_key", "server_url")
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise ValueError(f"Config missing required keys: {missing}")
    return cfg


# Inbound authentication used to live here - `_accepted_auth_tokens`,
# `_timing_safe_in`, `_check_auth_header`, `_ws_authorized`. All of it is gone
# with the listener it guarded. The agent no longer accepts a connection from
# anyone; it opens one, and `modules/link` presents this agent's key to the
# server rather than checking anyone else's.
#
# Worth keeping the reason it mattered. `_is_permissive_auth` sat in that
# check and accepted ANY non-empty X-Agent-Key whenever AGENT_MASTER_SECRET
# was unset on the host - and nothing in this repository ever set it, not the
# installer, not the scheduled task, not the systemd unit. So every default
# installation ran permissively, and
#
#     curl -H 'X-Agent-Key: a' http://<endpoint>:9099/soar/execute
#
# with `{"action": "run_cmd", ...}` was unauthenticated remote code execution
# as SYSTEM, fleet-wide, with `/config/rules.yaml` available to the same
# caller to switch detection off first.
#
# The mode existed so server→agent calls would not fail during rollout. That
# trade is on the wrong side - an EDR that fails open is worse than no EDR,
# because the console reports the endpoint as protected - and the answer in
# the end was not a better check on that port. It was not having the port.


def cmd_soar_execute(data: dict) -> tuple[dict, int]:
    """Run one SOAR action here. Shared with the channel - see cmd_get_config.

    `data` is the request body either way. The authentication that used to sit
    at the top belongs to the route: the channel is authenticated once, when
    the agent opens it, and there is no second party on it to check.
    """
    data = data if isinstance(data, dict) else {}

    action_raw = data.get("action", "")
    action = str(action_raw).strip().lower()

    if not action:
        return {"ok": False, "error": "action is required"}, 400

    allowed_actions = {a.value for a in ActionType}
    if action not in allowed_actions:
        return {"ok": False, "error": f"action not implemented: {action}"}, 501

    target_raw = data.get("target")
    target_str = str(target_raw).strip() if target_raw is not None else ""

    comment = (data.get("comment") or "").strip()

    event_id = data.get("event_id")
    try:
        event_id = int(event_id) if event_id is not None else None
    except Exception:
        event_id = None

    ttl = data.get("ttl", None)
    try:
        ttl = int(ttl) if ttl not in (None, "") else None
    except Exception:
        ttl = None

    force = bool(data.get("force", False))

    if action in (ActionType.BLOCK_IP.value, ActionType.UNBLOCK_IP.value):
        if not FirewallManager._is_valid_ip(target_str):
            return {"ok": False, "error": "invalid IPv4"}, 400
        target_for_exec = target_str

    elif action in (ActionType.DISABLE_USER.value, ActionType.ENABLE_USER.value):
        if not UserAccountManager._is_valid_username(target_str):
            return {"ok": False, "error": "invalid username"}, 400
        target_for_exec = target_str

    elif action == ActionType.RUN_CMD.value:
        if not isinstance(target_raw, list) or not target_raw:
            return ({"ok": False,
                     "error": "run_cmd target must be a non-empty list"}, 400)
        target_for_exec = target_raw

    elif action == ActionType.KILL_PROCESS.value:
        if not target_str:
            return {"ok": False, "error": "process target is required"}, 400
        target_for_exec = target_str

    elif action == ActionType.RESTART_SERVICE.value:
        if not target_str:
            return {"ok": False, "error": "service name is required"}, 400
        target_for_exec = target_str

    elif action == ActionType.LOCK_MACHINE.value:
        target_for_exec = target_str or ""

    elif action == ActionType.QUARANTINE_FILE.value:
        if not target_str:
            return {"ok": False, "error": "file path is required"}, 400
        target_for_exec = target_str

    elif action == ActionType.TAIL_LOG.value:
        if not target_str:
            return {"ok": False, "error": "log path is required"}, 400
        target_for_exec = target_str

    else:
        return {"ok": False, "error": f"action not implemented: {action}"}, 501

    ok, msg, expires_at = _soar.exec_action(
        action=action,
        target=target_for_exec,
        comment=comment,
        event_id=event_id,
        ttl=ttl,
        force=force,
    )

    status = "success" if ok else "failed"

    soar_action_id = None
    try:
        if action == ActionType.UNBLOCK_IP.value:
            db_action = ActionType.BLOCK_IP.value
        elif action == ActionType.ENABLE_USER.value:
            db_action = ActionType.DISABLE_USER.value
        else:
            db_action = action

        eid = int(event_id or 0)

        # fetch_one() already appends "ORDER BY ... LIMIT 1" — passing them
        # in the WHERE clause produces "LIMIT 1 LIMIT 1" → Postgres syntax error.
        row = fetch_one(
            "soar_actions",
            where="event_id=%s AND action=%s AND target=%s",
            params=(eid, db_action, target_str),
            order_by="id DESC",
        )
        if row:
            soar_action_id = row.get("id")
    except Exception:
        soar_action_id = None

    if not ok:
        lower_msg = (msg or "").lower()
        if any(x in lower_msg for x in ["invalid ip address", "invalid username", "must be a list"]):
            http_status = 400
        elif "unsupported action" in lower_msg:
            http_status = 501
        else:
            http_status = 500
    else:
        http_status = 200

    return ({
        "ok": ok,
        "message": msg or ("done" if ok else "failed"),
        "soar_action_id": soar_action_id,
        "status": status,
        "expires_at": expires_at,
    }, http_status)


# ---------------------------------------------------------------------------
# Commands, once
# ---------------------------------------------------------------------------
#
# The server can now reach this agent two ways: the HTTP listener below, and
# the channel the agent opens to it (modules/link.py). The command bodies live
# here so both call the same code.
#
# Not tidiness. Two implementations of "write the rules file" would drift, and
# the one that drifted would be reachable only in the deployments that had
# already moved to the channel - so the bug would appear on exactly the hosts
# nobody was still watching the old path on.
#
# Each returns `(body, status)`, which is the shape the channel speaks and
# what `sanic_json` takes.

CONFIG_TYPES = ("rules", "log_paths", "file_scan")


def cmd_get_config(cfg_type: str) -> tuple[dict, int]:
    if cfg_type not in CONFIG_TYPES:
        return {"ok": False, "error": "invalid type"}, 400
    try:
        # Persistent copy if the operator has ever pushed one, else the copy
        # that shipped inside the build. See modules/agent_paths.
        path = agent_paths.config_path(cfg_type)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"ok": True, "content": content, "path": path}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


def cmd_set_config(cfg_type: str, content) -> tuple[dict, int]:
    if cfg_type not in CONFIG_TYPES:
        return {"ok": False, "error": "invalid type"}, 400
    if content is None:
        return {"ok": False, "error": "no content"}, 400
    try:
        # Beside the executable, never into the PyInstaller extraction
        # directory: that one is deleted when the process exits, so the old
        # write reported success and silently reverted on the next restart.
        path = agent_paths.writable_config_path(cfg_type)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return {
            "ok": True,
            "message": f"Config written to {path}. It survives a restart.",
            "path": path,
        }, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


def dispatch_channel_request(method: str, path: str, body) -> tuple[dict, int]:
    """Route a request that arrived on the channel to the command it names.

    The paths are the ones the HTTP listener already serves, deliberately: the
    server sends the same `method` and `path` either way, so nothing on its
    side has to know which transport it got. See modules/link.

    No authentication here. The channel was authenticated once, when the agent
    opened it with its own key, and only the server is on the other end - so
    there is no second party to check. That is the difference from the HTTP
    routes this replaced, where anything that could reach port 9099 could
    knock and the check had to be right on every one of them.
    """
    body = body if isinstance(body, dict) else {}

    if path.startswith("/config/"):
        cfg_type = path[len("/config/"):].strip("/")
        if method == "GET":
            return cmd_get_config(cfg_type)
        if method == "POST":
            return cmd_set_config(cfg_type, body.get("content"))
        return {"ok": False, "error": f"{method} not allowed on {path}"}, 405

    if path == "/restart" and method == "POST":
        return cmd_restart()

    if path == "/reload_auth" and method == "POST":
        return cmd_reload_auth()

    if path == "/self_destruct" and method == "POST":
        return cmd_self_destruct()

    if path == "/soar/execute" and method == "POST":
        return cmd_soar_execute(body)

    if path == "/health":
        return {"ok": True, "agent": AGENT_NAME}, 200

    if path == "/telemetry/health":
        # What this agent holds and believes it has shipped, per table. The
        # server puts its own row counts beside these; neither half alone can
        # tell a quiet host from a broken pipeline.
        return {"ok": True, "agent": AGENT_NAME,
                "tables": telemetry_health.report(TABLES)}, 200

    # Named rather than a bare 404: a path the agent does not implement is
    # usually a server that is newer than this build, and saying so is the
    # difference between "upgrade the agent" and an afternoon of guessing.
    return {"ok": False,
            "error": f"this agent does not implement {method} {path}"}, 501



# `_stream_via_helper` and `_stream_directly` were here: the two capture
# paths the removed `/screen/ws` route chose between, each pumping frames
# straight into a websocket. `_ScreenStream` makes the same choice and
# hands frames back through `read`, so the channel has one thing to pump
# rather than a second implementation to keep in step.

def main():
    global AGENT_NAME, SERVER_IP, SERVER_PORT, AGENT_SHARED_SECRET, AUTOMATIONS_API_URL, AUTOMATIONS_MODE
    global INGEST_TLS, INGEST_CA, SERVER_HOSTNAME

    if hasattr(signal, 'SIGTERM'):
        try:
            signal.signal(signal.SIGTERM, handle_sigterm)
        except Exception:
            pass

    # Put the shipped configs beside the executable on first run, so the
    # writable copy and the read path are the same file from the start.
    # Never overwrites: a config an operator pushed is their decision, and a
    # new build must not quietly discard it.
    for created in agent_paths.seed_persistent_config():
        print(f"[*] seeded config: {created}", flush=True)

    kill_old_agent_if_exists()

    # Before any work: if another agent already holds the lock, this is the
    # watchdog task firing while everything is healthy. Exit 0 so Task
    # Scheduler does not record it as a failure.
    if not acquire_single_instance_lock():
        print("[*] Another Sentora agent instance is already running — nothing to do.", flush=True)
        sys.exit(0)

    # Once, here, rather than on every table send. This is the banner that
    # used to be repeated thousands of times a day in agent.log.
    print(f"[*] Host: {OS_INFO}")

    args = _parse_args()

    cfg_path = args.config or os.getenv("SENTORA_CONFIG")
    if not cfg_path:
        default_cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        if os.path.exists(default_cfg):
            cfg_path = default_cfg

    cfg = {}
    if cfg_path:
        try:
            cfg = _load_identity_from_config(cfg_path)
            print(f"[*] Loaded identity from: {cfg_path}")
        except Exception as e:
            print(f"[!] Failed to load config at {cfg_path}: {e}")
            cfg = {}

    AGENT_NAME = args.agent or cfg.get("agent_name")
    SERVER_IP = args.server or cfg.get("server_ip") or (cfg.get("server_url", "").replace("http://", "").replace("https://", "").split(":")[0] or "127.0.0.1")
    AGENT_SHARED_SECRET = cfg.get("agent_key")

    INGEST_TLS, SERVER_PORT, INGEST_CA, SERVER_HOSTNAME = _resolve_ingest_transport(
        cfg, args)

    if not AGENT_NAME:
        AGENT_NAME = "agent"
    if not AGENT_SHARED_SECRET or not cfg.get("server_url"):
        print(
            "[!] Missing enrolment config. Run the server installer (deploy.sh / deploy.ps1)\n"
            "    to register this host and produce config.json, then start the agent with\n"
            "        ./main --config <path/to/config.json>"
        )
        sys.exit(1)

    AUTOMATIONS_API_URL = args.api or cfg.get("server_url") or os.getenv("AUTOMATIONS_API_URL", f"http://{SERVER_IP}:8000")
    AUTOMATIONS_MODE = (args.automations_mode or "auto").lower()

    _init_agent_bootstrap(cfg["server_url"], cfg["agent_key"])

    # Bring the local database up to the shipped schema before any collector
    # writes to it. Postgres runs docker-entrypoint-initdb.d only on an empty
    # data directory, so an upgraded agent on an existing machine otherwise
    # keeps the schema it was first installed with, and every insert that
    # touches a newer column fails into agent.log where the server cannot see
    # it. Failures here are reported, not fatal: a partial schema still
    # collects most of the telemetry.
    try:
        from modules.db import apply_schema
        apply_schema()
    except Exception as e:
        print(f"[!] Could not apply the agent schema: {e}", flush=True)

    print(f"[*] Agent Name: {AGENT_NAME}")
    print(f"[*] Server IP: {SERVER_IP}")
    print(f"[*] Ingest: {SERVER_IP}:{SERVER_PORT} "
          f"({'TLS' if INGEST_TLS else 'PLAINTEXT - telemetry crosses the network in the clear'})")
    print(f"[*] API Base: {AUTOMATIONS_API_URL}")
    print(f"[*] Automations Mode: {AUTOMATIONS_MODE} "
          f"({'server' if (AUTOMATIONS_MODE == 'server' or (AUTOMATIONS_MODE == 'auto' and AUTOMATIONS_API_URL)) else 'db'})")
    print(f"[*] Public IP (auto-detected): {get_public_ip()}")
    print(f"[*] OS Info: {OS_INFO}")
    print("[*] Starting agent...")

    time.sleep(2)
    start_threads()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("[*] Exiting...")


if __name__ == "__main__":
    # The capture helper is this same binary re-entered with a flag, so it has
    # to branch before anything else starts: the helper must not take the
    # single-instance lock, open a database, register threads or bring up the
    # HTTP listener. It captures a screen and writes to a pipe, and that is
    # the whole of its job. See modules/screen_capture.
    if "--screen-helper" in sys.argv:
        import multiprocessing
        multiprocessing.freeze_support()
        sys.exit(screen_capture.helper_main(sys.argv))

    # Same reasoning: the console helper hosts a pseudoconsole in the user's
    # session, because session 0 cannot. It must not take the single-instance
    # lock or start any collector.
    if "--console-helper" in sys.argv:
        import multiprocessing
        multiprocessing.freeze_support()
        sys.exit(console.console_helper_main())

    import multiprocessing
    multiprocessing.freeze_support()

    # No listener. The agent opens a connection; nothing dials it.
    #
    # This used to be `app.run()` on 0.0.0.0:9099, with the collectors started
    # from a `before_server_start` hook - so an HTTP server nobody needed was
    # what kept the process alive and running. It existed because the server
    # reached agents by dialling that port, and everything painful about this
    # codebase followed from that one decision: an address to guess behind
    # NAT, a firewall rule Windows cannot prompt for as a service in session
    # 0, `ufw` on Linux, and a management API with /self_destruct on it
    # listening on every endpoint in the fleet.
    #
    # `modules/link` now dials the server and `dispatch_channel_request` and
    # `open_channel_stream` answer over it, which is every route this app
    # used to serve. `main` starts the collectors and blocks, which is all
    # Sanic was really providing.
    main()
