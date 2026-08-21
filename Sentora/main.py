import socket
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

from sanic import Sanic
from sanic_cors import CORS
from sanic.request import Request
from sanic.response import json as sanic_json, text as sanic_text

from modules.db import insert_record, fetch_unsent, mark_sent, fetch_one
import modules.enc_db as enc_db

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
    fh = logging.FileHandler(AGENT_LOG_PATH, encoding="utf-8", mode="a")
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
    """enc_db'ye anahtarı itilaflı API'lere rağmen takmaya çalış."""
    if hasattr(enc_db, "set_fernet_key") and callable(enc_db.set_fernet_key):
        enc_db.set_fernet_key(key)
        return
    for attr in ("FERNET_KEY", "fernet_key", "_fernet_key", "current_fernet_key"):
        if hasattr(enc_db, attr):
            setattr(enc_db, attr, key)
            return
    if hasattr(enc_db, "set_encrypt_key") and callable(enc_db.set_encrypt_key):
        enc_db.set_encrypt_key(key)
        return
    if hasattr(enc_db, "_fernet_cache"):
        try:
            enc_db._fernet_cache["key"] = key  # type: ignore[attr-defined]
            return
        except Exception:
            pass
    print("[!] Warning: Could not apply Fernet key to enc_db via known hooks. Ensure enc_db exposes a setter.")


def _is_valid_ipv4(ip: str) -> bool:
    parts = str(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def _is_valid_username(u: str) -> bool:
    return bool(_USER_RE.match(str(u or "")))


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



app = Sanic("Sentora_Agent")
CORS(app)

AGENT_NAME = None
SERVER_IP = None
SERVER_PORT = 5001
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
    """
    - HTTP ile dış servise çıkmaz.
    - Önce SERVER_IP'ye doğru route alıp, o route üzerindeki local IP'yi döner.
    - Bu da server'ın geri bağlanmaya çalışacağı interface'teki IP olur.
    - Eğer SERVER_IP henüz set değilse, 8.8.8.8 fallback kullanır.
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
    except:
        pass

    return ip or "127.0.0.1"

def send_alert(source, severity, message, metadata=None):
    """
    Helper function to send alerts to the local DB for ingestion.
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
            
        if hasattr(enc_db, "insert_record_enc"):
            enc_db.insert_record_enc("events_alert", rec)
        else:
            insert_record("events_alert", rec)
    except Exception as e:
        print(f"[Alert] Failed to send alert: {e}")


def send_table(table: str):
    rows = fetch_unsent(table, limit=50)
    if not rows:
        return
    fname = f"{table}.json"
    public_ip = get_public_ip()
    data_bytes = json.dumps([dict(r) for r in rows], default=str).encode()
    fsize = len(data_bytes)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_IP, SERVER_PORT))

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

        mark_sent(table, [r['id'] for r in rows])
        if debug:
            print(f"[+] {table} sent (IP: {public_ip}, OS: {OS_INFO})")

    except Exception as e:
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


def periodic_wrapped(func, interval: int, name: str):
    while True:
        try:
            func()
        except Exception as e:
            if debug:
                print(f"[!] Error: ({name}): {e}")
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
    """Yerel DB'deki events_alert kayıtlarına göre otomatik aksiyon."""
    while True:
        try:
            stats = _soar.process_events()
            print(f"[*] SOAR cycle: events={stats.get('events_processed', 0)} "
                  f"actions={stats.get('actions_taken', 0)} "
                  f"expired_resolved={stats.get('expired_resolved', 0)} "
                  f"errors={stats.get('errors', 0)}")
        except Exception as e:
            print(f"[!] soar_events_loop error: {e}")
        time.sleep(interval_sec)



@app.get("/health")
async def health(_):
    return sanic_json({
        "agent": AGENT_NAME,
        "server": SERVER_IP,
        "ingest_port": SERVER_PORT,
        "api_base": AUTOMATIONS_API_URL,
        "automations_mode": AUTOMATIONS_MODE,
        "os": OS_INFO,
        "status": "ok"
    })


@app.post("/self_destruct")
async def self_destruct(request: Request):
    threading.Thread(target=perform_destruction, daemon=True).start()
    return sanic_json({"status": "Destruction initiated"})


@app.post("/restart")
async def restart_agent(request):
    def restart():
        old_pid = os.getpid()
        print(f"[*] Restarting agent. Old PID: {old_pid}", flush=True)

        python = sys.executable
        args = [python] + sys.argv
        env = os.environ.copy()
        env["OLD_AGENT_PID"] = str(old_pid)

        if platform.system() == "Windows":
            subprocess.Popen(args, env=env, close_fds=True)
            try:
                app.stop()
            except Exception as e:
                print(f"[!] Error stopping app: {e}", flush=True)
            time.sleep(1)
            os._exit(0)
        else:
            subprocess.Popen(args, env=env, close_fds=True)
            time.sleep(1)
            os.kill(old_pid, signal.SIGTERM)

    threading.Thread(target=restart, daemon=True).start()
    return sanic_json({"status": "Agent restart initiated"})


@app.post("/reload_auth")
async def reload_auth(_):
    try:
        fk = _bootstrap_client.get_fernet_key()  # type: ignore
        _apply_fernet_key_to_enc_db(fk)
        return sanic_json({"ok": True, "message": "Fernet key reloaded"})
    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)


def perform_destruction():
    system = platform.system().lower()
    print(f"[*] Initiating self-destruction sequence on {system}...")
    
    try:
        if system == "windows":
            cmd = "powershell -Command \"Start-Sleep -s 5; Remove-Item -Recurse -Force (Get-Item -Path .).FullName\""
            subprocess.Popen(cmd, shell=True)
        else:
            cmd = "sleep 5 && rm -rf \"$(pwd)\""
            subprocess.Popen(cmd, shell=True)
            
        print("[*] Self-destruction command dispatched. Agent will exit.")
        if platform.system() == "Windows":
            os._exit(0)
        else:
            os.kill(os.getpid(), signal.SIGKILL)
    except Exception as e:
        print(f"[!] Error during destruction: {e}")
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
    parser.add_argument('--ingest-port', type=int, default=5001,
                        help='Ingest TCP port (Default: 5001)')
    return parser.parse_args()


def _load_identity_from_config(path: str) -> dict:
    """Load agent identity (agent_name, agent_key, server_url) from JSON config."""
    with open(path, "r", encoding="utf-8-sig") as f:
        cfg = json.load(f)
    required = ("agent_name", "agent_key", "server_url")
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise ValueError(f"Config missing required keys: {missing}")
    return cfg


def _insert_soar_action_local(*, event_id: int | None, action: str, target: str,
                              comment: str | None, status: str,
                              expires_at: str | None) -> int | None:
    try:
        rec = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": event_id,
            "action": action,
            "target": target,
            "comment": (comment or "")[:500],
            "status": status.upper(),
            "resolved_at": None,
            "expires_at": expires_at,
        }
        rid = insert_record("soar_actions", rec)
        try:
            return int(rid)
        except Exception:
            return None
    except Exception:
        return None


def _accepted_auth_tokens() -> set:
    """Both the per-agent enrollment key (AGENT_SHARED_SECRET runtime
    global, set from cfg.agent_key after registration) AND the server's
    master shared secret (env AGENT_MASTER_SECRET / AGENT_SHARED_SECRET)
    are valid for inbound server→agent calls. Tracking both means the
    server doesn't need to know which mode the agent is in.
    """
    keys = set()
    if AGENT_SHARED_SECRET:
        keys.add(AGENT_SHARED_SECRET)
    for env_var in ("AGENT_MASTER_SECRET", "AGENT_SHARED_SECRET"):
        v = os.getenv(env_var, "").strip()
        if v:
            keys.add(v)
    return keys


def _is_permissive_auth() -> bool:
    """Permissive mode kicks in when the agent has its own runtime
    AGENT_SHARED_SECRET (so it knows who IT is) but the operator hasn't
    propagated the server's master shared secret to this host yet. We
    accept any non-empty header in that case and log a warning, instead
    of hard-failing every server→agent call. Setting AGENT_MASTER_SECRET
    (or AGENT_SHARED_SECRET) on this host disables this.
    """
    if not AGENT_SHARED_SECRET:
        return False
    for env_var in ("AGENT_MASTER_SECRET", "AGENT_SHARED_SECRET"):
        if os.getenv(env_var, "").strip():
            return False
    return True


def _check_auth_header(request) -> bool:
    srv_key = (request.headers.get("X-Agent-Key") or "").strip()
    accepted = _accepted_auth_tokens()
    if accepted and srv_key in accepted:
        return True
    if _is_permissive_auth() and srv_key:
        accepted_fps = sorted(k[:6] + "…" for k in accepted)
        print(
            f"[auth] permissive accept — sent={srv_key[:6]}…, "
            f"agent_known={accepted_fps}. "
            f"Set AGENT_MASTER_SECRET env on this host to enforce.",
            flush=True,
        )
        return True
    accepted_fps = sorted(k[:6] + "…" for k in accepted) if accepted else []
    srv_fp = (srv_key[:6] + "…") if srv_key else "<empty>"
    print(f"[auth] reject — sent={srv_fp}, accepted={accepted_fps}", flush=True)
    return False


@app.post("/soar/execute")
async def soar_execute(request: Request):
    if not _check_auth_header(request):
        return sanic_json({"ok": False, "error": "unauthorized"}, status=401)

    data = request.json or {}

    action_raw = data.get("action", "")
    action = str(action_raw).strip().lower()

    if not action:
        return sanic_json({"ok": False, "error": "action is required"}, status=400)

    allowed_actions = {a.value for a in ActionType}
    if action not in allowed_actions:
        return sanic_json({"ok": False, "error": f"action not implemented: {action}"}, status=501)

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
            return sanic_json({"ok": False, "error": "invalid IPv4"}, status=400)
        target_for_exec = target_str

    elif action in (ActionType.DISABLE_USER.value, ActionType.ENABLE_USER.value):
        if not UserAccountManager._is_valid_username(target_str):
            return sanic_json({"ok": False, "error": "invalid username"}, status=400)
        target_for_exec = target_str

    elif action == ActionType.RUN_CMD.value:
        if not isinstance(target_raw, list) or not target_raw:
            return sanic_json(
                {"ok": False, "error": "run_cmd target must be a non-empty list"},
                status=400,
            )
        target_for_exec = target_raw

    elif action == ActionType.KILL_PROCESS.value:
        if not target_str:
            return sanic_json({"ok": False, "error": "process target is required"}, status=400)
        target_for_exec = target_str

    elif action == ActionType.RESTART_SERVICE.value:
        if not target_str:
            return sanic_json({"ok": False, "error": "service name is required"}, status=400)
        target_for_exec = target_str

    elif action == ActionType.LOCK_MACHINE.value:
        target_for_exec = target_str or ""

    elif action == ActionType.QUARANTINE_FILE.value:
        if not target_str:
            return sanic_json({"ok": False, "error": "file path is required"}, status=400)
        target_for_exec = target_str

    elif action == ActionType.TAIL_LOG.value:
        if not target_str:
            return sanic_json({"ok": False, "error": "log path is required"}, status=400)
        target_for_exec = target_str

    else:
        return sanic_json({"ok": False, "error": f"action not implemented: {action}"}, status=501)

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

    return sanic_json(
        {
            "ok": ok,
            "message": msg or ("done" if ok else "failed"),
            "soar_action_id": soar_action_id,
            "status": status,
            "expires_at": expires_at,
        },
        status=http_status,
    )

@app.route("/config/<cfg_type>", methods=["GET"])
async def get_config(request, cfg_type):
    if not _check_auth_header(request):
        return sanic_json({"ok": False, "error": "unauthorized"}, status=401)

    mapping = {
        "rules": "conf/rules.yaml",
        "log_paths": "conf/log_paths.yaml",
        "file_scan": "conf/file_scan.yaml"
    }
    if cfg_type not in mapping:
        return sanic_json({"ok": False, "error": "invalid type"}, status=400)
    
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base_dir, mapping[cfg_type])
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return sanic_json({"ok": True, "content": content})
    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)

@app.route("/config/<cfg_type>", methods=["POST"])
async def set_config(request, cfg_type):
    if not _check_auth_header(request):
        return sanic_json({"ok": False, "error": "unauthorized"}, status=401)

    mapping = {
        "rules": "conf/rules.yaml",
        "log_paths": "conf/log_paths.yaml",
        "file_scan": "conf/file_scan.yaml"
    }
    if cfg_type not in mapping:
        return sanic_json({"ok": False, "error": "invalid type"}, status=400)

    data = request.json or {}
    content = data.get("content")
    if content is None:
        return sanic_json({"ok": False, "error": "no content"}, status=400)

    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base_dir, mapping[cfg_type])
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return sanic_json({"ok": True, "message": "Config updated successfully"})
    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)



def _ws_authorized(request) -> bool:
    """WebSocket-friendly auth: header X-Agent-Key OR query string ?key=."""
    if _check_auth_header(request):
        return True
    qkey = (request.args.get("key") or "").strip() if hasattr(request, "args") else ""
    if not qkey:
        return False
    accepted = _accepted_auth_tokens()
    if accepted and qkey in accepted:
        return True
    if _is_permissive_auth() and qkey:
        return True
    return False


@app.websocket("/screen/ws")
async def screen_stream(request, ws):
    """Continuous JPEG screen-frame stream. Browser receives binary frames and
    paints them onto an <img>. Stops automatically when the websocket closes.
    """
    if not _ws_authorized(request):
        await ws.close(code=1008, reason="unauthorized")
        return

    try:
        import mss as _mss
    except ImportError:
        await ws.send(json.dumps({"error": "mss_not_installed"}))
        await ws.close(code=1011, reason="missing dep")
        return
    try:
        from PIL import Image
        import io as _io
    except ImportError:
        await ws.send(json.dumps({"error": "pillow_not_installed"}))
        await ws.close(code=1011, reason="missing dep")
        return

    try:
        fps = max(1, min(int(request.args.get("fps", 10)), 30))
    except Exception:
        fps = 10
    try:
        quality = max(20, min(int(request.args.get("q", 60)), 95))
    except Exception:
        quality = 60
    try:
        max_width = max(320, min(int(request.args.get("w", 1280)), 2560))
    except Exception:
        max_width = 1280

    frame_interval = 1.0 / fps
    print(f"[screen] stream start fps={fps} q={quality} w={max_width}", flush=True)

    try:
        with _mss.mss() as sct:
            monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
            while True:
                t0 = asyncio.get_event_loop().time()
                shot = sct.grab(monitor)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                if img.width > max_width:
                    ratio = max_width / img.width
                    img = img.resize((max_width, int(img.height * ratio)))
                buf = _io.BytesIO()
                img.save(buf, format="JPEG", quality=quality, optimize=False)
                try:
                    await ws.send(buf.getvalue())
                except Exception:
                    break
                elapsed = asyncio.get_event_loop().time() - t0
                if elapsed < frame_interval:
                    await asyncio.sleep(frame_interval - elapsed)
    except Exception as e:
        print(f"[screen] stream error: {e}", flush=True)
    finally:
        print("[screen] stream end", flush=True)


def main():
    global AGENT_NAME, SERVER_IP, SERVER_PORT, AGENT_SHARED_SECRET, AUTOMATIONS_API_URL, AUTOMATIONS_MODE

    if hasattr(signal, 'SIGTERM'):
        try:
            signal.signal(signal.SIGTERM, handle_sigterm)
        except Exception:
            pass

    kill_old_agent_if_exists()

    # Before any work: if another agent already holds the lock, this is the
    # watchdog task firing while everything is healthy. Exit 0 so Task
    # Scheduler does not record it as a failure.
    if not acquire_single_instance_lock():
        print("[*] Another Sentora agent instance is already running — nothing to do.", flush=True)
        sys.exit(0)

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
    SERVER_PORT = int(args.ingest_port)
    AGENT_SHARED_SECRET = cfg.get("agent_key")

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

    print(f"[*] Agent Name: {AGENT_NAME}")
    print(f"[*] Server IP: {SERVER_IP}")
    print(f"[*] Ingest Port: {SERVER_PORT}")
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


@app.listener('before_server_start')
async def start_agent(app, loop):
    def start_main():
        main()
    t = threading.Thread(target=start_main, daemon=True)
    t.start()


if __name__ == "__main__":
    app.config.AUTO_RELOAD = False
    app.config.TOUCHUP = False
    import multiprocessing
    multiprocessing.freeze_support()

    app.run(
        host="0.0.0.0",
        port=9099,
        single_process=True,
        workers=1,
        access_log=False,
        auto_reload=False
    )
