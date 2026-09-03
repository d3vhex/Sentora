import os
import hashlib
import platform
import psutil
import subprocess
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional

from modules.enc_db import insert_record_enc, fetch_one_dec, update_record_enc, delete_all_enc

IS_WINDOWS = platform.system() == "Windows"

CRITICAL_FILES_TO_HASH = {
    "windows": [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
    ],
    "linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/ssh/sshd_config"
    ]
}

def get_file_hash(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error hashing {path}: {e}")
        return None

def check_fim():
    paths = CRITICAL_FILES_TO_HASH["windows"] if IS_WINDOWS else CRITICAL_FILES_TO_HASH["linux"]
    for path in paths:
        current_hash = get_file_hash(path)
        if not current_hash:
            continue
        
        
        baseline = fetch_one_dec("fim_data", where="path = %s", params=(path,))
        
        if not baseline:
            insert_record_enc("fim_data", {
                "path": path,
                "hash_sha256": current_hash,
                "status": "baseline"
            })
        elif baseline["hash_sha256"] != current_hash:
            insert_record_enc("fim_data", {
                "path": path,
                "hash_sha256": current_hash,
                "status": "changed"
            })
            from modules.enc_db import insert_record_enc as siem_insert
            siem_insert("events_alert", {
                "source": "FIM",
                "severity": "CRITICAL",
                "message": f"Integrity violation detected in {path}! Hash changed.",
                "timestamp": datetime.now().isoformat()
            })

def track_network():
    """Established outbound connections, with the process behind each.

    `psutil.net_connections` raises AccessDenied where the agent is not
    privileged enough to see other processes' sockets. That is a real
    condition worth reporting rather than an empty table: the caller isolates
    and logs it, and an operator can act on "the agent cannot read the
    connection table" in a way they cannot act on a blank page.
    """
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
            except Exception:
                # The process ended between listing and lookup, which is
                # ordinary on a busy host. The connection is still worth
                # recording.
                name = "Unknown"
            
            insert_record_enc("network_connections", {
                "pid": conn.pid,
                "process_name": name,
                "local_addr": f"{conn.laddr.ip}",
                "local_port": conn.laddr.port,
                "remote_addr": f"{conn.raddr.ip}",
                "remote_port": conn.raddr.port,
                "state": conn.status
            })

SUSPICIOUS_PARENTS = {
    "excel.exe": ["powershell.exe", "cmd.exe"],
    "winword.exe": ["powershell.exe", "cmd.exe"],
    "outlook.exe": ["powershell.exe", "cmd.exe"],
    "apache2": ["sh", "bash"],
    "nginx": ["sh", "bash"]
}

SUSPICIOUS_PATHS = [
    "c:\\perflogs\\",
    "c:\\users\\public\\",
    "c:\\windows\\temp\\",
    "/dev/shm/",
    "/tmp/",
    "/var/tmp/"
]

def monitor_processes():
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cmdline']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            ppid = pinfo['ppid']
            name = pinfo['name']
            
            if ppid > 0:
                try:
                    parent = psutil.Process(ppid)
                    parent_name = parent.name().lower()
                    if parent_name in SUSPICIOUS_PARENTS:
                        if name.lower() in SUSPICIOUS_PARENTS[parent_name]:
                            insert_record_enc("process_events", {
                                "pid": pid,
                                "ppid": ppid,
                                "name": name,
                                "cmdline": " ".join(pinfo['cmdline'] or []),
                                "username": pinfo['username'],
                                "status": "suspicious_child"
                            })
                            continue
                except Exception:
                    pass
            
            try:
                exe_path = proc.exe().lower()
                for sus_path in SUSPICIOUS_PATHS:
                    if exe_path.startswith(sus_path):
                        insert_record_enc("process_events", {
                            "pid": pid,
                            "ppid": ppid,
                            "name": name,
                            "cmdline": " ".join(pinfo['cmdline'] or []),
                            "username": pinfo['username'],
                            "status": "suspicious_path"
                        })
                        break
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

        except Exception:
            continue

def get_hardware_inventory():
    # Nothing is swallowed here any more. An empty hardware tab is
    # indistinguishable from a host with no hardware, so a collector that
    # cannot run has to say why - the console cannot infer it.
    if IS_WINDOWS:
        ps_cmd = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-PnpDevice -PresentOnly | Select-Object FriendlyName, InstanceId | ConvertTo-Json"
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding='utf-8', errors='replace')
        if res.returncode != 0:
            raise RuntimeError(
                f"Get-PnpDevice exited {res.returncode}: "
                f"{(res.stderr or '').strip()[:200]}")
        if not (res.stdout or "").strip():
            raise RuntimeError("Get-PnpDevice returned nothing")
        data = json.loads(res.stdout)
        for item in (data if isinstance(data, list) else [data]):
            if not item or not item.get("FriendlyName"):
                continue
            insert_record_enc("hardware_inventory", {
                "type": "pnp",
                "name": item.get("FriendlyName"),
                "product_id": item.get("InstanceId", "N/A"),
                "serial_number": item.get("InstanceId", "N/A"),
                "status": "active"
            })
    else:
        res = subprocess.run(["lsusb"], capture_output=True, text=True, encoding='utf-8', errors='replace')
        if res.returncode != 0:
            raise RuntimeError(
                f"lsusb exited {res.returncode}: "
                f"{(res.stderr or '').strip()[:200]}")
        for line in res.stdout.splitlines():
            if line.strip():
                insert_record_enc("hardware_inventory", {
                    "type": "usb",
                    "name": line.strip()
                })

def monitor_registry():
    if not IS_WINDOWS:
        return
    ps_cmd = "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | ConvertTo-Json"
    res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if res.returncode != 0:
        raise RuntimeError(
            f"Get-ItemProperty exited {res.returncode}: "
            f"{(res.stderr or '').strip()[:200]}")
    if not (res.stdout or "").strip():
        return                      # an empty Run key is a real answer
    data = json.loads(res.stdout)
    for k, v in data.items():
        if k not in ["PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider"]:
            insert_record_enc("registry_logs", {
                "hive": "HKLM",
                "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": k,
                "value_data": str(v),
                "status": "monitored"
            })

def main():
    """Every collector, each isolated from the others.

    They used to be five bare calls in a row, so the first one to raise took
    the rest of the cycle with it - and since the caller retries on a timer,
    it took them again every two minutes, permanently.

    That is why the console showed no hardware and no network inventory at
    the same time: `track_network` and `get_hardware_inventory` sit second and
    fourth, and something ahead of them was throwing on every pass. An empty
    table reads as "this host has nothing to report", which is the one thing
    it did not mean.

    One failing collector now costs its own data and nothing else, and says
    so. `periodic_wrapped` rate-limits the repeat, so a permanently broken
    collector is loud once rather than every two minutes forever.
    """
    for name, collector in (
        ("fim", check_fim),
        ("network", track_network),
        ("processes", monitor_processes),
        ("hardware", get_hardware_inventory),
        ("registry", monitor_registry),
    ):
        try:
            collector()
        except Exception as e:
            print(f"[edr] {name} collector failed: {type(e).__name__}: {e}",
                  flush=True)
