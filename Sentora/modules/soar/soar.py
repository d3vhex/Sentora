# -*- coding: utf-8 -*-

import platform
import re
import subprocess
import time
import logging
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import os
import shutil
from typing import Any, Dict, Optional

from modules.db import (
    insert_record,
    fetch_recent,
    fetch_one,
    fetch_where,
    update_record,
)

from modules.soar.vnc_manager import VNCManager


class ActionType(Enum):
    BLOCK_IP        = "block_ip"
    UNBLOCK_IP      = "unblock_ip"
    DISABLE_USER    = "disable_user"
    ENABLE_USER     = "enable_user"
    RUN_CMD         = "run_cmd"
    KILL_PROCESS    = "kill_process"
    RESTART_SERVICE = "restart_service"
    LOCK_MACHINE    = "lock_machine"
    ISOLATE_HOST    = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE     = "delete_file"
    TAIL_LOG        = "tail_log"
    CONTAINER_KILL  = "container_kill"
    CONTAINER_STOP  = "container_stop"
    CONTAINER_ISOLATE = "container_isolate"
    FLUSH_DNS       = "flush_dns"
    DISABLE_INTERFACE = "disable_interface"
    LOGOFF_USER     = "logoff_user"
    CLEAR_TEMP      = "clear_temp"
    DUMP_PROCESS    = "dump_process"
    SUSPEND_PROCESS = "suspend_process"
    DELETE_REGISTRY_KEY = "delete_registry_key"
    PROTECT_SHADOWS = "protect_shadows"
    START_VNC       = "start_vnc"
    STOP_VNC        = "stop_vnc"



class ActionStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PERMANENT = "permanent"
    RESOLVED = "resolved"
    RESOLVE_FAILED = "resolve_failed"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SOARConfig:
    whitelist_ips: set = field(default_factory=lambda: {"192.168.1.1", "10.0.0.5", "127.0.0.1"})
    whitelist_users: set = field(default_factory=lambda: {"admin", "root", "administrator"})
    block_ttl: int = 3600
    user_disable_ttl: int = 0
    severities_to_auto_act: set = field(default_factory=lambda: {"CRITICAL", "HIGH"})
    permanent_block_threshold: int = 5
    max_events_to_process: int = 100
    command_timeout: int = 30
    log_file: str = "soar_actions.log"
    retry_attempts: int = 3
    retry_delay: int = 2
    quarantine_dir: str = "quarantine"
    tail_default_lines: int = 100

class SOARLogger:
    def __init__(self, log_file: str = "soar_actions.log"):
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            filename=str(log_path),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger(__name__)

    def info(self, message: str) -> None:
        self.logger.info(message)

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def error(self, message: str) -> None:
        self.logger.error(message)

    def debug(self, message: str) -> None:
        self.logger.debug(message)


class SystemCommandExecutor:
    def __init__(self, logger: SOARLogger, timeout: int = 30, retry_attempts: int = 3, retry_delay: int = 2):
        self.logger = logger
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

    def execute(self, cmd: List[str], operation_desc: str = "") -> Tuple[bool, str]:
        last_error = ""

        for attempt in range(1, self.retry_attempts + 1):
            try:
                self.logger.debug(f"Executing command (attempt {attempt}/{self.retry_attempts}): {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    shell=False,
                    encoding='utf-8',
                    errors='replace',
                )

                if result.returncode == 0:
                    success_msg = result.stdout.strip() or "Command executed successfully"
                    if operation_desc:
                        self.logger.info(f"{operation_desc}: SUCCESS")
                    return True, success_msg
                else:
                    error_msg = result.stderr.strip() or result.stdout.strip() or f"Command failed with exit code {result.returncode}"
                    last_error = error_msg
                    self.logger.warning(f"{operation_desc}: Failed on attempt {attempt} - {error_msg}")

                    if attempt < self.retry_attempts:
                        time.sleep(self.retry_delay)
                        continue

                    return False, error_msg

            except subprocess.TimeoutExpired:
                last_error = f"Command timed out after {self.timeout} seconds"
                self.logger.error(f"{operation_desc}: Timeout on attempt {attempt}")
                if attempt < self.retry_attempts:
                    time.sleep(self.retry_delay)
                    continue
                return False, last_error

            except FileNotFoundError:
                last_error = f"Command not found: {cmd[0]}"
                self.logger.error(f"{operation_desc}: Command not found - {cmd[0]}")
                return False, last_error

            except Exception as exc:
                last_error = str(exc)
                self.logger.error(f"{operation_desc}: Exception on attempt {attempt} - {exc}")
                if attempt < self.retry_attempts:
                    time.sleep(self.retry_delay)
                    continue
                return False, last_error

        return False, last_error


class FirewallManager:
    def __init__(self, logger: SOARLogger, executor: SystemCommandExecutor):
        self.system = platform.system().lower()
        self.logger = logger
        self.executor = executor
        self.logger.info(f"Firewall manager initialized for platform: {self.system}")

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        if not self._is_valid_ip(ip):
            return False, f"Invalid IP address format: {ip}"

        if self.system == 'windows':
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Sentora_Block_{ip}',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ]
        elif self.system == 'linux':
            if self._check_iptables_exists():
                cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP']
            else:
                return False, "iptables not found on system"
        else:
            return False, f"Unsupported operating system: {self.system}"

        success, msg = self.executor.execute(cmd, f"Block IP {ip}")

        if success and self.system == 'linux':
            self._save_iptables_rules()

        return success, msg

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        if not self._is_valid_ip(ip):
            return False, f"Invalid IP address format: {ip}"

        if self.system == 'windows':
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name=Sentora_Block_{ip}'
            ]
        elif self.system == 'linux':
            if self._check_iptables_exists():
                cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            else:
                return False, "iptables not found on system"
        else:
            return False, f"Unsupported operating system: {self.system}"

        success, msg = self.executor.execute(cmd, f"Unblock IP {ip}")

        if success and self.system == 'linux':
            self._save_iptables_rules()

        return success, msg

    def _check_iptables_exists(self) -> bool:
        try:
            result = subprocess.run(['which', 'iptables'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def _save_iptables_rules(self) -> None:
        try:
            if Path('/etc/debian_version').exists():
                subprocess.run(['iptables-save'], capture_output=True, timeout=10)
            elif Path('/etc/redhat-release').exists():
                subprocess.run(['service', 'iptables', 'save'], capture_output=True, timeout=10)
        except Exception as exc:
            self.logger.warning(f"Failed to persist iptables rules: {exc}")

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        if not ip or not isinstance(ip, str):
            return False

        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, TypeError):
            return False


class UserAccountManager:
    def __init__(self, logger: SOARLogger, executor: SystemCommandExecutor):
        self.system = platform.system().lower()
        self.logger = logger
        self.executor = executor
        self.logger.info(f"User account manager initialized for platform: {self.system}")

    def disable_user(self, user: str) -> Tuple[bool, str]:
        if not self._is_valid_username(user):
            return False, f"Invalid username format: {user}"

        if self.system == 'windows':
            cmd = ['net', 'user', user, '/active:no']
        elif self.system == 'linux':
            cmd = ['usermod', '-L', user]
        else:
            return False, f"Unsupported operating system: {self.system}"

        return self.executor.execute(cmd, f"Disable user {user}")

    def enable_user(self, user: str) -> Tuple[bool, str]:
        if not self._is_valid_username(user):
            return False, f"Invalid username format: {user}"

        if self.system == 'windows':
            cmd = ['net', 'user', user, '/active:yes']
        elif self.system == 'linux':
            cmd = ['usermod', '-U', user]
        else:
            return False, f"Unsupported operating system: {self.system}"

        return self.executor.execute(cmd, f"Enable user {user}")

    @staticmethod
    def _is_valid_username(user: str) -> bool:
        if not user or not isinstance(user, str):
            return False
        if len(user) > 32 or len(user) < 1:
            return False
        return bool(re.match(r'^[A-Za-z0-9_.-]+$', user))


class EventParser:
    IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    USER_REGEX = re.compile(r'user(?:name)?[=:\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE)

    @classmethod
    def extract_ips(cls, text: str) -> List[str]:
        if not text:
            return []

        ips = cls.IP_REGEX.findall(text)
        valid_ips = []

        for ip in ips:
            if cls._is_valid_ip(ip) and not cls._is_reserved_ip(ip):
                valid_ips.append(ip)

        return list(set(valid_ips))

    @classmethod
    def extract_user(cls, text: str) -> Optional[str]:
        if not text:
            return None

        match = cls.USER_REGEX.search(text)
        if match:
            username = match.group(1)
            if len(username) <= 32:
                return username
        return None

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _is_reserved_ip(ip: str) -> bool:
        parts = ip.split('.')
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])

            if first_octet == 0:
                return True
            if first_octet == 127:
                return True
            if first_octet == 224 and second_octet >= 0:
                return True
            if first_octet >= 240:
                return True

            return False
        except (ValueError, IndexError):
            return True


class ActionTracker:
    def __init__(self, logger: SOARLogger):
        self.logger = logger

    def is_action_active(self, target: str, action_type: ActionType) -> bool:
        try:
            row = fetch_one(
                'soar_actions',
                where='target=%s AND action=%s AND resolved_at IS NULL',
                params=(target, action_type.value)
            )
            return row is not None
        except Exception as exc:
            self.logger.error(f"Error checking active action for {target}: {exc}")
            return False

    def get_action_history(self, target: str, action_type: ActionType) -> List[Dict[str, Any]]:
        try:
            rows = fetch_where(
                'soar_actions',
                where='target=%s AND action=%s AND status IN (%s,%s)',
                params=(target, action_type.value, ActionStatus.SUCCESS.value, ActionStatus.PERMANENT.value)
            )
            return rows if rows else []
        except Exception as exc:
            self.logger.error(f"Error fetching action history for {target}: {exc}")
            return []

    def record_action(self, event_id: int, action_type: ActionType, target: str,
                      status: ActionStatus, comment: str, expires_at: Optional[str] = None) -> bool:
        try:
            insert_record('soar_actions', {
                'timestamp': self._get_timestamp(),
                'event_id': event_id,
                'action': action_type.value,
                'target': target,
                'comment': comment[:500] if comment else '',
                'status': status.value,
                'expires_at': expires_at,
            })
            self.logger.info(f"Action recorded: {action_type.value} -> {target} [{status.value}]")
            return True
        except Exception as exc:
            self.logger.error(f"Failed to record action for {target}: {exc}")
            return False

    def is_event_processed(self, event_id: int) -> bool:
        try:
            return fetch_one('soar_actions', where='event_id=%s', params=(event_id,)) is not None
        except Exception as exc:
            self.logger.error(f"Error checking if event {event_id} is processed: {exc}")
            return False

    def update_action(self, action_id: int, status: ActionStatus, comment: str) -> bool:
        try:
            existing = fetch_one('soar_actions', where='id=%s', params=(action_id,))
            if existing:
                existing_comment = existing.get('comment', '')
                full_comment = f"{existing_comment} | {comment}" if existing_comment else comment
            else:
                full_comment = comment

            update_record(
                'soar_actions',
                {
                    'status': status.value,
                    'resolved_at': self._get_timestamp(),
                    'comment': full_comment[:500]
                },
                'id=%s',
                (action_id,)
            )
            self.logger.info(f"Action {action_id} updated to status: {status.value}")
            return True
        except Exception as exc:
            self.logger.error(f"Failed to update action {action_id}: {exc}")
            return False

    @staticmethod
    def _get_timestamp() -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S')


class SOARAutomation:
    def __init__(self, config: Optional[SOARConfig] = None):
        self.config = config or SOARConfig()
        self.logger = SOARLogger(self.config.log_file)
        self.executor = SystemCommandExecutor(
            self.logger,
            timeout=self.config.command_timeout,
            retry_attempts=self.config.retry_attempts,
            retry_delay=self.config.retry_delay
        )
        self.firewall = FirewallManager(self.logger, self.executor)
        self.user_manager = UserAccountManager(self.logger, self.executor)
        self.tracker = ActionTracker(self.logger)
        self.parser = EventParser()
        self.vnc_manager = VNCManager()
        self.system = platform.system().lower()
        self.logger.info(f"SOAR Automation initialized on {platform.system()} {platform.release()}")

    def _kill_process(self, target: str) -> Tuple[bool, str]:
        """Kill a process by PID or by name."""
        if not target:
            return False, "Empty process target"

        is_pid = False
        try:
            int(target)
            is_pid = True
        except ValueError:
            is_pid = False

        if self.system == "windows":
            if is_pid:
                cmd = ["taskkill", "/PID", str(target), "/F"]
            else:
                cmd = ["taskkill", "/IM", str(target), "/F"]
        elif self.system == "linux":
            if is_pid:
                cmd = ["kill", "-9", str(target)]
            else:
                cmd = ["pkill", "-f", str(target)]
        else:
            return False, f"Unsupported operating system for kill_process: {self.system}"

        return self.executor.execute(cmd, f"Kill process {target}")

    def _restart_service(self, service_name: str) -> Tuple[bool, str]:
        if not service_name:
            return False, "Empty service name"

        if self.system == "windows":
            cmd = [
                "powershell",
                "-Command",
                f"Restart-Service -Name '{service_name}' -Force",
            ]
        elif self.system == "linux":
            cmd = ["systemctl", "restart", service_name]
        else:
            return False, f"Unsupported operating system for restart_service: {self.system}"

        return self.executor.execute(cmd, f"Restart service {service_name}")

    def _lock_machine(self) -> Tuple[bool, str]:
        if self.system == "windows":
            cmd = ["rundll32.exe", "user32.dll,LockWorkStation"]
            return self.executor.execute(cmd, "Lock workstation")
        elif self.system == "linux":
            cmd = ["loginctl", "lock-sessions"]
            return self.executor.execute(cmd, "Lock machine sessions")
        else:
            return False, f"Unsupported operating system for lock_machine: {self.system}"

    def _isolate_host(self) -> Tuple[bool, str]:
        if self.system == "windows":
            cmd = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Disable-NetAdapter -Confirm:$false"
            ]
            return self.executor.execute(cmd, "Isolate Windows Host")
        elif self.system == "linux":
            cmd = ["iptables", "-A", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]
            success, msg = self.executor.execute(cmd, "Isolate Linux Host")
            if success:
                self._save_iptables_rules()
            return success, msg
        else:
            return False, f"Unsupported OS for isolate_host: {self.system}"

    def _delete_file(self, file_path: str) -> Tuple[bool, str]:
        if not file_path: return False, "Empty file path"
        try:
            os.remove(file_path)
            return True, f"File deleted: {file_path}"
        except Exception as e:
            return False, str(e)

    def _quarantine_file(self, file_path: str) -> Tuple[bool, str]:
        if not file_path:
            return False, "Empty file path"

        try:
            src = Path(file_path)
            if not src.is_file():
                return False, f"File not found: {file_path}"

            qdir = Path(self.config.quarantine_dir)
            qdir.mkdir(parents=True, exist_ok=True)

            ts = int(time.time())
            dest_name = f"{src.stem}_{ts}{src.suffix}"
            dest = qdir / dest_name

            shutil.move(str(src), str(dest))
            msg = f"File moved to quarantine: {dest}"
            self.logger.info(msg)
            return True, msg
        except Exception as exc:
            self.logger.error(f"Quarantine file failed for {file_path}: {exc}")
            return False, str(exc)

    def _tail_log(self, file_path: str, lines: int = 100) -> Tuple[bool, str]:
        if not file_path:
            return False, "Empty log path"

        try:
            path = Path(file_path)
            if not path.is_file():
                return False, f"Log file not found: {file_path}"

            with path.open("r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()

            if not all_lines:
                return True, "(no content)"

            tail = "".join(all_lines[-max(1, int(lines)):])
            return True, tail
        except Exception as exc:
            self.logger.error(f"tail_log failed for {file_path}: {exc}")
            return False, str(exc)

    def _container_action(self, container_id: str, action: str) -> Tuple[bool, str]:
        """
        Execute actions on Docker containers via CLI (assumes docker is installed and accessible).
        actions: kill, stop, network_disconnect
        """
        try:
            if action == "kill":
                cmd = ["docker", "kill", container_id]
            elif action == "stop":
                cmd = ["docker", "stop", container_id]
            elif action == "network_disconnect":
                inspect_cmd = ["docker", "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", container_id]
                ok, networks_str = self.executor.execute(inspect_cmd, f"Inspect container {container_id}")
                if not ok: return False, networks_str
                
                networks = networks_str.strip().split()
                if not networks: return True, f"Container {container_id} is already isolated (no networks)."
                
                for nw in networks:
                    dis_cmd = ["docker", "network", "disconnect", nw, container_id]
                    self.executor.execute(dis_cmd, f"Isolate container {container_id} from {nw}")
                return True, f"Container {container_id} disconnected from: {', '.join(networks)}"
            else:
                return False, f"Unknown container action: {action}"
                
            return self.executor.execute(cmd, f"Docker {action} on {container_id}")
        except Exception as e:
            return False, str(e)

    def _flush_dns(self) -> Tuple[bool, str]:
        if self.system == "windows":
            cmd = ["ipconfig", "/flushdns"]
        elif self.system == "linux":
            cmd = ["systemd-resolve", "--flush-caches"]
        else:
            return False, f"Unsupported OS for flush_dns: {self.system}"
        return self.executor.execute(cmd, "Flush DNS Cache")

    def _disable_interface(self, interface_name: str) -> Tuple[bool, str]:
        if not interface_name:
            return False, "Interface name required"
        
        if self.system == "windows":
            cmd = ["powershell", "-Command", f"Disable-NetAdapter -Name '{interface_name}' -Confirm:$false"]
        elif self.system == "linux":
            cmd = ["ip", "link", "set", interface_name, "down"]
        else:
            return False, f"Unsupported OS for disable_interface: {self.system}"
        return self.executor.execute(cmd, f"Disable interface {interface_name}")

    def _logoff_user(self, target_user: str) -> Tuple[bool, str]:
        if not target_user:
            return False, "Target user required"

        if self.system == "windows":
            cmd = ["powershell", "-Command", f"$session = (quser | Where-Object {{$_ -match '{target_user}'}} | ForEach-Object {{($_ -split ' +')[2]}}); if ($session) {{ logoff $session }} else {{ throw 'Session not found for {target_user}' }}"]
        elif self.system == "linux":
            cmd = ["pkill", "-u", target_user]
        else:
            return False, f"Unsupported OS for logoff_user: {self.system}"
        return self.executor.execute(cmd, f"Logoff user {target_user}")

    def _clear_temp(self) -> Tuple[bool, str]:
        try:
            if self.system == "windows":
                temp_path = Path(os.path.expandvars(r"%TEMP%"))
            else:
                temp_path = Path("/tmp")

            if not temp_path.exists():
                return True, f"Temp directory does not exist: {temp_path}"

            deleted_count = 0
            for item in temp_path.iterdir():
                try:
                    if item.is_file() or item.is_symlink():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                    deleted_count += 1
                except Exception:
                    pass
            
            return True, f"Cleared {deleted_count} items from {temp_path}"
        except Exception as e:
            return False, f"Failed to clear temp: {str(e)}"

    def _dump_process(self, target_pid: str) -> Tuple[bool, str]:
        if not target_pid:
            return False, "Target PID required"
            
        qdir = Path(self.config.quarantine_dir)
        qdir.mkdir(parents=True, exist_ok=True)
        dump_file = str(qdir / f"memdump_{target_pid}_{int(time.time())}.dmp")

        if self.system == "windows":
            cmd = ["procdump.exe", "-accepteula", "-ma", str(target_pid), dump_file]
        elif self.system == "linux":
            cmd = ["gcore", "-o", dump_file, str(target_pid)]
        else:
            return False, f"Unsupported OS for dump_process: {self.system}"
            
        ok, msg = self.executor.execute(cmd, f"Dump process {target_pid}")
        if ok:
            return True, f"Memory dump initiated to {qdir}"
        return False, f"Failed to dump process (requires procdump/gcore): {msg}"

    def _suspend_process(self, target_pid: str) -> Tuple[bool, str]:
        if not target_pid: return False, "Target PID required"
        if self.system == "windows":
            ps_script = (
                "$code = @\"\n"
                "using System;\n"
                "using System.Runtime.InteropServices;\n"
                "public class PSH {\n"
                "    [DllImport(\"ntdll.dll\")] public static extern int NtSuspendProcess(IntPtr processHandle);\n"
                "}\n"
                "\"@;\n"
                "Add-Type -TypeDefinition $code;\n"
                f"$p = Get-Process -Id {target_pid} -ErrorAction Stop;\n"
                "[PSH]::NtSuspendProcess($p.Handle);"
            )
            cmd = ["powershell", "-NoProfile", "-Command", ps_script]
        elif self.system == "linux":
            cmd = ["kill", "-STOP", str(target_pid)]
        else:
            return False, f"Unsupported OS for suspend_process: {self.system}"
        return self.executor.execute(cmd, f"Suspend process {target_pid}")

    def _delete_registry_key(self, reg_path: str) -> Tuple[bool, str]:
        if not reg_path: return False, "Registry path required"
        if self.system == "windows":
            cmd = f'reg delete "{reg_path}" /f'
            return self.executor.execute(cmd.split(), f"Delete Registry Key: {reg_path}")
        return False, "delete_registry_key is only supported on Windows."

    def _protect_shadows(self) -> Tuple[bool, str]:
        if self.system == "windows":
            cmd = ["icacls", r"C:\Windows\System32\vssadmin.exe", "/deny", "Everyone:(X)"]
            return self.executor.execute(cmd, "Protect Volume Shadow Copies")
        return False, "protect_shadows is only supported on Windows."

    def exec_action(
        self,
        action: str,
        target: Any,
        comment: str = "",
        event_id: Optional[int] = None,
        ttl: Optional[int] = None,
        force: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        a = (action or "").strip().lower()
        expires_at: Optional[str] = None

        if a == ActionType.BLOCK_IP.value:
            if not force and self.tracker.is_action_active(str(target), ActionType.BLOCK_IP):
                return True, "Already blocked (skipped)", None
            ok, msg = self.firewall.block_ip(str(target))
            if ok:
                ttl_eff = int(ttl) if (ttl not in (None, "")) else int(self.config.block_ttl)
                expires_at = self._calculate_expiration(ttl_eff) if ttl_eff > 0 else None
                self.tracker.record_action(int(event_id or 0), ActionType.BLOCK_IP, str(target),
                                           ActionStatus.SUCCESS, comment or msg, expires_at)
            else:
                self.tracker.record_action(int(event_id or 0), ActionType.BLOCK_IP, str(target),
                                           ActionStatus.FAILED, comment or msg, None)
            return ok, msg, expires_at

        if a == ActionType.UNBLOCK_IP.value:
            ok, msg = self.firewall.unblock_ip(str(target))
            status = ActionStatus.RESOLVED if ok else ActionStatus.RESOLVE_FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.BLOCK_IP, str(target),
                                       status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.DISABLE_USER.value:
            if not force and self.tracker.is_action_active(str(target), ActionType.DISABLE_USER):
                return True, "Already disabled (skipped)", None
            ok, msg = self.user_manager.disable_user(str(target))
            if ok:
                ttl_eff = int(ttl) if (ttl not in (None, "")) else int(self.config.user_disable_ttl)
                expires_at = self._calculate_expiration(ttl_eff) if (ttl_eff and ttl_eff > 0) else None
                self.tracker.record_action(int(event_id or 0), ActionType.DISABLE_USER, str(target),
                                           ActionStatus.SUCCESS, comment or msg, expires_at)
            else:
                self.tracker.record_action(int(event_id or 0), ActionType.DISABLE_USER, str(target),
                                           ActionStatus.FAILED, comment or msg, None)
            return ok, msg, expires_at

        if a == ActionType.ENABLE_USER.value:
            ok, msg = self.user_manager.enable_user(str(target))
            status = ActionStatus.RESOLVED if ok else ActionStatus.RESOLVE_FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.DISABLE_USER, str(target),
                                       status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.KILL_PROCESS.value:
            ok, msg = self._kill_process(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(
                int(event_id or 0),
                ActionType.KILL_PROCESS,
                str(target),
                status,
                comment or msg,
                None,
            )
            return ok, msg, None

        if a == ActionType.RESTART_SERVICE.value:
            ok, msg = self._restart_service(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(
                int(event_id or 0),
                ActionType.RESTART_SERVICE,
                str(target),
                status,
                comment or msg,
                None,
            )
            return ok, msg, None

        if a == ActionType.LOCK_MACHINE.value:
            ok, msg = self._lock_machine()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(
                int(event_id or 0),
                ActionType.LOCK_MACHINE,
                str(target or ""),
                status,
                comment or msg,
                None,
            )
            return ok, msg, None

        if a == "isolate_host":
            ok, msg = self._isolate_host()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.LOCK_MACHINE, "SELF", status, comment or msg, None)
            return ok, msg, None

        if a == "delete_file":
            ok, msg = self._delete_file(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.QUARANTINE_FILE, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.QUARANTINE_FILE.value:
            ok, msg = self._quarantine_file(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(
                int(event_id or 0),
                ActionType.QUARANTINE_FILE,
                str(target),
                status,
                comment or msg,
                None,
            )
            return ok, msg, None

        if a == ActionType.TAIL_LOG.value:
            ok, msg = self._tail_log(str(target), self.config.tail_default_lines)
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(
                int(event_id or 0),
                ActionType.TAIL_LOG,
                str(target),
                status,
                comment or msg,
                None,
            )
            return ok, msg, None

        if a == ActionType.CONTAINER_KILL.value:
            ok, msg = self._container_action(str(target), "kill")
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.CONTAINER_KILL, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.CONTAINER_STOP.value:
            ok, msg = self._container_action(str(target), "stop")
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.CONTAINER_STOP, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.CONTAINER_ISOLATE.value:
            ok, msg = self._container_action(str(target), "network_disconnect")
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.CONTAINER_ISOLATE, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.FLUSH_DNS.value:
            ok, msg = self._flush_dns()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.FLUSH_DNS, "SELF", status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.DISABLE_INTERFACE.value:
            ok, msg = self._disable_interface(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.DISABLE_INTERFACE, str(target), status, comment or msg, None)
            return ok, msg, None
            
        if a == ActionType.LOGOFF_USER.value:
            ok, msg = self._logoff_user(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.LOGOFF_USER, str(target), status, comment or msg, None)
            return ok, msg, None
            
        if a == ActionType.CLEAR_TEMP.value:
            ok, msg = self._clear_temp()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.CLEAR_TEMP, "SYSTEM", status, comment or msg, None)
            return ok, msg, None
            
        if a == ActionType.DUMP_PROCESS.value:
            ok, msg = self._dump_process(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.DUMP_PROCESS, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.CONTAINER_ISOLATE.value:
            ok, msg = self._container_action(str(target), "network_disconnect")
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.CONTAINER_ISOLATE, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.SUSPEND_PROCESS.value:
            ok, msg = self._suspend_process(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.SUSPEND_PROCESS, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.DELETE_REGISTRY_KEY.value:
            ok, msg = self._delete_registry_key(str(target))
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.DELETE_REGISTRY_KEY, str(target), status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.PROTECT_SHADOWS.value:
            ok, msg = self._protect_shadows()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.PROTECT_SHADOWS, "SYSTEM", status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.START_VNC.value:
            ok, msg = self.vnc_manager.start_vnc()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.START_VNC, "SYSTEM", status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.STOP_VNC.value:
            ok, msg = self.vnc_manager.stop_vnc()
            status = ActionStatus.SUCCESS if ok else ActionStatus.FAILED
            self.tracker.record_action(int(event_id or 0), ActionType.STOP_VNC, "SYSTEM", status, comment or msg, None)
            return ok, msg, None

        if a == ActionType.RUN_CMD.value:
            if not isinstance(target, list) or not target:
                return False, "RUN_CMD target must be a list", None
            ok, msg = self.executor.execute(target, "Run cmd")
            return ok, msg, None

        return False, f"Unsupported action: {action}", None
    
    def process_due_automations(self, agent_name: str, max_batch: int = 25) -> Dict[str, int]:
        stats = {"leased": 0, "executed": 0, "ok": 0, "failed": 0}
        try:
            rows = fetch_where(
                "automations",
                where="device=%s AND status IN ('pending','active')",
                params=(agent_name,)
            ) or []
        except Exception as e:
            self.logger.error(f"automations fetch failed: {e}")
            return stats

        if not rows:
            return stats

        rows = sorted(rows, key=lambda r: (str(r.get("timestamp") or ""), int(r.get("id") or 0)))
        batch = rows[:max_batch]
        stats["leased"] = len(batch)

        for it in batch:
            aid = int(it.get("id") or 0)
            try:
                update_record("automations", {"status": "active"}, "id=%s", (aid,))
            except Exception as e:
                self.logger.error(f"automation {aid} lease->active failed: {e}")
                continue

            try:
                action  = str(it.get("action") or "").lower().strip()
                target  = it.get("target")
                comment = (it.get("comment") or "").strip()
                event_id= it.get("event_id")
                ok, msg, _exp = self.exec_action(action, target, comment=comment, event_id=event_id)
                stats["executed"] += 1
                if ok:
                    stats["ok"] += 1
                    update_record("automations", {"status": "completed", "comment": f"{comment} | OK: {msg}"[:500]}, "id=%s", (aid,))
                else:
                    stats["failed"] += 1
                    update_record("automations", {"status": "failed", "comment": f"{comment} | ERR: {msg}"[:500]}, "id=%s", (aid,))
            except Exception as e:
                stats["failed"] += 1
                try:
                    update_record("automations", {"status": "failed", "comment": f"EXC: {e}"[:500]}, "id=%s", (aid,))
                except Exception:
                    pass

        return stats

    def resolve_expired_actions(self) -> int:
        now = self._get_timestamp()

        try:
            expired_actions = fetch_where(
                'soar_actions',
                where='expires_at <= %s AND expires_at IS NOT NULL AND resolved_at IS NULL',
                params=(now,)
            )
        except Exception as exc:
            self.logger.error(f"Failed to fetch expired actions: {exc}")
            return 0

        if not expired_actions:
            return 0

        self.logger.info(f"Processing {len(expired_actions)} expired actions")
        resolved_count = 0

        for action in expired_actions:
            action_id = action.get('id')
            action_type = action.get('action')
            target = action.get('target')

            if not all([action_id, action_type, target]):
                continue

            success, msg = self._reverse_action(action_type, target)
            status = ActionStatus.RESOLVED if success else ActionStatus.RESOLVE_FAILED

            if self.tracker.update_action(action_id, status, f"Auto-reverted: {msg}"):
                resolved_count += 1

        self.logger.info(f"Successfully resolved {resolved_count}/{len(expired_actions)} expired actions")
        return resolved_count

    def _reverse_action(self, action_type: str, target: str) -> Tuple[bool, str]:
        try:
            if action_type == ActionType.BLOCK_IP.value:
                return self.firewall.unblock_ip(target)
            elif action_type == ActionType.DISABLE_USER.value:
                return self.user_manager.enable_user(target)
            else:
                return True, "Unknown action type"
        except Exception as exc:
            self.logger.error(f"Exception during action reversal: {exc}")
            return False, str(exc)

    def process_ip_threats(self, event_id: int, ips: List[str], severity: str) -> List[str]:
        actions_taken = []

        for ip in ips:
            if ip in self.config.whitelist_ips:
                self.logger.info(f"Skipping whitelisted IP: {ip}")
                continue

            if self.tracker.is_action_active(ip, ActionType.BLOCK_IP):
                self.logger.debug(f"IP {ip} already blocked")
                continue

            history = self.tracker.get_action_history(ip, ActionType.BLOCK_IP)
            block_count = len(history)
            permanent = block_count >= self.config.permanent_block_threshold

            if permanent:
                self.logger.warning(f"IP {ip} exceeded threshold ({block_count} blocks), applying permanent block")

            success, msg = self.firewall.block_ip(ip)

            if permanent:
                status = ActionStatus.PERMANENT
                expires_at = None
            else:
                status = ActionStatus.SUCCESS if success else ActionStatus.FAILED
                expires_at = self._calculate_expiration(self.config.block_ttl) if success else None

            comment = f"{severity} alert | {msg}"
            self.tracker.record_action(event_id, ActionType.BLOCK_IP, ip, status, comment, expires_at)

            label = f"block_ip:{ip}"
            if permanent:
                label += " [PERMANENT]"
            elif expires_at:
                label += f" [expires: {expires_at}]"

            actions_taken.append(label)

        return actions_taken

    def process_user_threats(self, event_id: int, user: Optional[str], severity: str) -> List[str]:
        actions_taken = []

        if not user:
            return actions_taken

        if user in self.config.whitelist_users:
            self.logger.info(f"Skipping whitelisted user: {user}")
            return actions_taken

        if self.tracker.is_action_active(user, ActionType.DISABLE_USER):
            self.logger.debug(f"User {user} already disabled")
            return actions_taken

        success, msg = self.user_manager.disable_user(user)
        status = ActionStatus.SUCCESS if success else ActionStatus.FAILED

        expires_at = None
        if success and self.config.user_disable_ttl > 0:
            expires_at = self._calculate_expiration(self.config.user_disable_ttl)

        comment = f"{severity} alert | {msg}"
        self.tracker.record_action(event_id, ActionType.DISABLE_USER, user, status, comment, expires_at)

        label = f"disable_user:{user}"
        if expires_at:
            label += f" [expires: {expires_at}]"

        actions_taken.append(label)
        return actions_taken

    def process_events(self) -> Dict[str, int]:
        # This cycle runs every ~30s and used to emit four lines plus two
        # 60-character rules every time, whether or not anything happened:
        # about 7400 lines in thirteen hours saying "nothing happened". The
        # summary at the end now carries the same information, and only when
        # there is some.
        self.logger.debug("Starting SOAR event processing cycle")

        stats = {
            'expired_resolved': 0,
            'events_processed': 0,
            'actions_taken': 0,
            'errors': 0
        }

        stats['expired_resolved'] = self.resolve_expired_actions()

        try:
            events = fetch_recent('events_alert', limit=self.config.max_events_to_process)
        except Exception as exc:
            self.logger.error(f"Failed to fetch events: {exc}")
            stats['errors'] += 1
            return stats

        if not events:
            self.logger.info("No events to process")
            return stats

        # debug: one line per cycle saying "Retrieved 0 events" 1487 times
        # in thirteen hours is not information.
        self.logger.debug(f"Retrieved {len(events)} events for processing")

        for event in reversed(events):
            try:
                event_id = event.get('id')
                severity = str(event.get('severity', '')).upper()
                message = event.get('message', '') or ''

                if not event_id:
                    continue

                if severity not in self.config.severities_to_auto_act:
                    continue

                if self.tracker.is_event_processed(event_id):
                    continue

                ips = self.parser.extract_ips(message)
                user = self.parser.extract_user(message)

                if not ips and not user:
                    continue

                actions = []
                actions.extend(self.process_ip_threats(event_id, ips, severity))
                actions.extend(self.process_user_threats(event_id, user, severity))

                if actions:
                    stats['events_processed'] += 1
                    stats['actions_taken'] += len(actions)
                    self.logger.info(f"Event {event_id} [{severity}]: {', '.join(actions)}")

            except Exception as exc:
                self.logger.error(f"Error processing event {event.get('id', 'unknown')}: {exc}")
                stats['errors'] += 1

        # Only when the cycle did something. An idle cycle is the normal case
        # and saying so repeatedly buries the cycles that are not idle.
        if stats['events_processed'] or stats['actions_taken'] or stats['errors']:
            self.logger.info(
                f"SOAR cycle: {stats['events_processed']} events, "
                f"{stats['actions_taken']} actions, {stats['errors']} errors")
        else:
            self.logger.debug("SOAR cycle: idle")

        return stats

    def _calculate_expiration(self, ttl_seconds: int) -> str:
        expiration_time = time.time() + ttl_seconds
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiration_time))

    @staticmethod
    def _get_timestamp() -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S')


def main() -> None:
    """Scan the local events_alert table and take the actions it calls for."""
    try:
        config = SOARConfig()
        soar = SOARAutomation(config)
        stats = soar.process_events()

        print("SOAR Automation completed:")
        print(f"  - Events processed: {stats['events_processed']}")
        print(f"  - Actions taken: {stats['actions_taken']}")
        print(f"  - Expired actions resolved: {stats['expired_resolved']}")
        print(f"  - Errors encountered: {stats['errors']}")

    except Exception as exc:
        print(f"SOAR Automation failed: {exc}")
        logging.error(f"Critical error in main: {exc}")
        raise




def get_action_catalog() -> Dict[str, Dict[str, Any]]:
    """The action catalogue the playbook editor renders from.

    Returns metadata only - it knows nothing about HTTP or the web framework,
    which is what lets the same catalogue serve the API and the agent.
    """
    return {
        ActionType.BLOCK_IP.value: {
            "label": "Block IP",
            "description": "Block incoming traffic from a remote IP using the local firewall.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "192.168.1.100"},
                {"name": "ttl", "type": "integer", "required": False, "description": "TTL in seconds (0 = default / permanent)"},
                {"name": "comment", "type": "string", "required": False},
                {"name": "force", "type": "boolean", "required": False},
            ],
        },
        ActionType.UNBLOCK_IP.value: {
            "label": "Unblock IP",
            "description": "Remove previously added firewall block rule for an IP.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "192.168.1.100"},
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.DISABLE_USER.value: {
            "label": "Disable User",
            "description": "Disable a local user account on this host.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "suspicious.user"},
                {"name": "ttl", "type": "integer", "required": False, "description": "TTL in seconds (0 = default / permanent)"},
                {"name": "comment", "type": "string", "required": False},
                {"name": "force", "type": "boolean", "required": False},
            ],
        },
        ActionType.ENABLE_USER.value: {
            "label": "Enable User",
            "description": "Re-enable a previously disabled user account.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "suspicious.user"},
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.KILL_PROCESS.value: {
            "label": "Kill Process",
            "description": "Kill a process by PID or name.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "1234 or python3"},
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.RESTART_SERVICE.value: {
            "label": "Restart Service",
            "description": "Restart a system service (systemd / Windows service).",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "sshd"},
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.LOCK_MACHINE.value: {
            "label": "Lock Machine",
            "description": "Lock the active user sessions on this host.",
            "fields": [
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.QUARANTINE_FILE.value: {
            "label": "Quarantine File",
            "description": "Move a suspicious file into the local quarantine directory.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "C:\\malware.exe or /tmp/mal"},
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.TAIL_LOG.value: {
            "label": "Tail Log",
            "description": "Return last N lines from a log file.",
            "fields": [
                {"name": "target", "type": "string", "required": True, "example": "/var/log/auth.log"},
                {"name": "comment", "type": "string", "required": False},
            ],
        },
        ActionType.RUN_CMD.value: {
            "label": "Run Command",
            "description": "Execute a local system command on this host.",
            "fields": [
                {
                    "name": "target",
                    "type": "string_or_list",
                    "required": True,
                    "example": "whoami or ['bash', '-c', 'id']",
                    "note": "If string is given, it will be split by spaces."
                },
                {"name": "comment", "type": "string", "required": False},
            ],
        },
    }


def _normalize_run_cmd_target(raw: Any) -> List[str]:
    """Normalise a RUN_CMD target into an argument list.

    A list is cast to strings and emptied of blanks; a string is split on
    whitespace.
    """
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x).strip()]
    if isinstance(raw, str):
        parts = raw.strip().split()
        return [p for p in parts if p]
    return []


def execute_action_from_payload(
    payload: Dict[str, Any],
    config: Optional[SOARConfig] = None,
    soar_obj: Optional[SOARAutomation] = None,
) -> Dict[str, Any]:
    """Run one SOAR action from an API payload.

    Expected shape:
        {
          "action": "block_ip",
          "target": "1.2.3.4",
          "comment": "manual block from SOAR UI",
          "ttl": 3600,         # optional
          "force": false,      # optional
          "event_id": 123      # optional
        }

    Returns a plain dict for the caller to serialise, so this stays
    independent of the web framework in front of it.
    """
    action = str(payload.get("action", "")).strip().lower()
    if not action:
        return {"ok": False, "error": "Missing 'action' in payload"}

    target = payload.get("target")
    comment = str(payload.get("comment") or "")
    ttl = payload.get("ttl")
    force = bool(payload.get("force") or False)

    event_id_raw = payload.get("event_id")
    event_id: Optional[int]
    try:
        event_id = int(event_id_raw) if event_id_raw not in (None, "") else None
    except (ValueError, TypeError):
        event_id = None

    if action == ActionType.RUN_CMD.value:
        target = _normalize_run_cmd_target(target)

    soar = soar_obj or SOARAutomation(config or SOARConfig())
    ok, msg, expires_at = soar.exec_action(
        action=action,
        target=target,
        comment=comment,
        event_id=event_id,
        ttl=ttl,
        force=force,
    )

    return {
        "ok": bool(ok),
        "message": msg,
        "expires_at": expires_at,
        "action": action,
        "target": target,
        "event_id": event_id,
    }


def run_pending_automations_for_device(
    device: str,
    max_batch: int = 25,
    config: Optional[SOARConfig] = None,
    soar_obj: Optional[SOARAutomation] = None,
) -> Dict[str, Any]:

    if not device:
        return {
            "device": device,
            "leased": 0,
            "executed": 0,
            "ok": 0,
            "failed": 0,
            "error": "device is required",
        }

    soar = soar_obj or SOARAutomation(config or SOARConfig())
    stats = soar.process_due_automations(agent_name=device, max_batch=max_batch)
    stats["device"] = device
    return stats



__all__ = [
    "SOARConfig",
    "SOARLogger",
    "SystemCommandExecutor",
    "FirewallManager",
    "UserAccountManager",
    "EventParser",
    "ActionTracker",
    "SOARAutomation",
    "ActionType",
    "ActionStatus",
    "Severity",
    "main",
    "get_action_catalog",
    "execute_action_from_payload",
    "run_pending_automations_for_device",
]
