from sanic import Sanic
import bcrypt
import aiomysql
import secrets
import os, pathlib
import stat
import time
from enum import Enum
import re
from sanic_cors import CORS
from sanic.response import json, file, HTTPResponse
import multiprocessing
import json as pyjson
from mysql.connector.aio import connect 
import mysql.connector
from datetime import datetime
from time import sleep
import core.opensearch as os_utils
import smtplib
from email.message import EmailMessage
from typing import List, Any
from pydantic import BaseModel, EmailStr, constr, Field, field_validator
from typing import Optional, List

class LoginRequest(BaseModel):
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=6)

class CreateUserRequest(BaseModel):
    username: constr(min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    password: constr(min_length=8)
    role: str = "user"

    @field_validator('password')
    @classmethod
    def password_complexity(cls, v: str):
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one number')
        return v

class CreateRoleRequest(BaseModel):
    role_name: constr(min_length=2, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    permissions: List[str] = []

class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: constr(min_length=8)

    @field_validator('new_password')
    @classmethod
    def password_complexity(cls, v: str):
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one number')
        return v

import asyncio
import hashlib
import requests
import textwrap
from sanic.exceptions import SanicException
import subprocess
from functools import wraps
from sanic.response import json as sanic_json
import ldap3
from sanic import response
from ldap3 import Server, Connection, ALL, Tls
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPBindError
import ssl
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv, set_key, dotenv_values
 
ENC_PREFIX = "enc::"
ENV_PATH = pathlib.Path(".env")

if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)

CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
# A credentialed request cannot use a wildcard origin: the browser rejects
# `Access-Control-Allow-Origin: *` outright whenever cookies are attached. In
# the normal deployment this app serves the SPA itself, so requests are
# same-origin and no CORS entry is needed at all — hence the empty default.
if "*" in CORS_ORIGINS:
    print("[!] CORS_ORIGINS='*' is incompatible with cookie authentication and was ignored. "
          "List explicit origins if the UI is served from a different host.")
    CORS_ORIGINS = [o for o in CORS_ORIGINS if o != "*"]
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "my-secret-pw")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

multiprocessing.freeze_support()
app = Sanic("SIEMLoggerAPI")
app.config.RESPONSE_TIMEOUT = 600
app.config.REQUEST_TIMEOUT = 600
app.config.WORKER_ACK_TIMEOUT = 60.0
CORS(app, origins=CORS_ORIGINS, supports_credentials=True)

app.static("/assets", "./frontend/dist/assets", name="frontend_assets")
app.static("/vite.svg", "./frontend/dist/vite.svg", name="frontend_logo")

from ai.utils import load_ai_config, is_critical_log, save_ai_results
from security import session as session_store
from security import ssrf
from core import config_validation
from core import threat_feeds

# Cookies are only marked Secure when the platform is actually served over
# TLS; a Secure cookie on a plain-http lab deployment is silently dropped by
# the browser and nobody can log in. Set SESSION_COOKIE_SECURE=1 in .env once
# you terminate TLS in front of the app.
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0").lower() in ("1", "true", "yes", "on")

# 'Lax' blocks the cookie on cross-site POST/XHR, which is the CSRF case that
# matters, while staying compatible with normal same-origin use. 'Strict' is
# available for deployments that want it; 'None' requires Secure and exists
# only for split-origin setups.
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax").strip().capitalize()
if SESSION_COOKIE_SAMESITE not in ("Lax", "Strict", "None"):
    print(f"[!] Invalid SESSION_COOKIE_SAMESITE={SESSION_COOKIE_SAMESITE!r}; falling back to 'Lax'.")
    SESSION_COOKIE_SAMESITE = "Lax"

AGENT_SHARED_SECRET = os.getenv("AGENT_SHARED_SECRET", "") or os.getenv("AGENT_SHARED_SECRET", "")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434/api")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

if not AGENT_SHARED_SECRET:
    AGENT_SHARED_SECRET = secrets.token_urlsafe(32)
    print("[+] Generated ephemeral agent shared secret (set AGENT_SHARED_SECRET in .env to override).")

ENCRYPTED_FIELDS_MAP = {
    "siem_events": ["source", "timestamp", "message"],
    "critical_files": ["path", "owner", "grp", "permissions", "last_opened"],
    "packages": ["package", "version"],
    "vulnerabilities_report": ["package_name", "package_version", "vulnerability_id", "summary", "details_url"],
    "events_alert": ["source", "timestamp", "severity", "score", "categories", "message"],
    "soar_actions": ["timestamp", "action", "target", "comment", "status"],
    "fim_data": ["path", "hash_sha256"],
    "registry_logs": ["hive", "key_path", "value_name", "value_data"],
    "network_connections": ["process_name", "local_addr", "remote_addr"],
    "process_events": ["name", "cmdline", "username"],
    "hardware_inventory": ["name", "serial_number"],
    "security_audit": ["finding", "details"]
}


async def init_hub_db():
    """
    Ensures that the sentora_hub database and its global tables exist.
    """
    try:
        with sync_mysql_conn() as conn:
            cur = conn.cursor()
            try:
                cur.execute("CREATE DATABASE IF NOT EXISTS sentora_hub")
                cur.execute("USE sentora_hub")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS hardware_inventory (
                        id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        type         VARCHAR(64),
                        name         VARCHAR(255),
                        vendor_id    VARCHAR(128),
                        product_id   VARCHAR(128),
                        serial_number VARCHAR(128),
                        status       VARCHAR(32),
                        `timestamp`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        sent         TINYINT(1) DEFAULT 0,
                        dup_fp       CHAR(64) NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intel (
                        id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        type        VARCHAR(32),
                        value       VARCHAR(255) NOT NULL,
                        source      VARCHAR(128),
                        severity    VARCHAR(16),
                        description TEXT,
                        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE KEY uniq_intel (type, value)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)

                conn.commit()
            finally:
                cur.close()
        print("[HubDB] Central database 'sentora_hub' initialized successfully.")
    except Exception as e:
        print(f"[HubDB] Error initializing central database: {e}")

async def init_enrollment_tables():
    """Ensure enrollment_tokens + agent_identities exist in userdb (idempotent migration)."""
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS enrollment_tokens (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        token CHAR(64) NOT NULL UNIQUE,
                        created_by_user_id INT,
                        created_by_username VARCHAR(100),
                        hostname_hint VARCHAR(255),
                        note VARCHAR(500),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        expires_at DATETIME NOT NULL,
                        used_at DATETIME NULL,
                        used_by_agent VARCHAR(128) NULL,
                        used_from_ip VARCHAR(45) NULL,
                        INDEX idx_expires (expires_at),
                        INDEX idx_used (used_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS agent_identities (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        agent_name VARCHAR(128) NOT NULL UNIQUE,
                        agent_key CHAR(64) NOT NULL UNIQUE,
                        os_type VARCHAR(32),
                        hostname VARCHAR(255),
                        enrolled_from_ip VARCHAR(45),
                        enrolled_via_token CHAR(64),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME NULL,
                        revoked_at DATETIME NULL,
                        INDEX idx_agent_name (agent_name),
                        INDEX idx_revoked (revoked_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                conn.commit()
            finally:
                cur.close()
        print("[Enrollment] Tables ready in userdb.")
    except Exception as e:
        print(f"[Enrollment] Error initializing tables: {e}")

async def init_email_templates_table():
    """Ensure `email_templates` exists in userdb (idempotent migration).

    `send_email` and `/<agent>/notifications/templates` both query this table,
    but init_userdb.sql never created it — so every templated alert mail failed
    at the SELECT and the notifications endpoint returned a 500. Columns match
    what send_email reads: template_name, subject_template, body_template.
    """
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS email_templates (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        template_name VARCHAR(255) NOT NULL UNIQUE,
                        subject_template TEXT NOT NULL,
                        body_template TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                # `dispatch_critical_alerts` looks up a per-agent template name
                # ("Critical Alerts - Agent: WIN-01"), so without this generic
                # fallback an operator would have to create one row per
                # enrolled endpoint before any alert mail went out — with a log
                # line as the only symptom of not having done so.
                cur.execute("""
                    INSERT IGNORE INTO email_templates
                        (template_name, subject_template, body_template)
                    VALUES (%s, %s, %s)
                """, (
                    DEFAULT_ALERT_TEMPLATE,
                    "[Sentora] Critical alerts on {{agent}}",
                    "Agent: {{agent}}\n\n{{body}}\n\n-- Sentora",
                ))
                conn.commit()
            finally:
                cur.close()
        print("[Email] Templates table ready in userdb.")
    except Exception as e:
        print(f"[Email] Error initializing templates table: {e}")


async def init_session_table():
    """Ensure the `sessions` table exists in userdb (idempotent migration)."""
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute(session_store.CREATE_TABLE_SQL)
                conn.commit()
            finally:
                cur.close()
        print("[Session] Table ready in userdb.")
    except Exception as e:
        print(f"[Session] Error initializing table: {e}")

@app.listener("main_process_start")
async def setup_hub(app):
    await init_hub_db()
    await init_enrollment_tables()
    await init_session_table()
    await init_email_templates_table()


def is_soar_enabled() -> bool:
    """Community edition: SOAR is unconditionally enabled."""
    return True


def _soar_block_response():
    """Legacy guard return — never fires in Community edition because
    is_soar_enabled() always returns True. Kept so existing call sites that
    `if not is_soar_enabled(): return _soar_block_response()` stay valid."""
    return sanic_json(
        {"status": "error", "message": "SOAR unavailable"},
        status=503,
    )


AUTOMATION_ALLOWED_ACTIONS = {
    "block_ip",
    "unblock_ip",
    "disable_user",
    "enable_user",
    "kill_process",
    "restart_service",
    "lock_machine",
    "quarantine_file",
    "tail_log",
    "run_cmd",
    "flush_dns",
    "disable_interface",
    "logoff_user",
    "clear_temp",
    "dump_process",
    "container_kill",
    "container_stop",
    "container_isolate",
    "suspend_process",
    "delete_registry_key",
    "protect_shadows",
    "start_vnc",
    "stop_vnc"
}
AUTOMATION_ALLOWED_STATUSES = {"pending", "active", "paused", "completed", "failed"}

SOAR_TO_AUTO_STATUS = {
    "success": "completed",
    "permanent": "completed",
    "resolved": "completed",
    "resolve_failed": "failed",
    "failed": "failed",
}


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _append_comment(old: str | None, add: str | None, limit: int = 500) -> str:
    old = (old or "").strip()
    add = (add or "").strip()
    if not add:
        return old[:limit]
    merged = (f"{old} | {add}" if old else add).strip()
    return merged[:limit]

def _is_valid_ipv4(ip: str) -> bool:
    parts = str(ip).split(".")
    if len(parts) != 4: return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False

_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
def _is_valid_username(u: str) -> bool:
    return bool(_USER_RE.match(str(u or "")))

async def _insert_soar_action_row(agent: str, *, event_id: int, action: str,
                                  target: str, comment: str, status: str,
                                  expires_at: str | None):
    """
    sofar_actions tablosuna doğrudan insert (agent DB).
    Kolonlar: id, timestamp, event_id, action, target, comment, status, resolved_at, expires_at, sent?
    """
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute(
        """
        INSERT INTO soar_actions
          (timestamp, event_id, action, target, comment, status, expires_at)
        VALUES
          (NOW(), %s, %s, %s, %s, %s, %s)
        """,
        (event_id, action, target, comment, status.upper(), expires_at)
    )
    await cnx.commit()
    rid = cur.lastrowid
    await cur.close(); await cnx.close()
    return rid

async def _history_block_count(agent: str, target_ip: str) -> int:
    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "SELECT COUNT(*) FROM soar_actions WHERE action=%s AND target=%s AND status IN ('SUCCESS','PERMANENT')",
            (ActionType.BLOCK_IP.value, target_ip)
        )
        row = await cur.fetchone()
        await cur.close(); await cnx.close()
        return int(row[0] if row else 0)
    except Exception:
        return 0

async def _execute_automation_record(agent: str, rec: dict) -> dict:
    """
    Automation kaydını çalıştırır - Agent'a SOAR isteği gönderir.
    
    Args:
        agent: Agent adı
        rec: automations tablosundan gelen kayıt (dict)
        
    Returns:
        Execution sonucu detayları
    """
    action = rec["action"].strip()
    target = rec["target"].strip()
    event_id = int(rec["event_id"]) if rec.get("event_id") else None

    comment_prefix = f"automation#{rec['id']}"
    comment_full = f"{comment_prefix} | {rec.get('comment') or ''}".strip()

    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute(
        "UPDATE automations SET status='active', updated_at=NOW() WHERE id=%s",
        (rec["id"],)
    )
    await cnx.commit()
    await cur.close()
    await cnx.close()

    try:
        result = await call_agent_soar(
            agent,
            action=action,
            target=target,
            comment=comment_full,
            event_id=event_id,
            ttl=rec.get("ttl")
        )

        ok = result.get("ok", False)
        auto_status = "completed" if ok else "failed"
        soar_status = result.get("status", "failed")
        soar_action_id = result.get("soar_action_id")
        expires_at = result.get("expires_at")
        msg_detail = result.get("message", "")

        final_comment = _append_comment(
            rec.get("comment"),
            f"{comment_prefix} | {msg_detail}"
        )

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "UPDATE automations SET status=%s, comment=%s, updated_at=NOW() WHERE id=%s",
            (auto_status, final_comment, rec["id"])
        )
        await cnx.commit()
        await cur.close()
        await cnx.close()

        return {
            "automation": {
                "id": rec["id"],
                "status": auto_status,
                "comment": final_comment,
                "updated_at": _now_str(),
            },
            "soar_action_id": soar_action_id,
            "soar_status": soar_status,
            "expires_at": expires_at,
            "message": msg_detail,
            "ok": ok,
        }

    except Exception as e:
        error_msg = str(e)
        final_comment = _append_comment(
            rec.get("comment"),
            f"{comment_prefix} | ERROR: {error_msg}"
        )

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "UPDATE automations SET status='failed', comment=%s, updated_at=NOW() WHERE id=%s",
            (final_comment, rec["id"])
        )
        await cnx.commit()
        await cur.close()
        await cnx.close()

        return {
            "automation": {
                "id": rec["id"],
                "status": "failed",
                "comment": final_comment,
                "updated_at": _now_str(),
            },
            "soar_action_id": None,
            "soar_status": "failed",
            "expires_at": None,
            "message": error_msg,
            "ok": False,
        }

def ensure_permissions(path: pathlib.Path):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def _as_bool(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val == 1
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes", "y", "on", "active"}
    return False

def load_or_create_fernet_from_env():
    """Resolve the server-side Fernet key, which protects at-rest columns.

    Normally supplied as `FERNET_KEY` in the environment (compose passes it
    through from .env). The fallback generates one and writes it back to .env
    so it survives a restart — but the container runs as a non-root user and
    /app is not writable, so that path only works for a bare-metal dev run.

    Generating a key we cannot persist would be the worst outcome: every
    restart would produce a different key and silently render previously
    encrypted values unreadable. So a failed write is fatal and says exactly
    what to do about it.
    """
    key_b64 = os.getenv("FERNET_KEY")
    if key_b64:
        return Fernet(key_b64.encode())

    vals = dotenv_values(dotenv_path=ENV_PATH) if ENV_PATH.exists() else {}

    key_b64 = vals.get("FERNET_KEY")
    if not key_b64:
        key_b64 = Fernet.generate_key().decode()
        try:
            if not ENV_PATH.exists():
                ENV_PATH.touch()
            set_key(str(ENV_PATH), "FERNET_KEY", key_b64)
            ensure_permissions(ENV_PATH)
            print(f"[+] Generated FERNET_KEY and persisted it to {ENV_PATH.resolve()}")
        except OSError as e:
            raise SystemExit(
                f"[FATAL] No FERNET_KEY set and it could not be persisted to "
                f"{ENV_PATH} ({e}).\n"
                f"        Add a key to your .env — compose passes it through:\n"
                f"          FERNET_KEY={key_b64}\n"
                f"        Losing this key makes existing encrypted columns "
                f"unreadable, so store it somewhere you can restore from."
            ) from e

    return Fernet(key_b64.encode())

fernet = load_or_create_fernet_from_env()

import zipfile
import io

@app.get("/api/agent/download/<os_type>")
async def download_agent(request, os_type):
    user_id = current_user_id(request)
    provided_key = request.headers.get("X-Agent-Key") or request.args.get("key")
    agent_key = request.headers.get("X-Agent-Key") or request.args.get("agent_key")

    is_authed = False
    if user_id and await user_has_permission(user_id, "manage_agent"):
        is_authed = True
    elif provided_key == AGENT_SHARED_SECRET:
        is_authed = True
    elif agent_key:
        try:
            with sync_mysql_conn("userdb") as conn:
                cur = conn.cursor()
                try:
                    cur.execute(
                        "SELECT 1 FROM agent_identities WHERE agent_key=%s AND revoked_at IS NULL",
                        (agent_key,)
                    )
                    if cur.fetchone():
                        is_authed = True
                finally:
                    cur.close()
        except Exception:
            pass

    if not is_authed:
        return sanic_json({"status": "error", "message": "Unauthorized"}, status=403)

    await audit_log(request, "DOWNLOAD_AGENT", os_type, f"Agent package requested for {os_type}")

    server_ip = request.host.split(':')[0]
    
    memory_file = io.BytesIO()
    
    agent_root = pathlib.Path("Sentora")
    if not agent_root.exists():
        return sanic_json({"ok": False, "error": "Agent source not found"}, status=404)

    exe_name = "main.exe" if os_type == "windows" else "main"

    bin_path = agent_root / exe_name
    if not bin_path.exists():
        return sanic_json({
            "ok": False,
            "error": f"Agent binary '{exe_name}' is not built. "
                     f"Run Sentora/build_agent.{'ps1' if os_type=='windows' else 'sh'} "
                     f"to produce it before enrolling agents."
        }, status=503)

    files_to_zip = [
        exe_name,
        "docker-compose.yml",
        "db/init.sql"
    ]

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f_path in files_to_zip:
            abs_path = agent_root / f_path
            if abs_path.exists():
                zf.write(abs_path, f_path)

        if os_type == "windows":
            setup_bat = f"""@echo off
setlocal
cd /d "%~dp0"

:: Check for Administrator privileges
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script requires Administrator privileges.
    echo [*] Attempting to elevate...
    powershell.exe -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [*] Starting Sentora Agent Database (Docker)...
if exist "docker-compose.yml" (
    docker compose up -d
)

echo [*] Creating Background Runner...
echo @echo off > run_agent.bat
echo cd /d "%%~dp0" >> run_agent.bat
:: Prevent Python from trying to format %%COMPUTERNAME%%, just let batch handle it
echo "main.exe" -a "Agent-%%COMPUTERNAME%%" -s "{server_ip}" >> run_agent.bat

echo [*] Installing Sentora Agent Background Task...
set TASK_NAME=SentoraAgent
set WATCH_NAME=SentoraAgentWatchdog
set BIN_PATH="%~dp0run_agent.bat"

:: Stop and delete old Scheduled Tasks if they exist
schtasks /end /tn "%TASK_NAME%" >nul 2>&1
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
schtasks /delete /tn "%WATCH_NAME%" /f >nul 2>&1

:: Run silently on boot as SYSTEM
schtasks /create /tn "%TASK_NAME%" /tr "%BIN_PATH%" /sc onstart /ru System /f
if %errorlevel% neq 0 (
    echo [!] Failed to create background task.
) else (
    echo [*] Starting the Agent now...
    schtasks /run /tn "%TASK_NAME%"
)

:: Watchdog. schtasks cannot attach a repetition interval to an onstart
:: trigger, so this is a second task on a 15-minute schedule. main.exe takes
:: a single-instance lock before doing any work and exits 0 if another agent
:: already holds it -- so while the agent is healthy this is a no-op, and
:: when it has died it brings it back without waiting for a reboot.
schtasks /create /tn "%WATCH_NAME%" /tr "%BIN_PATH%" /sc minute /mo 15 /ru System /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Watchdog task not created - the agent will still start at boot.
) else (
    echo [*] Watchdog registered ^(checks every 15 minutes^).
)

echo [+] Setup Complete! The Agent is now running in the background.
pause
"""
            zf.writestr("setup.bat", setup_bat)
        else:
            setup_sh = f"""#!/bin/bash
cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./setup.sh)"
  exit 1
fi

echo "[*] Starting Sentora Agent Database (Docker)..."
if command -v docker >/dev/null 2>&1; then
    docker compose up -d || docker-compose up -d
else
    echo "[!] Docker is not installed. Database cannot be started."
fi

echo "[*] Installing Sentora Agent Service..."
chmod +x main

SERVICE_FILE="/etc/systemd/system/sentora-agent.service"
cat > $SERVICE_FILE << EOF
[Unit]
Description=Sentora Agent
After=network.target docker.service

[Service]
ExecStart=$(pwd)/main -a "Agent-$(hostname)" -s "{server_ip}"
WorkingDirectory=$(pwd)
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentora-agent
systemctl start sentora-agent

echo "[+] Setup Complete! The Agent is now running in the background."
"""
            zf.writestr("setup.sh", setup_sh)

    memory_file.seek(0)

    return HTTPResponse(
        body=memory_file.getvalue(),
        content_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=Sentora-Agent-{os_type}.zip",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )

ENROLLMENT_TOKEN_TTL_HOURS = int(os.getenv("ENROLLMENT_TOKEN_TTL_HOURS", "24"))

def _gen_token() -> str:
    return secrets.token_hex(32)

def _client_ip(request) -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.ip or "-"

async def _validate_agent_auth(request) -> str | None:
    """Return agent_name if X-Agent-Key matches a non-revoked identity, else None.
    Also accepts the global AGENT_SHARED_SECRET for backward compat (returns '*')."""
    key = request.headers.get("X-Agent-Key") or request.args.get("agent_key")
    if not key:
        legacy = request.headers.get("X-Agent-Key") or request.args.get("key")
        if legacy and legacy == AGENT_SHARED_SECRET:
            return "*"
        return None
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT agent_name FROM agent_identities WHERE agent_key=%s AND revoked_at IS NULL",
                    (key,)
                )
                row = cur.fetchone()
                if row:
                    return row[0]
            finally:
                cur.close()
    except Exception as e:
        print(f"[Enroll] agent auth lookup error: {e}")
    if key == AGENT_SHARED_SECRET:
        return "*"
    return None

@app.post("/api/agents/enroll")
async def enroll_agent(request):
    """Create a one-time enrollment token (authenticated, requires manage_agent)."""
    user_id = current_user_id(request)
    if not user_id or not await user_has_permission(user_id, "manage_agent"):
        return sanic_json({"status": "error", "message": "Unauthorized"}, status=403)

    body = request.json or {}
    hostname_hint = (body.get("hostname_hint") or "").strip()[:255]
    note = (body.get("note") or "").strip()[:500]
    ttl_hours = int(body.get("ttl_hours") or ENROLLMENT_TOKEN_TTL_HOURS)
    ttl_hours = max(1, min(ttl_hours, 24 * 30))

    username = None
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute("SELECT username FROM users WHERE id=%s", (user_id,))
                r = cur.fetchone()
                if r:
                    username = r[0]
            finally:
                cur.close()
    except Exception:
        pass

    token = _gen_token()
    expires_at = datetime.now().replace(microsecond=0)
    from datetime import timedelta as _td
    expires_at = expires_at + _td(hours=ttl_hours)

    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT INTO enrollment_tokens
                       (token, created_by_user_id, created_by_username, hostname_hint, note, expires_at)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (token, user_id, username, hostname_hint or None, note or None, expires_at)
                )
                conn.commit()
            finally:
                cur.close()
    except Exception as e:
        return sanic_json({"status": "error", "message": f"Failed to create token: {e}"}, status=500)

    await audit_log(request, "ENROLL_TOKEN_CREATE", token[:8] + "...",
                    f"ttl={ttl_hours}h hostname_hint={hostname_hint or '-'}")

    proto = "https" if request.scheme == "https" else "http"
    host = request.host
    base = f"{proto}://{host}"
    return sanic_json({
        "status": "success",
        "token": token,
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
        "server_url": base,
        "install": {
            "linux":   f"curl -fsSL '{base}/api/agent/deploy/linux?token={token}' | sudo bash",
            "windows": f"iwr -useb '{base}/api/agent/deploy/windows?token={token}' | iex",
        }
    })

@app.get("/api/agents/enrollments")
async def list_enrollments(request):
    """List recent enrollment tokens (authed)."""
    user_id = current_user_id(request)
    if not user_id or not await user_has_permission(user_id, "manage_agent"):
        return sanic_json({"status": "error", "message": "Unauthorized"}, status=403)

    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor(dictionary=True)
            try:
                cur.execute(
                    """SELECT id, token, created_by_username, hostname_hint, note,
                              created_at, expires_at, used_at, used_by_agent, used_from_ip
                       FROM enrollment_tokens
                       ORDER BY created_at DESC LIMIT 100"""
                )
                rows = cur.fetchall()
            finally:
                cur.close()
        for r in rows:
            for k, v in list(r.items()):
                if isinstance(v, datetime):
                    r[k] = v.strftime("%Y-%m-%d %H:%M:%S")
            if r.get("token"):
                r["token_preview"] = r["token"][:8] + "…" + r["token"][-4:]
                del r["token"]
        return sanic_json({"status": "success", "enrollments": rows})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@app.delete("/api/agents/enrollments/<token_id:int>")
async def revoke_enrollment(request, token_id):
    user_id = current_user_id(request)
    if not user_id or not await user_has_permission(user_id, "manage_agent"):
        return sanic_json({"status": "error", "message": "Unauthorized"}, status=403)
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute("DELETE FROM enrollment_tokens WHERE id=%s AND used_at IS NULL", (token_id,))
                conn.commit()
                affected = cur.rowcount
            finally:
                cur.close()
        if affected:
            await audit_log(request, "ENROLL_TOKEN_REVOKE", str(token_id), "")
            return sanic_json({"status": "success"})
        return sanic_json({"status": "error", "message": "Token not found or already used"}, status=404)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@app.post("/api/agents/register")
async def register_agent(request):
    """Exchange a one-time enrollment token for a per-agent identity.
    Body: {token, agent_name?, hostname?, os_type?}. Returns {agent_name, agent_key, server_url}."""
    body = request.json or {}
    token = (body.get("token") or "").strip()
    if not token or len(token) != 64:
        return sanic_json({"status": "error", "message": "Invalid token format"}, status=400)

    client_ip = _client_ip(request)
    hostname = (body.get("hostname") or "").strip()[:255] or None
    os_type = (body.get("os_type") or "").strip()[:32] or None
    req_name = (body.get("agent_name") or "").strip()[:128] or None

    if req_name and not re.match(r"^[A-Za-z0-9_.-]{1,128}$", req_name):
        return sanic_json({"status": "error", "message": "Invalid agent_name"}, status=400)

    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor(dictionary=True)
            try:
                cur.execute(
                    """SELECT id, expires_at, used_at FROM enrollment_tokens
                       WHERE token=%s FOR UPDATE""",
                    (token,)
                )
                row = cur.fetchone()
                if not row:
                    return sanic_json({"status": "error", "message": "Token not recognized"}, status=404)
                if row["used_at"] is not None:
                    return sanic_json({"status": "error", "message": "Token already used"}, status=409)
                if row["expires_at"] and row["expires_at"] < datetime.now():
                    return sanic_json({"status": "error", "message": "Token expired"}, status=410)

                if not req_name:
                    base = hostname or f"Agent-{token[:8]}"
                    req_name = re.sub(r"[^A-Za-z0-9_.-]", "-", base)[:128] or f"Agent-{token[:8]}"

                final_name = req_name
                suffix = 1
                while True:
                    cur.execute("SELECT 1 FROM agent_identities WHERE agent_name=%s", (final_name,))
                    if not cur.fetchone():
                        break
                    suffix += 1
                    final_name = f"{req_name}-{suffix}"[:128]
                    if suffix > 500:
                        return sanic_json({"status": "error", "message": "Could not allocate agent name"}, status=500)

                agent_key = _gen_token()
                cur.execute(
                    """INSERT INTO agent_identities
                       (agent_name, agent_key, os_type, hostname, enrolled_from_ip, enrolled_via_token)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (final_name, agent_key, os_type, hostname, client_ip, token)
                )
                cur.execute(
                    """UPDATE enrollment_tokens
                       SET used_at=NOW(), used_by_agent=%s, used_from_ip=%s
                       WHERE id=%s""",
                    (final_name, client_ip, row["id"])
                )
                conn.commit()
            finally:
                cur.close()
    except mysql.connector.IntegrityError as e:
        return sanic_json({"status": "error", "message": f"Identity conflict: {e}"}, status=409)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

    proto = "https" if request.scheme == "https" else "http"
    host = request.host
    server_url = f"{proto}://{host}"
    server_ip = host.split(":")[0]
    return sanic_json({
        "status": "success",
        "agent_name": final_name,
        "agent_key": agent_key,
        "server_url": server_url,
        "server_ip": server_ip,
    })


@app.get("/api/agents/bootstrap")
async def agent_bootstrap(request):
    """Hand the shared Fernet key to a token-enrolled agent.

    Community edition: the key is read from the server's local file
    (FERNET_KEY_PATH) — no remote auth round-trip. The agent
    authenticates with the per-agent X-Agent-Key issued by
    /api/agents/register.
    """
    agent_key = (request.headers.get("X-Agent-Key") or "").strip()
    if not agent_key or len(agent_key) != 64:
        return sanic_json({"ok": False, "error": "missing X-Agent-Key"}, status=401)

    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor(dictionary=True)
            try:
                cur.execute("SELECT agent_name FROM agent_identities WHERE agent_key=%s", (agent_key,))
                row = cur.fetchone()
            finally:
                cur.close()
    except Exception as e:
        return sanic_json({"ok": False, "error": f"auth lookup failed: {e}"}, status=500)
    if not row:
        return sanic_json({"ok": False, "error": "unknown agent_key"}, status=403)

    try:
        fk = await asyncio.to_thread(bootstrap_client.get_fernet_key)
    except Exception as e:
        return sanic_json({"ok": False, "error": f"local fernet key load failed: {e}"}, status=500)

    return sanic_json({
        "ok": True,
        "fernet_key": fk,
        "is_active": True,
        "tier": "Community",
        "expires_at": None,
    })


def _render_linux_install(server_url: str, server_ip: str, token: str) -> str:
    return f"""#!/usr/bin/env bash
# Sentora Agent — Token-Based Installer
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Please run as root (use: curl ... | sudo bash)"
  exit 1
fi

TOKEN="{token}"
SERVER_URL="{server_url}"
SERVER_IP="{server_ip}"
INSTALL_DIR="/opt/sentora-agent"
HOSTNAME_VAL="$(hostname)"
OS_TYPE="linux"

echo "[*] Sentora Agent Installer"
echo "[*] Server : $SERVER_URL"
echo "[*] Host   : $HOSTNAME_VAL"

# Dependencies
if ! command -v curl >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y curl
fi
if ! command -v unzip >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y unzip
fi

# Allow overriding token via --token (for local execution)
for arg in "$@"; do
  case "$arg" in
    --token=*) TOKEN="${{arg#--token=}}" ;;
  esac
done
if [ -z "$TOKEN" ]; then
  echo "[!] Missing enrollment token"; exit 1
fi

echo "[*] Registering with server..."
REG_RESP="$(curl -fsSL -X POST "$SERVER_URL/api/agents/register" \\
  -H 'Content-Type: application/json' \\
  -d "{{\\"token\\":\\"$TOKEN\\",\\"hostname\\":\\"$HOSTNAME_VAL\\",\\"os_type\\":\\"$OS_TYPE\\"}}")"

AGENT_NAME="$(echo "$REG_RESP" | sed -n 's/.*"agent_name"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')"
AGENT_KEY="$(echo "$REG_RESP"  | sed -n 's/.*"agent_key"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')"

if [ -z "$AGENT_NAME" ] || [ -z "$AGENT_KEY" ]; then
  echo "[!] Registration failed: $REG_RESP"
  exit 1
fi

echo "[+] Enrolled as: $AGENT_NAME"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[*] Downloading agent binary..."
curl -fsSL -H "X-Agent-Key: $AGENT_KEY" -o agent.zip "$SERVER_URL/api/agent/download/linux"
unzip -q -o agent.zip
chmod +x main 2>/dev/null || true

# Write identity config
umask 077
cat > "$INSTALL_DIR/config.json" <<EOF
{{
  "agent_name": "$AGENT_NAME",
  "agent_key":  "$AGENT_KEY",
  "server_url": "$SERVER_URL",
  "server_ip":  "$SERVER_IP"
}}
EOF
chmod 600 "$INSTALL_DIR/config.json"

SERVICE_FILE="/etc/systemd/system/sentora-agent.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sentora Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/main --config $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentora-agent
systemctl restart sentora-agent

rm -f agent.zip
echo "[+] Sentora Agent installed and running as: $AGENT_NAME"
"""


def _render_windows_install(server_url: str, server_ip: str, token: str) -> str:
    return f"""# Sentora Agent - Token-Based Installer (Windows)
& {{
    $ErrorActionPreference = "Stop"
    $Token     = "{token}"
    $ServerUrl = "{server_url}"
    $ServerIp  = "{server_ip}"
    $InstallDir = "C:\\Program Files\\Sentora-Agent"
    $Hostname  = $env:COMPUTERNAME
    $OsType    = "windows"
    $LogPath   = Join-Path $env:TEMP "sentora-install.log"
    Start-Transcript -Path $LogPath -Force | Out-Null

    try {{
        Write-Host "[*] Sentora Agent Installer" -ForegroundColor Cyan
        Write-Host "[*] Server : $ServerUrl"
        Write-Host "[*] Host   : $Hostname"
        Write-Host "[*] Log    : $LogPath"

        # Elevation: if not admin, relaunch the one-liner in an elevated window
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {{
            Write-Host "[!] Not elevated. Relaunching in an Administrator window..." -ForegroundColor Yellow
            $url = "$ServerUrl/api/agent/deploy/windows?token=$Token"
            $cmd = "iwr -useb '$url' | iex; Read-Host 'Press Enter to close'"
            try {{
                Start-Process -FilePath "powershell.exe" `
                    -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-NoExit","-Command",$cmd `
                    -Verb RunAs | Out-Null
                Write-Host "[*] A new elevated window has opened. Follow installation there." -ForegroundColor Green
            }} catch {{
                Write-Host "[!] Could not auto-elevate: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    Please open PowerShell as Administrator and run the one-liner again." -ForegroundColor Yellow
            }}
            return
        }}

        Write-Host "[*] Registering with server..." -ForegroundColor Cyan
        $RegBody = @{{ token = $Token; hostname = $Hostname; os_type = $OsType }} | ConvertTo-Json -Compress
        try {{
            $Reg = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/agents/register" -ContentType "application/json" -Body $RegBody
        }} catch {{
            Write-Host "[!] Registration call failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }}

        if (-not $Reg.agent_name -or -not $Reg.agent_key) {{
            Write-Host "[!] Registration response missing identity: $($Reg | ConvertTo-Json -Compress)" -ForegroundColor Red
            return
        }}

        $AgentName = $Reg.agent_name
        $AgentKey  = $Reg.agent_key
        Write-Host "[+] Enrolled as: $AgentName" -ForegroundColor Green

        if (!(Test-Path $InstallDir)) {{ New-Item -ItemType Directory -Path $InstallDir | Out-Null }}
        Set-Location $InstallDir

        Write-Host "[*] Downloading agent binary..." -ForegroundColor Cyan
        try {{
            Invoke-WebRequest -Uri "$ServerUrl/api/agent/download/windows" `
                -Headers @{{ "X-Agent-Key" = $AgentKey }} -OutFile "agent.zip" -UseBasicParsing
        }} catch {{
            $srv = ""
            try {{ $srv = (New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() }} catch {{}}
            Write-Host "[!] Binary download failed: $($_.Exception.Message)" -ForegroundColor Red
            if ($srv) {{ Write-Host "    Server said: $srv" -ForegroundColor Yellow }}
            return
        }}

        # Stop any previously installed agent BEFORE extracting, otherwise the
        # running main.exe locks itself and Expand-Archive blows up with
        # UnauthorizedAccessException. This is the upgrade-in-place path.
        $existingExe = Join-Path $InstallDir "main.exe"
        if (Test-Path $existingExe) {{
            Write-Host "[*] Stopping previous agent to release main.exe..." -ForegroundColor Cyan
            try {{
                $prevTask = Get-ScheduledTask -TaskName "SentoraAgent" -ErrorAction SilentlyContinue
                if ($prevTask) {{
                    Stop-ScheduledTask -TaskName "SentoraAgent" -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName "SentoraAgent" -Confirm:$false -ErrorAction SilentlyContinue
                }}
            }} catch {{}}
            try {{
                Get-Process -Name "main" -ErrorAction SilentlyContinue | Where-Object {{
                    try {{ $_.Path -eq $existingExe }} catch {{ $false }}
                }} | Stop-Process -Force -ErrorAction SilentlyContinue
            }} catch {{}}

            # Wait until the file is no longer locked. Up to 10s — Windows
            # releases the handle a beat after the process exits.
            for ($i = 0; $i -lt 20; $i++) {{
                try {{
                    $fs = [System.IO.File]::Open($existingExe, 'Open', 'ReadWrite', 'None')
                    $fs.Close()
                    break
                }} catch {{
                    Start-Sleep -Milliseconds 500
                }}
            }}
        }}

        try {{
            Expand-Archive -Path "agent.zip" -DestinationPath "." -Force
        }} catch {{
            Write-Host "[!] Failed to extract agent.zip: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    The previous agent may still be locking main.exe." -ForegroundColor Yellow
            Write-Host "    Manually stop it and retry: Stop-ScheduledTask -TaskName SentoraAgent; Get-Process main | Stop-Process -Force" -ForegroundColor Yellow
            return
        }}

        if (-not (Test-Path (Join-Path $InstallDir "main.exe"))) {{
            Write-Host "[!] main.exe missing after extraction. Server did not ship a binary." -ForegroundColor Red
            return
        }}

        $Config = @{{
            agent_name      = $AgentName
            agent_key       = $AgentKey
            server_url      = $ServerUrl
            server_ip       = $ServerIp
            ingest_port     = 5001
        }} | ConvertTo-Json -Depth 3
        $ConfigPath = Join-Path $InstallDir "config.json"
        # PS5.1 `Set-Content -Encoding UTF8` writes a BOM which Python's
        # json.load rejects with "Unexpected UTF-8 BOM". Use .NET to write
        # BOM-less UTF-8.
        [System.IO.File]::WriteAllText($ConfigPath, $Config, (New-Object System.Text.UTF8Encoding $false))

        # Bootstrap the agent's local postgres. Sentora/docker-compose.yml is
        # shipped inside the zip and defines the `sentora-db-agent` container
        # on localhost:5432 — modules/db.py hard-connects to that. Without it
        # every insert_record/fetch_unsent raises "connection refused".
        $composePath = Join-Path $InstallDir "docker-compose.yml"
        if (Test-Path $composePath) {{
            if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {{
                Write-Host "[!] Docker not found on PATH. Install Docker Desktop and retry." -ForegroundColor Red
                Write-Host "    The agent needs a local postgres (sentora-db-agent) to store its state." -ForegroundColor Yellow
                return
            }}
            Write-Host "[*] Starting local agent database (postgres on :5432)..." -ForegroundColor Cyan
            # NOTE: do NOT redirect stderr with 2>&1. PowerShell 5.1 + Stop
            # action turns every native-cmd stderr line into a NativeCommandError
            # — and `docker compose` writes progress ("Network ... Creating",
            # "Container ... Started") to stderr. We check $LASTEXITCODE instead.
            Push-Location $InstallDir
            $prevEA = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & docker compose up -d
            $composeExit = $LASTEXITCODE
            $ErrorActionPreference = $prevEA
            Pop-Location
            if ($composeExit -ne 0) {{
                Write-Host "[!] docker compose up failed (exit $composeExit)." -ForegroundColor Red
                Write-Host "    Run manually: cd `"$InstallDir`" ; docker compose up -d" -ForegroundColor Yellow
                return
            }}

            Write-Host "[*] Waiting for postgres on localhost:5432..." -ForegroundColor Cyan
            $dbReady = $false
            for ($i = 0; $i -lt 30; $i++) {{
                if (Test-NetConnection -ComputerName localhost -Port 5432 -InformationLevel Quiet -WarningAction SilentlyContinue) {{
                    $dbReady = $true
                    break
                }}
                Start-Sleep -Seconds 2
            }}
            if (-not $dbReady) {{
                Write-Host "[!] Postgres did not become reachable within 60s." -ForegroundColor Red
                Write-Host "    Check: docker logs sentora-db-agent" -ForegroundColor Yellow
                return
            }}
            Write-Host "[+] Agent database ready (sentora-db-agent)." -ForegroundColor Green
        }} else {{
            Write-Host "[!] docker-compose.yml missing in $InstallDir — agent will crash on DB connect." -ForegroundColor Red
            return
        }}

        # Persistence via Scheduled Task (SYSTEM, AtStartup). main.py is a plain
        # console app — it does not implement the Windows Service Control
        # Protocol, so sc.exe create + Start-Service silently fails. Scheduled
        # Task runs the binary as SYSTEM at every boot and we kick it off now.
        $taskName = "SentoraAgent"
        $exePath  = Join-Path $InstallDir "main.exe"
        $workDir  = $InstallDir

        # Remove legacy sc.exe service if it exists from a previous install
        $legacy = Get-Service -Name $taskName -ErrorAction SilentlyContinue
        if ($legacy) {{
            Stop-Service -Name $taskName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $taskName | Out-Null
        }}

        # Remove previous scheduled task (if any) so we can re-register cleanly
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {{
            try {{ Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }} catch {{}}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }}

        try {{
            $action    = New-ScheduledTaskAction -Execute $exePath -Argument "--config `"$ConfigPath`"" -WorkingDirectory $workDir

            # Two triggers. AtStartup is the normal path. The repeating one is
            # a watchdog: if the agent is ever not running -- crash, manual
            # stop, a failed upgrade -- the next tick starts it again. Without
            # it, a single unhandled exit left the endpoint blind until
            # somebody noticed, which is the worst failure mode a sensor has.
            #
            # MultipleInstances=IgnoreNew below makes the watchdog a no-op
            # while the agent is already up, so this costs nothing when
            # everything is fine.
            $bootTrigger  = New-ScheduledTaskTrigger -AtStartup
            $watchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
                                -RepetitionInterval (New-TimeSpan -Minutes 15)
            $triggers = @($bootTrigger, $watchTrigger)

            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

            # RestartCount is deliberately generous: the agent now retries its
            # own server bootstrap internally, so a restart here means the
            # process actually died, and a sensor that gives up after three
            # tries is a sensor you cannot rely on.
            $settings = New-ScheduledTaskSettingsSet `
                            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                            -StartWhenAvailable `
                            -ExecutionTimeLimit ([TimeSpan]::Zero) `
                            -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) `
                            -MultipleInstances IgnoreNew

            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
        }} catch {{
            Write-Host "[!] Failed to register scheduled task: $($_.Exception.Message)" -ForegroundColor Red
            return
        }}

        # Kill any stale main.exe before starting
        Get-Process -Name "main" -ErrorAction SilentlyContinue | Where-Object {{
            try {{ $_.Path -eq $exePath }} catch {{ $false }}
        }} | Stop-Process -Force -ErrorAction SilentlyContinue

        try {{
            Start-ScheduledTask -TaskName $taskName
            Start-Sleep -Seconds 3
        }} catch {{
            Write-Host "[!] Failed to start scheduled task: $($_.Exception.Message)" -ForegroundColor Red
            return
        }}

        # Verify the agent process is actually running
        $proc = Get-Process -Name "main" -ErrorAction SilentlyContinue | Where-Object {{
            try {{ $_.Path -eq $exePath }} catch {{ $false }}
        }} | Select-Object -First 1
        if (-not $proc) {{
            Write-Host "[!] Agent process did not start. Check $InstallDir\\agent.log" -ForegroundColor Red
            Write-Host "    You can also inspect: Get-ScheduledTaskInfo -TaskName $taskName" -ForegroundColor Yellow
            return
        }}

        Remove-Item -Path "agent.zip" -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Sentora Agent installed and running as: $AgentName" -ForegroundColor Green
        Write-Host "    Task   : $taskName (PID $($proc.Id))"
        Write-Host "    Config : $ConfigPath"
        Write-Host "    Log    : $InstallDir\\agent.log"
    }} catch {{
        Write-Host "[!] Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }} finally {{
        Stop-Transcript | Out-Null
    }}
}}
"""


@app.get("/api/agent/deploy/linux")
async def deploy_agent_linux(request):
    proto = "https" if request.scheme == "https" else "http"
    host = request.host
    token = (request.args.get("token") or "").strip()
    server_url = f"{proto}://{host}"
    server_ip = host.split(":")[0]
    script = _render_linux_install(server_url, server_ip, token)
    return HTTPResponse(body=script, content_type="text/x-sh")


@app.get("/api/agent/deploy/windows")
async def deploy_agent_windows(request):
    proto = "https" if request.scheme == "https" else "http"
    host = request.host
    token = (request.args.get("token") or "").strip()
    server_url = f"{proto}://{host}"
    server_ip = host.split(":")[0]
    script = _render_windows_install(server_url, server_ip, token)
    return HTTPResponse(body=script, content_type="text/plain")


class CustomEncoder(pyjson.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime,)):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(obj, float) and 1000000000 < obj < 2000000000:
            try:
                return datetime.fromtimestamp(obj).strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        if isinstance(obj, str) and '.' in obj:
            try:
                f_val = float(obj)
                if 1000000000 < f_val < 2500000000:
                   return datetime.fromtimestamp(f_val).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
                
        return str(obj)

def fetch_email_config():
    try:
        with sync_mysql_conn("userdb") as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT * FROM email_config ORDER BY updated_at DESC LIMIT 1")
                return cursor.fetchone()
            finally:
                cursor.close()
    except Exception as e:
        print(f"[!] Email config fetch error: {e}")
        return None

def render_template(template: str, context: dict) -> str:
    for key, value in context.items():
        template = template.replace(f"{{{{{key}}}}}", str(value))
    return template

 


def get_mail_config():
    """Get mail configuration and determine if mail is enabled"""
    cfg = fetch_email_config()
    mail_enabled = bool(cfg and cfg.get('smtp_server') and cfg.get('email_to'))
    
    if mail_enabled:
        return {
            'enabled': True,
            'smtp_server': cfg['smtp_server'],
            'smtp_port': cfg['smtp_port'],
            'smtp_user': cfg['smtp_user'],
            'smtp_password': cfg['smtp_password'],
            'use_tls': cfg['smtp_use_tls'],
            'from_addr': cfg['email_from'],
            'to_addr': cfg['email_to']
        }
    else:
        return {'enabled': False}


async def get_role_permissions(role_name: str) -> list:
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("""
            SELECT p.name FROM roles r
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE r.role_name = %s OR r.role_name = 'admin'
        """, (role_name,))
        rows = await cursor.fetchall()
        await cursor.close(); await cnx.close()
        perms = list(set([row[0] for row in rows]))
        return perms
    except Exception as e:
        print(f"Error fetching role permissions: {e}")
        return []

async def get_user_permissions(user_id: int) -> list:
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("""
            SELECT p.name FROM users u
            JOIN roles r ON u.role = r.role_name
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE u.id = %s OR (u.role = 'admin' AND p.name = 'all_permission')
        """, (user_id,))
        rows = await cursor.fetchall()
        await cursor.close(); await cnx.close()
        perms = [row[0] for row in rows]
        if 'all_permission' in perms:
            pass
        return perms
    except Exception as e:
        print(f"Error fetching permissions: {e}")
        return []

@app.route("/user/permissions", methods=["GET"])
async def fetch_my_permissions(request):
    user_id = current_user_id(request)
    if not user_id:
        return sanic_json({"status": "error", "message": "Not authenticated"}, status=401)
    perms = await get_user_permissions(user_id)
    return sanic_json({"status": "success", "permissions": perms})

async def user_has_permission(user_id: int, permission_name: str) -> bool:
    if not user_id:
        return False
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("""
            SELECT COUNT(*) FROM users u
            JOIN roles r ON u.role = r.role_name
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE u.id = %s AND (p.name = %s OR p.name = 'all_permission')
        """, (user_id, permission_name))

        result = await cursor.fetchone()
        await cursor.close(); await cnx.close()
        return result[0] > 0
    except Exception as e:
        print(f"[!] Permission check error: {e}")
        return False



async def audit_log(request, action: str, resource: str, details: str = ""):
    # Attributed from the session, not from a client-supplied header — an
    # audit trail an attacker can sign with someone else's name is worse than
    # no audit trail, because it reads as authoritative.
    user_id = current_user_id(request)
    username = current_username(request)

    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.conn_info.peername[0] if request.conn_info and request.conn_info.peername else "unknown"

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("""
            INSERT INTO audit_logs (user_id, username, action, resource, details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, username, action, resource, details, ip))

        await cnx.commit()
        await cursor.close(); await cnx.close()

        try:
            asyncio.create_task(os_utils.index_log(
                agent="system", 
                table="audit_logs", 
                item={
                    "user_id": user_id,
                    "username": username,
                    "action": action,
                    "resource": resource,
                    "details": details,
                    "ip_address": ip
                }
            ))
        except Exception as os_e:
            print(f"[!] OpenSearch audit index failed: {os_e}")
    except Exception as e:
        print(f"[!] Audit log failure: {e}")

# ---------------------------------------------------------------------------
# Authentication / authorization
#
# Identity comes from an HttpOnly session cookie, never from a client-supplied
# header. `X-User-ID` is still sent by the frontend and still validated, but
# only as an assertion that must MATCH the session — a mismatch is a hard 401.
# That check is not redundant: browsers cannot attach custom headers to
# cross-site requests without a CORS preflight, so requiring the header also
# makes the session cookie unusable for CSRF.
# ---------------------------------------------------------------------------

# Handlers reachable without a session. Everything else is deny-by-default.
_PUBLIC_HANDLERS = {
    # Login endpoint and the SPA shell (the SPA routes to /login on its own).
    "login", "logout", "health_check", "serve_root", "serve_index",
    # Agent-facing endpoints. These carry X-Agent-Key or an enrollment token
    # (and the automation-poll pair currently carries nothing — tracked as
    # follow-up work). The session layer must not be what gates agent traffic,
    # or every enrolled endpoint stops reporting the moment this ships.
    "download_agent", "register_agent", "agent_bootstrap",
    "deploy_agent_linux", "deploy_agent_windows",
    "get_pending_automations_for_agent",
    "report_automation_result", "report_automation_result_by_id",
}

# Static assets must load before anyone can log in. Matched on path because
# Sanic's internal static handler name varies across versions.
_PUBLIC_PATH_PREFIXES = ("/assets/", "/vite.svg", "/favicon.ico")

# Path-shaped mirror of _PUBLIC_HANDLERS, used only as the backstop in
# `authenticate` when a route's handler cannot be resolved. Kept deliberately
# narrow: it covers login and agent traffic, not the SPA catch-all, so a
# failure here is a visibly broken UI rather than a silent bypass.
_PUBLIC_EXACT_PATHS = {
    "/login", "/logout", "/health",
    "/api/agents/register", "/api/agents/bootstrap",
    "/api/agent/deploy/linux", "/api/agent/deploy/windows",
}
_AGENT_PATH_SUFFIXES = ("/automations/pending", "/automations/report")


def _is_public_path(path: str) -> bool:
    if path in _PUBLIC_EXACT_PATHS or path.startswith(_PUBLIC_PATH_PREFIXES):
        return True
    if path.startswith("/api/agent/download/"):
        return True
    if path.endswith(_AGENT_PATH_SUFFIXES):
        return True
    return bool(re.fullmatch(r"/automations/\d+/report", path))

# Permissions required per route, keyed by handler __qualname__. A set rather
# than a single value because four routes stack two decorators, and stacked
# decorators mean "all of these", not "the outermost one".
_PERMISSION_REQUIREMENTS: dict[str, set[str]] = {}


def require_permission(permission_name):
    """Declare the permission a route requires.

    Records the requirement in `_PERMISSION_REQUIREMENTS` *and* returns a
    guarding wrapper. Both halves matter, because the two decorator orderings
    do not behave the same way:

        @require_permission("x")     |    @app.route("/p")
        @app.route("/p")             |    @require_permission("x")
        async def h(...)             |    async def h(...)

    In the left form `app.route` registers the *bare* handler before this
    decorator ever runs, so the wrapper below is built but never called — which
    is how 85 routes in this file ended up silently unguarded. The registry is
    consulted by the `authenticate` middleware via the handler's __qualname__,
    which @wraps preserves, so enforcement is now identical either way.

    Prefer the right-hand form in new code: the wrapper is the cheaper check
    when it does run.
    """
    def decorator(func):
        _PERMISSION_REQUIREMENTS.setdefault(func.__qualname__, set()).add(permission_name)

        @wraps(func)
        async def wrapper(request, *args, **kwargs):
            # The middleware already resolved this; skip the duplicate query.
            if not getattr(request.ctx, "permission_checked", False):
                if not await user_has_permission(current_user_id(request), permission_name):
                    return sanic_json({
                        "status": "error",
                        "message": f"Permission denied: '{permission_name}' required"
                    }, status=403)
            return await func(request, *args, **kwargs)

        # @wraps copies __qualname__, so this is the same key — the setdefault
        # above already holds it. Restated for the case where a future change
        # makes the wrapper's qualname differ.
        _PERMISSION_REQUIREMENTS.setdefault(wrapper.__qualname__, set()).add(permission_name)
        return wrapper
    return decorator


def current_user(request) -> dict | None:
    """The authenticated user for this request, or None."""
    return getattr(request.ctx, "user", None)


def current_user_id(request) -> int:
    user = current_user(request)
    return int(user["user_id"]) if user else 0


def current_username(request) -> str:
    user = current_user(request)
    return user["username"] if user else "Anonymous"


def _unauthorized(message: str):
    return sanic_json({"status": "error", "message": message}, status=401)


async def revoke_user_sessions(user_id: int, reason: str = "") -> int:
    """Kill every live session for a user.

    Called whenever the credential or the privileges a session was issued
    against change — password reset, role change, account deletion. Without
    this an admin can revoke someone's access and still have their old browser
    tab working until the idle timeout.
    """
    if not user_id:
        return 0
    try:
        async with userdb_conn() as cnx:
            cur = await cnx.cursor()
            try:
                killed = await session_store.revoke_for_user(cur, int(user_id))
                await cnx.commit()
            finally:
                await cur.close()
        if killed:
            print(f"[Session] Revoked {killed} session(s) for user {user_id} ({reason})")
        return killed
    except Exception as e:
        print(f"[!] Session revoke failed for user {user_id}: {e}")
        return 0


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@app.on_request
async def authenticate(request):
    """Resolve the session cookie, then gate the request.

    Runs after routing, so `request.route` already names the handler we are
    about to call. Returning a response here short-circuits that handler.
    """
    request.ctx.user = None
    request.ctx.session_token = None
    request.ctx.permission_checked = False

    # CORS preflight carries no cookies by design.
    if request.method == "OPTIONS":
        return None

    if request.path.startswith(_PUBLIC_PATH_PREFIXES):
        return None

    # Resolved before the public-route check on purpose: `download_agent` is
    # public at this layer but still reads the session to decide whether the
    # caller is an operator or an enrolled agent.
    raw_token = request.cookies.get(session_store.SESSION_COOKIE)
    if raw_token:
        try:
            async with userdb_conn() as cnx:
                cur = await cnx.cursor(dictionary=True)
                try:
                    row = await session_store.load(cur, raw_token)
                    if row:
                        request.ctx.user = row
                        request.ctx.session_token = raw_token
                        if await session_store.touch(cur, row["token_hash"], row["last_seen_at"]):
                            await cnx.commit()
                finally:
                    await cur.close()
        except Exception as e:
            print(f"[!] Session lookup failed: {e}")

    user = request.ctx.user

    route = getattr(request, "route", None)
    handler = getattr(route, "handler", None) if route else None
    handler_name = getattr(handler, "__qualname__", "")

    # Public routes are exempt from everything below. This has to come before
    # the X-User-ID check: the browser keeps `userId` in localStorage and the
    # axios interceptor attaches it to /login too, so enforcing the header
    # first would make an expired session impossible to log back in from.
    if handler_name in _PUBLIC_HANDLERS:
        return None

    # Backstop for the case where the router did not attach a resolved route to
    # the request. Everything below is deny-by-default, so without this a Sanic
    # release that changes when `request.route` is populated would lock
    # operators out of the login page rather than let anything through.
    if not handler_name and _is_public_path(request.path):
        return None

    if not user:
        return _unauthorized("Authentication required")

    # `X-User-ID` is no longer identity — it is an assertion checked against
    # the session. SameSite is the primary CSRF control; requiring the header
    # on state-changing requests is the second layer, and the one that still
    # holds if SameSite is ever relaxed to None for a split-origin deployment.
    asserted = request.headers.get("X-User-ID")
    if asserted is None:
        if request.method not in _SAFE_METHODS:
            return _unauthorized("X-User-ID header required on state-changing requests")
    else:
        try:
            asserted_id = int(asserted)
        except (TypeError, ValueError):
            return _unauthorized("Malformed X-User-ID header")
        if asserted_id != int(user["user_id"]):
            return _unauthorized("X-User-ID does not match the active session")

    required = _PERMISSION_REQUIREMENTS.get(handler_name)
    if required:
        uid = int(user["user_id"])
        for permission in sorted(required):
            if not await user_has_permission(uid, permission):
                return sanic_json({
                    "status": "error",
                    "message": f"Permission denied: '{permission}' required"
                }, status=403)
        request.ctx.permission_checked = True

    return None


@app.before_server_start
async def verify_auth_wiring(app):
    """Report the auth posture of every route at boot.

    The bug this replaces was invisible precisely because nothing ever
    inspected the result of wiring `@require_permission` up: 85 routes looked
    guarded in the source and were not. Printing the tally at startup means a
    regression shows up in the very first lines of the container log.
    """
    try:
        guarded = public = session_only = 0
        unknown: list[str] = []

        for route in app.router.routes:
            name = getattr(getattr(route, "handler", None), "__qualname__", "")
            if not name:
                unknown.append("/" + "/".join(getattr(route, "parts", ())))
            elif name in _PUBLIC_HANDLERS:
                public += 1
            elif name in _PERMISSION_REQUIREMENTS:
                guarded += 1
            else:
                session_only += 1

        print(
            f"[Auth] Routes: {guarded} permission-gated, {session_only} session-only, "
            f"{public} public."
        )
        if not _PERMISSION_REQUIREMENTS:
            print("[Auth] FATAL: permission registry is empty — every route is session-only.")
        if unknown:
            print(f"[Auth] WARNING: {len(unknown)} route(s) with an unresolvable handler: {unknown[:5]}")
    except Exception as e:
        # Diagnostics must never be what stops the server from booting.
        print(f"[Auth] Wiring self-check skipped: {e}")

DEFAULT_ALERT_TEMPLATE = "Critical Alerts (default)"


def send_email(template_name: str, context: dict, fallback: str | None = None) -> bool:
    """Send a templated mail.

    `dispatch_critical_alerts` names its template per agent
    ("Critical Alerts - Agent: WIN-01"), so an operator would have to hand-create
    one row for every enrolled endpoint before any alert mail went out — and the
    only symptom of not having done so was a line in the server log. `fallback`
    keeps the per-agent override working while letting a generic template cover
    the agents nobody has customised.
    """
    config = get_mail_config()
    if not config['enabled']:
        print("[!] Email not enabled or configured")
        return False

    try:
        with sync_mysql_conn("userdb") as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT * FROM email_templates WHERE template_name = %s", (template_name,))
                template = cursor.fetchone()
                if not template and fallback:
                    cursor.execute("SELECT * FROM email_templates WHERE template_name = %s", (fallback,))
                    template = cursor.fetchone()
                    if template:
                        print(f"[i] Template '{template_name}' not found; using '{fallback}'.")
            finally:
                cursor.close()

        if not template:
            print(f"[!] Template '{template_name}' not found"
                  + (f" (fallback '{fallback}' missing too)." if fallback else "."))
            return False

        subject = render_template(template['subject_template'], context)
        body = render_template(template['body_template'], context)

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = config['from_addr']
        msg['To'] = config['to_addr']
        msg.set_content(body)

        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
            if config['use_tls']:
                server.starttls()
            if config['smtp_user'] and config['smtp_password']:
                server.login(config['smtp_user'], config['smtp_password'])
            server.send_message(msg)

        print(f"[+] Templated mail sent: {subject}")
        return True

    except Exception as e:
        print(f"[!] Templated email send error: {e}")
        return False

def dispatch_critical_alerts(agent: str, limit: int = 100) -> int:
    db_name = _agent_db_name(agent)
    try:
        with sync_mysql_conn(db_name) as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT * FROM events_alert
                    WHERE (sent IS NULL OR sent = FALSE)
                    ORDER BY id DESC LIMIT %s
                """, (limit,))
                rows = cursor.fetchall()

                lines: List[str] = []
                ids: List[int] = []

                for r in rows:
                    try:
                        severity = str(r.get('severity', '')).strip().upper()
                        if severity == 'CRITICAL':
                            line = f"[{r.get('timestamp','')}] Agent: {agent} | Source: {r.get('source','')} | Categories: {r.get('categories','')} | Message: {r.get('message','')}"
                            lines.append(line)
                            ids.append(r['id'])
                    except Exception as parse_err:
                        print(f"[!] Parse error for agent {agent}, alert ID {r.get('id')}: {parse_err}")

                if lines:
                    body = f"Critical Alerts from Agent: {agent}\n\n" + '\n'.join(lines)
                    send_email(f'Critical Alerts - Agent: {agent}', {"body": body, "agent": agent},
                               fallback=DEFAULT_ALERT_TEMPLATE)
                    cursor.executemany("UPDATE events_alert SET sent = TRUE WHERE id = %s", [(i,) for i in ids])
                    conn.commit()
                    print(f"[+] Processed {len(lines)} critical alerts for agent {agent}")

                return len(lines)
            finally:
                cursor.close()

    except Exception as db_err:
        print(f"[!] dispatch_critical_alerts DB error for agent {agent}: {db_err}")
        return 0

async def load_ai_config(agent: str):
    """Load AI configuration. Currently global for the server/agent."""
    default_config = {
        "provider": "ollama",
        "api_url": "http://host.docker.internal:11434/api",
        "model": "llama3:latest",
        "api_key": ""
    }
    try:
        async with userdb_conn() as cnx:
            cur = await cnx.cursor(dictionary=True)
            try:
                await cur.execute("SELECT * FROM ai_config ORDER BY updated_at DESC LIMIT 1")
                row = await cur.fetchone()
            finally:
                await cur.close()
        return row if row else default_config
    except Exception as e:
        print(f"[!] AI config fetch error: {e}, falling back to defaults")
        return default_config

def _fetch_rows_safely(db_name: str, query: str, params: tuple = (), context: str = "") -> list:
    try:
        with sync_mysql_conn(db_name) as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(query, params)
                return cursor.fetchall()
            finally:
                cursor.close()
    except Exception as e:
        print(f"[!] Error fetching {context}: {e}")
        return []

def fetch_unsent_siem_logs(agent: str, limit: int = 100):
    return _fetch_rows_safely(
        _agent_db_name(agent),
        "SELECT * FROM siem_events WHERE (ai_analyzed IS NULL OR ai_analyzed = FALSE) ORDER BY id ASC LIMIT %s",
        (limit,),
        f"unsent SIEM logs for {agent}",
    )

def mark_logs_as_analyzed(agent: str, log_ids: list):
    """Mark SIEM logs as analyzed by AI"""
    if not log_ids:
        return
    db_name = _agent_db_name(agent)
    try:
        with sync_mysql_conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                placeholders = ','.join(['%s'] * len(log_ids))
                cursor.execute(
                    f"UPDATE siem_events SET ai_analyzed = TRUE, ai_analyzed_at = NOW() WHERE id IN ({placeholders})",
                    log_ids,
                )
                conn.commit()
                print(f"[+] Marked {len(log_ids)} logs as analyzed for {agent}")
            finally:
                cursor.close()
    except Exception as e:
        print(f"[!] Error marking logs as analyzed for {agent}: {e}")

def fetch_critical_files_data(agent: str, limit: int = 100):
    return _fetch_rows_safely(
        _agent_db_name(agent),
        "SELECT * FROM critical_files ORDER BY id DESC LIMIT %s",
        (limit,),
        f"critical files for {agent}",
    )

def fetch_events_alert_data(agent: str, limit: int = 100):
    return _fetch_rows_safely(
        _agent_db_name(agent),
        "SELECT * FROM events_alert ORDER BY id DESC LIMIT %s",
        (limit,),
        f"events alert for {agent}",
    )

def fetch_vulnerabilities_data(agent: str, limit: int = 100):
    return _fetch_rows_safely(
        _agent_db_name(agent),
        "SELECT * FROM vulnerabilities_report ORDER BY id DESC LIMIT %s",
        (limit,),
        f"vulnerabilities_report for {agent}",
    )

def fetch_soar_actions_data(agent: str, limit: int = 100):
    return _fetch_rows_safely(
        _agent_db_name(agent),
        "SELECT * FROM soar_actions ORDER BY id DESC LIMIT %s",
        (limit,),
        f"soar_actions for {agent}",
    )

from core import mq as mq_utils

async def analyze_agent_logs(agent: str, limit: int = 100):
    """
    Refactored: Fetch logs and push to ai_manual_queue in chunks (background)
    to avoid timeout for the HTTP request.
    """
    cfg = await load_ai_config(agent)
    if not cfg:
        return {'success': False, 'error': f'AI config missing for {agent}', 'logs_analyzed': 0}

    try:
        key_b64 = getattr(app.ctx, "fernet_key", None)
        if not key_b64:
            key_b64 = await asyncio.to_thread(bootstrap_client.get_fernet_key)
        fernet_obj = Fernet(key_b64.encode("utf-8") if isinstance(key_b64, str) else key_b64)
    except Exception as e:
        return {'success': False, 'error': f'Fernet key error: {e}'}

    siem_rows   = await asyncio.to_thread(fetch_unsent_siem_logs, agent, limit)
    cf_rows     = await asyncio.to_thread(fetch_critical_files_data, agent, limit)
    alert_rows  = await asyncio.to_thread(fetch_events_alert_data, agent, limit)
    vuln_rows   = await asyncio.to_thread(fetch_vulnerabilities_data, agent, limit)
    soar_rows   = await asyncio.to_thread(fetch_soar_actions_data, agent, limit)

    all_logs = []
    for r in siem_rows:  all_logs.append(("siem_events", r))
    for r in cf_rows:    all_logs.append(("critical_files", r))
    for r in alert_rows: all_logs.append(("events_alert", r))
    for r in vuln_rows:  all_logs.append(("vulnerabilities_report", r))
    for r in soar_rows:  all_logs.append(("soar_actions", r))

    if not all_logs:
        return {'success': True, 'message': 'No new logs to analyze.', 'logs_analyzed': 0}

    chunk_size = 10
    pushed_count = 0
    msgs_published = 0

    by_table: dict = {}
    for table, row in all_logs:
        dec = decrypt_row_fields(row, ENCRYPTED_FIELDS_MAP.get(table, []), fernet_obj)
        by_table.setdefault(table, []).append(dec)

    for table, rows in by_table.items():
        for i in range(0, len(rows), chunk_size):
            batch = rows[i:i + chunk_size]
            await mq_utils.publish_to_queue(mq_utils.AI_MANUAL, agent, table, batch)
            pushed_count += len(batch)
            msgs_published += 1

    return {
        'success': True,
        'message': f"Queued {pushed_count} logs across {msgs_published} batches for background analysis.",
        'logs_queued': pushed_count,
        'batches_published': msgs_published,
        'total_records': len(all_logs)
    }

async def analyze_selected_logs(agent: str, logs: list):
    """Analyze a specific selection of logs from the UI"""
    try:
        key_b64 = getattr(app.ctx, "fernet_key", None)
        if not key_b64:
            key_b64 = await asyncio.to_thread(bootstrap_client.get_fernet_key)
        fernet_obj = Fernet(key_b64.encode("utf-8") if isinstance(key_b64, str) else key_b64)
    except Exception as e:
        return {'success': False, 'error': f'Fernet key error: {e}'}

    pushed_count = 0
    for log in logs:
        table = log.get("table")
        data  = log.get("data")
        if table and data:
            log_id = data.get("id")
            if log_id:
                row = await asyncio.to_thread(fetch_one_log_from_db, agent, table, log_id)
                if row:
                    dec = decrypt_row_fields(row, ENCRYPTED_FIELDS_MAP.get(table, []), fernet_obj)
                    await mq_utils.publish_to_queue(mq_utils.AI_MANUAL, agent, table, dec)
                    pushed_count += 1
    
    return {'success': True, 'message': f"Queued {pushed_count} selected logs for analysis."}

def fetch_one_log_from_db(agent, table, log_id):
    """Helper to fetch a single log row for re-decryption"""
    db_name = _agent_db_name(agent)
    try:
        with sync_mysql_conn(db_name) as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(f"SELECT * FROM `{table}` WHERE id = %s", (log_id,))
                return cursor.fetchone()
            finally:
                cursor.close()
    except Exception:
        return None


async def analyze_all_agents_logs():
    try:
        def get_agents():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    databases = cursor.fetchall()
                    return [db[0].replace('_db', '') for db in databases if db[0].endswith('_db')]
                finally:
                    cursor.close()

        agents = await asyncio.to_thread(get_agents)
        
        tasks = [analyze_agent_logs(agent) for agent in agents]
        agent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        results = {}
        total_analyzed = 0
        
        for agent, result in zip(agents, agent_results):
            if isinstance(result, Exception):
                results[agent] = {"success": False, "error": str(result), "logs_analyzed": 0}
            else:
                results[agent] = result
                total_analyzed += result.get('logs_analyzed', 0)
        
        return {
            'success': True,
            'total_logs_analyzed': total_analyzed,
            'agents_processed': len(agents),
            'results': results
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Error analyzing logs for all agents: {str(e)}',
            'total_logs_analyzed': 0
        }

@app.route("/api/global/stats", methods=["GET"])
async def get_global_inventory_stats(request):
    try:
        def fetch_counts():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    agents = [db[0] for db in cursor.fetchall() if db[0].endswith('_db')]

                    total_hardware = 0
                    total_software = 0
                    total_fim = 0

                    for db in agents:
                        try:
                            cursor.execute(f"USE {db}")
                            cursor.execute("SELECT COUNT(*) FROM hardware_inventory")
                            total_hardware += cursor.fetchone()[0]
                            cursor.execute("SELECT COUNT(*) FROM software_inventory")
                            total_software += cursor.fetchone()[0]
                            cursor.execute("SELECT COUNT(*) FROM fim_data")
                            total_fim += cursor.fetchone()[0]
                        except Exception:
                            continue

                    return total_hardware, total_software, total_fim
                finally:
                    cursor.close()

        hw, sw, fim = await asyncio.to_thread(fetch_counts)
        return sanic_json({
            "status": "success",
            "total_hardware": hw,
            "total_software": sw,
            "total_fim_events": fim
        })
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

def dispatch_all_critical_alerts():
    """Dispatch critical alerts for all agents"""
    try:
        with sync_mysql_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SHOW DATABASES")
                databases = cursor.fetchall()
                agents = [db[0].replace('_db', '') for db in databases if db[0].endswith('_db')]
            finally:
                cursor.close()

        total_alerts = 0
        for agent in agents:
            total_alerts += dispatch_critical_alerts(agent)

        print(f"[+] Total critical alerts processed: {total_alerts}")
        return total_alerts

    except Exception as e:
        print(f"[!] Error in dispatch_all_critical_alerts: {e}")
        return 0

def _close_sync_quiet(conn):
    try:
        if conn is not None:
            conn.close()
    except Exception:
        pass

async def _close_async_quiet(conn):
    try:
        if conn is not None:
            await conn.ensure_closed() if hasattr(conn, "ensure_closed") else conn.close()
    except Exception:
        pass

from contextlib import contextmanager, asynccontextmanager

@contextmanager
def sync_mysql_conn(db: str | None = None):
    """Sync MySQL connection with guaranteed close on exception."""
    conn = mysql.connector.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
        database=db
    )
    try:
        yield conn
    finally:
        _close_sync_quiet(conn)

@asynccontextmanager
async def userdb_conn():
    cnx = await connect_userdb()
    try:
        yield cnx
    finally:
        await _close_async_quiet(cnx)

@asynccontextmanager
async def agent_conn(agent: str):
    cnx = await connect_db_for_agent(agent)
    try:
        yield cnx
    finally:
        await _close_async_quiet(cnx)


import collections

_POOL_MAXSIZE      = 10
_POOL_IDLE_SEC     = 60


class _PooledConn:
    """Thin proxy over a mysql.connector.aio Connection. `await close()` returns
    the underlying connection to the owning pool instead of closing the socket."""
    __slots__ = ("_conn", "_pool", "_released")

    def __init__(self, conn, pool):
        self._conn = conn
        self._pool = pool
        self._released = False

    async def close(self):
        if self._released:
            return
        self._released = True
        await self._pool.release(self._conn)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __del__(self):
        if self._released:
            return
        try:
            self._pool._idle.append((self._conn, time.time()))
            self._pool._sem.release()
            self._released = True
        except Exception:
            pass


class _AsyncMySQLPool:
    def __init__(self, factory, maxsize=_POOL_MAXSIZE, max_idle_sec=_POOL_IDLE_SEC):
        self._factory = factory
        self._sem = asyncio.Semaphore(maxsize)
        self._idle = collections.deque()
        self._lock = asyncio.Lock()
        self._max_idle_sec = max_idle_sec

    async def acquire(self):
        await self._sem.acquire()
        try:
            now = time.time()
            async with self._lock:
                while self._idle:
                    conn, ts = self._idle.popleft()
                    if now - ts >= self._max_idle_sec:
                        try:
                            await conn.close()
                        except Exception:
                            pass
                        continue
                    try:
                        await conn.rollback()
                    except Exception:
                        try:
                            await conn.close()
                        except Exception:
                            pass
                        continue
                    return _PooledConn(conn, self)
            conn = await self._factory()
            return _PooledConn(conn, self)
        except BaseException:
            self._sem.release()
            raise

    async def release(self, conn):
        try:
            await conn.rollback()
        except Exception:
            pass
        try:
            async with self._lock:
                self._idle.append((conn, time.time()))
        finally:
            self._sem.release()


_userdb_pool: "_AsyncMySQLPool | None" = None
_agent_pools: "dict[str, _AsyncMySQLPool]" = {}
_agent_pools_lock = asyncio.Lock()


def _make_userdb_factory():
    async def _f():
        return await connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER,
            password=DB_PASSWORD, database="userdb",
        )
    return _f


def _agent_db_name(agent: str) -> str:
    """Map an agent identifier (possibly a Windows hostname containing '-')
    to its MySQL database name. MUST mirror server.py:_sanitize_db_name so
    every code path lands on the same DB that the ingest layer created.
    """
    safe = re.sub(r'[^A-Za-z0-9_]', '_', agent or 'agent')
    safe = safe.strip('_') or 'agent'
    return f"{safe}_db"


def _make_agent_factory(agent: str):
    db_name = _agent_db_name(agent)
    async def _f():
        try:
            return await connect(
                host=DB_HOST, port=DB_PORT, user=DB_USER,
                password=DB_PASSWORD, database=db_name,
            )
        except Exception:
            if agent.startswith("Agent_"):
                alt_db = f"{agent[6:]}_db"
                return await connect(
                    host=DB_HOST, port=DB_PORT, user=DB_USER,
                    password=DB_PASSWORD, database=alt_db,
                )
            raise
    return _f


async def connect_db_for_agent(agent: str):
    global _agent_pools
    pool = _agent_pools.get(agent)
    if pool is None:
        async with _agent_pools_lock:
            pool = _agent_pools.get(agent)
            if pool is None:
                pool = _AsyncMySQLPool(_make_agent_factory(agent))
                _agent_pools[agent] = pool
    return await pool.acquire()


async def connect_userdb():
    global _userdb_pool
    if _userdb_pool is None:
        _userdb_pool = _AsyncMySQLPool(_make_userdb_factory())
    return await _userdb_pool.acquire()

_FERNET_KEY_PATH = os.getenv(
    "FERNET_KEY_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "fernet.key"),
)


def load_or_create_fernet_key() -> str:
    """Read the persisted Fernet key, or generate one on first boot."""
    path = _FERNET_KEY_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass
    if os.path.exists(path):
        try:
            with open(path, "rb") as f:
                key = f.read().strip()
            if key:
                return key.decode("utf-8") if isinstance(key, bytes) else key
        except Exception as e:
            print(f"[!] Could not read existing Fernet key at {path}: {e}", flush=True)
    key = Fernet.generate_key()
    try:
        with open(path, "wb") as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        print(f"[+] Generated new Fernet key at {path}", flush=True)
    except Exception as e:
        print(f"[!] Could not persist generated Fernet key: {e}", flush=True)
    return key.decode("utf-8")


def get_local_fernet_key(*_, **__) -> str:
    return load_or_create_fernet_key()


class BootstrapError(Exception):
    """Kept for legacy `except BootstrapError` blocks; never raised in CE."""


class _NoOpBootstrapClient:
    """Drop-in replacement for legacy bootstrap clients.

    Community edition: every method is a local-only no-op that returns
    "active community" status. Same shape so legacy callers keep working
    without surgery.
    """

    def __init__(self):
        self._fernet_key = None
        self.cache = {
            "active": True,
            "tier": "Community",
            "tiers": ["Community"],
            "expires_at": None,
            "fernet_key": None,
        }

    def status(self, reveal_key: bool = False) -> dict:
        if reveal_key and not self.cache.get("fernet_key"):
            self.get_fernet_key()
        return dict(self.cache)

    def get_fernet_key(self) -> str:
        if self._fernet_key is None:
            self._fernet_key = load_or_create_fernet_key()
            self.cache["fernet_key"] = self._fernet_key
        return self._fernet_key

    def validate_or_exit(self):
        self.get_fernet_key()
        print("[+] Sentora Community Edition — local key initialised.")


bootstrap_client = _NoOpBootstrapClient()


@app.before_server_start
async def setup_db_pool(app):
    print(f"[*] Initializing database connection pool to {DB_HOST}...")
    app.ctx.db_pool = await aiomysql.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db='userdb',
        autocommit=True,
        minsize=5,
        maxsize=20
    )

@app.exception(Exception)
async def handle_exception(request, exception):
    if hasattr(exception, "status_code") and exception.status_code in (404, 405):
        return None

    status_code = getattr(exception, "status_code", 500)
    print(f"[!] Unhandled Exception: {exception}")
    return sanic_json({
        "status": "error",
        "message": "An internal server error occurred.",
        "details": str(exception) if app.debug else "Contact administrator"
    }, status=status_code)

@app.before_server_start
async def init_local_keys(app):
    await asyncio.to_thread(bootstrap_client.validate_or_exit)
    app.ctx.fernet_key = bootstrap_client.get_fernet_key()


@app.after_server_stop
async def close_db_pool(app):
    if hasattr(app.ctx, "db_pool"):
        print("[*] Closing database connection pool...")
        app.ctx.db_pool.close()
        await app.ctx.db_pool.wait_closed()

def decrypt_row_fields(row: dict, encrypted_fields: list, fernet: Fernet) -> dict:
    out = dict(row)
    for field in encrypted_fields or []:
        if field not in out:
            continue
        val = out[field]
        if not isinstance(val, str):
            continue
        if not val.startswith(ENC_PREFIX):
            continue
        token_b64 = val[len(ENC_PREFIX):]
        try:
            pt = fernet.decrypt(token_b64.encode("utf-8"))
            try:
                decoded = pyjson.loads(pt.decode("utf-8"))
            except Exception:
                decoded = pt.decode("utf-8")
            out[field] = decoded
        except InvalidToken:
            out[field] = val
    return out

async def stream_from_db_dec(table: str, agent: str,
                             connect_db_for_agent,
                             encrypted_fields: list = None,
                             limit: int = 1000,
                             rename_map: dict = None):
    """
    - connect_db_for_agent: senin mevcut helper'ını kullanır (aynı imza).
    - encrypted_fields: o tablonun şifrelenen sütunlarının isim listesi, örn: ["message","path"]
    """
    try:
        key_b64 = getattr(app.ctx, "fernet_key", None)
        if not key_b64:
            key_b64 = bootstrap_client.get_fernet_key()
        fernet_obj = Fernet(key_b64.encode("utf-8") if isinstance(key_b64, str) else key_b64)

        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()

        query = f"SELECT * FROM {table} ORDER BY id DESC"
        if limit is not None:
            query += f" LIMIT {limit}"
        try:
            await cursor.execute(query)
        except Exception as qerr:
            err_str = str(qerr)
            if "1146" in err_str or "doesn't exist" in err_str.lower():
                await cursor.close(); await cnx.close()
                return HTTPResponse(body="[]", content_type="application/json; charset=utf-8")
            raise
        columns = [col[0] for col in cursor.description]
        rows = await cursor.fetchall()
        await cursor.close()
        await cnx.close()

        dict_rows = [dict(zip(columns, row)) for row in rows]

        if encrypted_fields is None:
            default_map = {
                "siem_events": ["message"],
                "critical_files": ["path","owner","grp","permissions","last_opened"],
                "portscan_result": ["service","product","version"],
                "packages": ["package","version"],
                "vulnerabilities_report": ["package_name","package_version","vulnerability_id","summary","details_url"],
                "events_alert": ["message","source"]
            }
            encrypted_fields = default_map.get(table, [])

        dec_rows = [decrypt_row_fields(r, encrypted_fields, fernet_obj) for r in dict_rows]

        if rename_map:
            for r in dec_rows:
                for old_k, new_k in rename_map.items():
                    if old_k in r:
                        r[new_k] = r.pop(old_k)

        body = '[' + ','.join([pyjson.dumps(r, cls=CustomEncoder, ensure_ascii=False) for r in dec_rows]) + ']'
        return HTTPResponse(body=body, content_type="application/json; charset=utf-8")

    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)

async def stream_from_db(table: str, agent: str, limit: int = 1000):
    try:
        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()
        query = f"SELECT * FROM {table} ORDER BY id DESC"
        if limit is not None:
            query += f" LIMIT {limit}"
        try:
            await cursor.execute(query)
        except Exception as qerr:
            err_str = str(qerr)
            if "1146" in err_str or "doesn't exist" in err_str.lower():
                await cursor.close(); await cnx.close()
                return HTTPResponse(body="[]", content_type="application/json; charset=utf-8")
            raise
        columns = [col[0] for col in cursor.description]
        rows = await cursor.fetchall()
        await cursor.close(); await cnx.close()

        json_lines = [pyjson.dumps(dict(zip(columns, row)), cls=CustomEncoder, ensure_ascii=False) for row in rows]
        return HTTPResponse(
            body='[' + ','.join(json_lines) + ']',
            content_type="application/json; charset=utf-8"
        )
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)


import psutil

def _server_disk_percent() -> float:
    """Return the largest disk usage percent across reachable mountpoints.

    We look at every candidate mountpoint and pick the highest non-zero
    value with non-zero total bytes. This survives the Docker Desktop /
    WSL2 case where /host_disk maps to an almost-empty WSL VM rootfs and
    reports 0% even though the real host disk is full.
    """
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(p: str):
        if p and p not in seen:
            seen.add(p)
            candidates.append(p)

    if os.path.exists('/host_disk'):
        _add('/host_disk')
    _add('/')
    _add('C:\\')

    try:
        for part in psutil.disk_partitions(all=True):
            opts = (part.opts or '').lower()
            if any(tag in opts for tag in ('cdrom', 'removable')):
                continue
            mp = part.mountpoint or ''
            if not mp:
                continue
            if mp.startswith(('/proc', '/sys', '/dev', '/run')):
                continue
            _add(mp)
    except Exception:
        pass

    best = 0.0
    for c in candidates:
        try:
            usage = psutil.disk_usage(c)
            if usage.total <= 0:
                continue
            pct = float(usage.percent)
            if pct > best:
                best = pct
        except Exception:
            continue
    return best


@app.route("/server/resources", methods=["GET"])
async def get_server_resources(request):
    try:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        disk = await asyncio.to_thread(_server_disk_percent)
        return sanic_json({
            "status": "success",
            "cpu_usage": cpu,
            "ram_usage": ram,
            "disk_usage": disk,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("read_telemetry")
@app.route("/<agent>/siem-events")
async def get_siem_events(request, agent):
    return await stream_from_db_dec(
        "siem_events", agent, connect_db_for_agent,
                encrypted_fields=ENCRYPTED_FIELDS_MAP["siem_events"]
    )



@require_permission("read_telemetry")
@app.route("/<agent>/events_alert")
async def get_events_alert(request, agent):
    return await stream_from_db_dec(
        "events_alert", agent, connect_db_for_agent,
                encrypted_fields=ENCRYPTED_FIELDS_MAP["events_alert"]
    )

@require_permission("read_telemetry")
@app.route("/api/agent/<agent>/inventory/hardware")
async def get_hardware_inventory(request, agent):
    fields = ENCRYPTED_FIELDS_MAP.get("hardware_inventory")
    return await stream_from_db_dec("hardware_inventory", agent, connect_db_for_agent, encrypted_fields=fields)

@require_permission("read_telemetry")
@app.route("/api/agent/<agent>/inventory/software")
async def get_software_inventory(request, agent):
    fields = ENCRYPTED_FIELDS_MAP.get("packages")
    return await stream_from_db_dec("packages", agent, connect_db_for_agent,                                    encrypted_fields=fields, rename_map={"package": "name"})

@require_permission("read_telemetry")
@app.route("/api/agent/<agent>/inventory/network")
async def get_network_inventory(request, agent):
    return await stream_from_db_dec("network_connections", agent, connect_db_for_agent)

@require_permission("read_telemetry")
@app.route("/api/agent/<agent>/fim")
async def get_fim_data(request, agent):
    fields = ENCRYPTED_FIELDS_MAP.get("fim_data")
    return await stream_from_db_dec("fim_data", agent, connect_db_for_agent, encrypted_fields=fields)

@require_permission("read_telemetry")
@app.route("/api/agent/<agent>/packages")
async def get_packages_data(request, agent):
    fields = ENCRYPTED_FIELDS_MAP.get("packages")
    return await stream_from_db_dec("packages", agent, connect_db_for_agent, encrypted_fields=fields)

@require_permission("role_create")
@require_permission("manage_users")
@app.route("/roles", methods=["POST"])
async def create_role(request):
    data = request.json or {}
    role_name = data.get("role_name")
    
    created_by = current_username(request)

    if not role_name:
        return sanic_json({
            "status": "error",
            "message": "Role name is required."
        }, status=400)

    if role_name in ["admin", "user", "guest"]:
        return sanic_json({
            "status": "error",
            "message": f"Role '{role_name}' is a system-defined role and cannot be created manually."
        }, status=403)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT id FROM roles WHERE role_name = %s", (role_name,))
        if await cursor.fetchone():
            await cursor.close()
            await cnx.close()
            return sanic_json({
                "status": "error",
                "message": f"Role '{role_name}' already exists."
            }, status=409)

        await cursor.execute("""
            INSERT INTO roles (role_name, created_by, created_at)
            VALUES (%s, %s, NOW())
        """, (role_name, created_by))

        role_id = cursor.lastrowid
        await cnx.commit()
        await cursor.close()
        await cnx.close()

        return sanic_json({
            "status": "success",
            "message": f"Role '{role_name}' created successfully.",
            "role_id": role_id
        }, status=201)

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }, status=500)
    

@require_permission("user_create")
@app.route("/users", methods=["POST"])
async def create_user(request):
    try:
        data_raw = request.json or {}
        user_data = CreateUserRequest(**data_raw)
        username = user_data.username
        password = user_data.password
        role = user_data.role
    except Exception as e:
        if hasattr(e, 'errors') and callable(e.errors):
            errors = e.errors()
            if len(errors) > 0 and 'msg' in errors[0]:
                clean_msg = errors[0]['msg']
                if clean_msg.startswith("Value error, "):
                    clean_msg = clean_msg[len("Value error, "):]
                return sanic_json({"status": "error", "message": clean_msg}, status=400)
                
        return sanic_json({"status": "error", "message": f"Invalid input: {str(e)}"}, status=400)
    
    created_by = current_username(request)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        allowed_roles = await get_allowed_roles()
        if role not in allowed_roles:
            await cursor.close(); await cnx.close()
            return sanic_json({
                "status": "error",
                "message": f"Invalid role. Allowed roles: {', '.join(allowed_roles)}"
            }, status=400)

        await cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if await cursor.fetchone():
            await cursor.close()
            await cnx.close()
            return sanic_json({
                "status": "error",
                "message": "Username already exists."
            }, status=409)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        await cursor.execute("""
            INSERT INTO users (username, password, role, created_by, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """, (username, hashed_password, role, created_by))

        user_id = cursor.lastrowid
        await cnx.commit()
        await cursor.close()
        await cnx.close()

        await audit_log(request, "CREATE_USER", username, f"Role assigned: {role}")

        return sanic_json({
            "status": "success",
            "message": f"User '{username}' created successfully with role '{role}'.",
            "user_id": user_id
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }, status=500)

@require_permission("manage_users")
@app.route("/users/<user_id>/role", methods=["PUT"])
async def update_user_role(request, user_id):
    data = request.json or {}
    new_role = data.get("role")
    # Was taken from the request body, so the caller chose whose name went in
    # the audit column. Same class of bug as the old X-User-ID header.
    updated_by = current_username(request)

    allowed_roles = await get_allowed_roles()
    if new_role not in allowed_roles:
        return sanic_json({
            "status": "error",
            "message": f"Invalid role. Allowed roles: {', '.join(allowed_roles)}"
        }, status=400)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT username, role FROM users WHERE id = %s", (user_id,))
        user_info = await cursor.fetchone()

        if not user_info:
            await cursor.close()
            await cnx.close()
            return sanic_json({
                "status": "error",
                "message": "User not found."
            }, status=404)

        username, current_role = user_info

        if current_role == "admin" and new_role != "admin":
            await cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_count = (await cursor.fetchone())[0]

            if admin_count <= 1:
                await cursor.close()
                await cnx.close()
                return sanic_json({
                    "status": "error",
                    "message": "Cannot remove admin role from the last admin user."
                }, status=403)

        await cursor.execute("""
            UPDATE users
            SET role = %s, updated_by = %s, updated_at = NOW()
            WHERE id = %s
        """, (new_role, updated_by, user_id))

        await cnx.commit()
        await cursor.close()
        await cnx.close()

        # Their live sessions were issued against the old role, so drop them
        # rather than let a demoted user keep the privileges until timeout.
        await revoke_user_sessions(int(user_id), "role changed")

        await audit_log(request, "UPDATE_USER_ROLE", username, f"Updated role to {new_role}")

        return sanic_json({
            "status": "success",
            "message": f"User '{username}' role updated to '{new_role}'. Their active sessions were ended."
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }, status=500)

@require_permission("manage_users")
@app.route("/users/<user_id>/password", methods=["PUT"])
async def admin_reset_password(request, user_id):
    data = request.json or {}
    new_password = data.get("password")
    
    if not new_password or len(new_password) < 6:
        return sanic_json({
            "status": "error",
            "message": "Password must be at least 6 characters."
        }, status=400)

    try:
        # This wrote `new_password` straight into the column. Besides storing
        # the password in the clear, it also locked the account out: `login`
        # runs bcrypt.checkpw against the stored value, which raises on
        # anything that isn't a bcrypt hash.
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user_id))
        await cnx.commit()
        await cursor.close(); await cnx.close()

        await revoke_user_sessions(int(user_id), "password reset by admin")

        await audit_log(request, "RESET_PASSWORD", user_id, f"Password reset for user ID {user_id}")

        return sanic_json({"status": "success", "message": "User password reset. Their active sessions were ended."})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_users")
@app.route("/users/<user_id>", methods=["DELETE"])
async def delete_user(request, user_id):
    try:
        target_uid = int(user_id)
    except (ValueError, TypeError):
        return sanic_json({"status": "error", "message": "Invalid user ID format"}, status=400)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT username, role FROM users WHERE id = %s", (target_uid,))
        user = await cursor.fetchone()

        if not user:
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "error", "message": "User not found"}, status=404)

        username, role = user
        if role == "admin":
            await cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_count = (await cursor.fetchone())[0]
            if admin_count <= 1:
                await cursor.close(); await cnx.close()
                return sanic_json({"status": "error", "message": "Cannot delete the last admin user."}, status=403)

        await cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        await cnx.commit()
        await cursor.close(); await cnx.close()

        await revoke_user_sessions(target_uid, "account deleted")

        await audit_log(request, "DELETE_USER", username, f"Deleted user ID {user_id}")

        return sanic_json({
            "status": "success",
            "message": f"User '{username}' deleted successfully."
        })
    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {e}"
        }, status=500)

async def fetch_ldap_users():
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("SELECT ldap_host, ldap_port, bind_dn, bind_password, users_base FROM ldap_conf")
        row = await cursor.fetchone()
        await cursor.close(); await cnx.close()

        ldap_users = []

        ldap_host, ldap_port, bind_dn, encrypted_password, search_base = row
        bind_password = decrypt_password(encrypted_password)
        try:
            server = Server(ldap_host, port=ldap_port, get_info=ALL)
            conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

            conn.search(search_base, '(objectClass=inetOrgPerson)', attributes=['uid', 'cn'])

            for entry in conn.entries:
                ldap_users.append({
                    "username": f"{entry.uid}" if 'uid' in entry else f"(no uid)",
                    "role": "ldap",
                    "created_by": "LDAP",
                    "created_at": None
                })

        except Exception as ldap_err:
            print(f"[!] LDAP error: {ldap_err}")

        return ldap_users

    except Exception as e:
        print(f"[!] Error fetching LDAP users: {e}")
        return []


@require_permission("manage_users")
@app.route("/users", methods=["GET"])
async def list_users(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("""
            SELECT id, username, role, created_by, created_at
            FROM users
            ORDER BY created_at DESC
        """)

        users = []
        for row in await cursor.fetchall():
            users.append({
                "id": row[0],
                "username": row[1],
                "role": row[2],
                "created_by": row[3],
                "created_at": row[4].strftime("%Y-%m-%d %H:%M:%S") if row[4] else None
            })

        await cursor.close(); await cnx.close()

        ldap_users = await fetch_ldap_users()
        all_users = users + ldap_users

        return sanic_json({
            "status": "success",
            "users": all_users,
            "total": len(all_users)
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }, status=500)

async def get_allowed_roles():
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("SELECT role_name FROM roles")
        roles = [row[0] for row in await cursor.fetchall()]
        await cursor.close()
        await cnx.close()
        return roles
    except Exception as e:
        raise SanicException(f"Failed to fetch roles: {str(e)}", status_code=500)

@require_permission("read_telemetry")
@app.route("/<agent>/resources")
async def get_resources(request, agent):
    return await stream_from_db("resource_usage", agent)


@require_permission("read_telemetry")
@app.route("/<agent>/critical_files")
async def get_critical_files(request, agent):
    return await stream_from_db_dec(
        "critical_files", agent, connect_db_for_agent,
                encrypted_fields=ENCRYPTED_FIELDS_MAP["critical_files"]
    )


@require_permission("read_telemetry")
@app.route("/<agent>/disks")
async def get_disk_usage(request, agent):
    return await stream_from_db("disk_usage", agent)

@require_permission("read_telemetry")
@app.route("/<agent>/vulnerabilities_report")
async def get_vulnerabilities_report(request, agent):
    return await stream_from_db_dec(
        "vulnerabilities_report", agent, connect_db_for_agent,
                encrypted_fields=ENCRYPTED_FIELDS_MAP["vulnerabilities_report"]
    )

@require_permission("read_telemetry")
@app.route("/<agent>/portscan_result")
async def get_portscan_result(request, agent):
    return await stream_from_db("portscan_result", agent)

@require_permission("read_telemetry")
@app.route("/<agent>/agent_info")
async def get_agent_info(request, agent):
    return await stream_from_db("agent_info", agent)

@require_permission("read_telemetry")
@app.route("/<agent>/packages")
async def get_packages(request, agent):
    return await stream_from_db_dec(
        "packages", agent, connect_db_for_agent,
                encrypted_fields=ENCRYPTED_FIELDS_MAP["packages"]
    )

@require_permission("read_telemetry")
@app.route("/<agent>/ai_logs")
async def get_ai_logs(request, agent):
    return await stream_from_db("ai_log_checker_results", agent)

@require_permission("read_telemetry")
@app.route("/<agent>/ai_insights")
async def get_agent_ai_insights(request, agent):
    """Fetch latest 20 AI insights for a specific agent"""
    return await stream_from_db("ai_analysis_results", agent, limit=20)



@require_permission("read_telemetry")
@app.route("/<agent>/docker_containers")
async def get_docker_containers(request, agent):
    return await stream_from_db("docker_containers", agent)

@require_permission("analyze_logs")
@app.route("/analyze-logs", methods=["POST"])
async def analyze_logs_all_agents(request):
    try:
        result = await analyze_all_agents_logs()
        return sanic_json(result)
    except Exception as e:
        return sanic_json({
            "success": False,
            "error": f"Error analyzing logs: {str(e)}",
            "total_logs_analyzed": 0
        }, status=500)


async def _push_recent_alerts_to_defensive(agent: str, limit: int = 25) -> dict:
    """Fetch the most-recent events_alert rows for an agent and queue each one
    on the AI_SOAR (defensive) RabbitMQ queue. This is the single mechanism
    behind both the manual `/analyze-defensive/<agent>` endpoint and the
    periodic auto-sweep, so they behave identically.
    """
    rows = await asyncio.to_thread(fetch_events_alert_data, agent, limit)
    if not rows:
        return {"queued": 0, "reason": "no events_alert rows"}

    try:
        key_b64 = getattr(app.ctx, "fernet_key", None)
        if not key_b64:
            key_b64 = await asyncio.to_thread(bootstrap_client.get_fernet_key)
        fernet_obj = Fernet(key_b64.encode("utf-8") if isinstance(key_b64, str) else key_b64)
    except Exception:
        fernet_obj = None

    pushed = 0
    for row in rows:
        try:
            payload = decrypt_row_fields(row, ENCRYPTED_FIELDS_MAP.get("events_alert", []), fernet_obj) if fernet_obj else dict(row)
        except Exception:
            payload = dict(row)
        try:
            ok = await mq_utils.publish_to_queue(mq_utils.AI_SOAR, agent, "events_alert", payload)
            if ok:
                pushed += 1
        except Exception as e:
            print(f"[!] defensive push failed agent={agent}: {e}", flush=True)
    return {"queued": pushed, "total_rows": len(rows)}


@require_permission("analyze_logs")
@app.route("/analyze-defensive/<agent>", methods=["POST"])
async def trigger_defensive_scan(request, agent):
    """Manually push the latest events_alert rows for an agent through the
    defensive AI worker. Returns immediately; results land in
    ai_analysis_results once the worker finishes (visible in AI Analysis UI).
    """
    data = request.json or {}
    try:
        limit = max(1, min(int(data.get("limit", 25)), 200))
    except Exception:
        limit = 25
    try:
        result = await _push_recent_alerts_to_defensive(agent, limit)
        return sanic_json({"success": True, "agent": agent, **result})
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)


# ─────────────────────── Shadow Mode (defensive AI) ───────────────────────
# When AI_SHADOW_MODE is set on the defensive worker, auto-dispatchable
# verdicts are saved as `AI_DEFENSIVE_SHADOW` insights with shadow_status
# 'pending' instead of being executed. The operator reviews them in the
# SOAR Hub and either approves (→ real SOAR action is queued) or rejects
# (→ recorded and hidden from pending list). No retention timer — proposals
# live until decided.
#
# Every approve/reject decision is written to shadow_audit_chain, a
# hash-chained append-only table that lets you prove a decision was not
# tampered with after the fact (useful for compliance audits).

_CHAIN_DDL = """
CREATE TABLE IF NOT EXISTS shadow_audit_chain (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    shadow_id     INT NOT NULL,
    action        VARCHAR(64)  NOT NULL,
    target        VARCHAR(512) NOT NULL,
    decision      VARCHAR(16)  NOT NULL,
    decided_by    VARCHAR(128) NOT NULL,
    decided_at    VARCHAR(32)  NOT NULL,
    note          TEXT,
    prev_hash     CHAR(64)     NOT NULL,
    row_hash      CHAR(64)     NOT NULL,
    INDEX idx_shadow_id (shadow_id)
)
"""

async def _chain_init(cnx):
    cur = await cnx.cursor()
    try:
        await cur.execute(_CHAIN_DDL)
        await cnx.commit()
    finally:
        await cur.close()


async def _chain_append(cnx, shadow_id: int, action: str, target: str,
                         decision: str, decided_by: str, note: str = '') -> str:
    await _chain_init(cnx)
    cur = await cnx.cursor(dictionary=True)
    try:
        await cur.execute(
            "SELECT row_hash FROM shadow_audit_chain ORDER BY id DESC LIMIT 1"
        )
        last = await cur.fetchone()
        prev_hash = last['row_hash'] if last else ('0' * 64)

        decided_at_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        payload = f"{shadow_id}|{action}|{target}|{decision}|{decided_by}|{decided_at_str}|{prev_hash}"
        row_hash = hashlib.sha256(payload.encode()).hexdigest()

        await cur.execute(
            """
            INSERT INTO shadow_audit_chain
                (shadow_id, action, target, decision, decided_by, decided_at, note, prev_hash, row_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (shadow_id, action, target, decision, decided_by, decided_at_str, note or '', prev_hash, row_hash),
        )
        await cnx.commit()
    finally:
        await cur.close()
    return row_hash


async def _chain_verify(cnx) -> dict:
    cur = await cnx.cursor(dictionary=True)
    try:
        await cur.execute("SHOW TABLES LIKE 'shadow_audit_chain'")
        if not await cur.fetchone():
            return {"valid": True, "entries": 0, "note": "chain not yet initialized"}
        await cur.execute("SELECT * FROM shadow_audit_chain ORDER BY id ASC")
        rows = await cur.fetchall()
    finally:
        await cur.close()

    if not rows:
        return {"valid": True, "entries": 0}

    prev_hash = '0' * 64
    for i, row in enumerate(rows):
        da = row['decided_at']
        da_str = da.strftime('%Y-%m-%dT%H:%M:%SZ') if hasattr(da, 'strftime') else str(da)
        payload = (
            f"{row['shadow_id']}|{row['action']}|{row['target']}|"
            f"{row['decision']}|{row['decided_by']}|{da_str}|{row['prev_hash']}"
        )
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if row['row_hash'] != expected or row['prev_hash'] != prev_hash:
            return {
                "valid": False,
                "entries": len(rows),
                "tampered_at_position": i + 1,
                "chain_id": row['id'],
                "shadow_id": row['shadow_id'],
            }
        prev_hash = row['row_hash']

    return {"valid": True, "entries": len(rows), "last_hash": prev_hash}

@require_permission("read_telemetry")
@app.route("/<agent>/shadow/pending", methods=["GET"])
async def list_shadow_pending(request, agent):
    """Return pending shadow proposals for one agent, enriched with prior-execution context."""
    try:
        async with agent_conn(agent) as cnx:
            cur = await cnx.cursor(dictionary=True)
            try:
                await cur.execute(
                    """
                    SELECT a.id, a.timestamp, a.source_file, a.critical_summary, a.source_data,
                           a.proposed_action, a.proposed_target, a.shadow_status,
                           a.shadow_decided_at, a.shadow_decided_by, a.created_at,
                           (SELECT COUNT(*) FROM automations au
                            WHERE LOWER(au.action) = LOWER(a.proposed_action)
                              AND au.target = a.proposed_target) AS ctx_prev_count,
                           (SELECT MAX(au.updated_at) FROM automations au
                            WHERE LOWER(au.action) = LOWER(a.proposed_action)
                              AND au.target = a.proposed_target) AS ctx_last_seen,
                           (SELECT au.status FROM automations au
                            WHERE LOWER(au.action) = LOWER(a.proposed_action)
                              AND au.target = a.proposed_target
                            ORDER BY au.updated_at DESC LIMIT 1) AS ctx_last_status
                    FROM ai_analysis_results a
                    WHERE a.source_file = 'AI_DEFENSIVE_SHADOW'
                      AND a.shadow_status = 'pending'
                    ORDER BY a.id DESC
                    LIMIT 200
                    """
                )
                rows = list(await cur.fetchall())
            finally:
                await cur.close()
        for r in rows:
            r['agent'] = agent
            for k in ('created_at', 'timestamp', 'shadow_decided_at', 'ctx_last_seen'):
                if r.get(k) and hasattr(r[k], 'isoformat'):
                    r[k] = r[k].isoformat()
            r['ctx_prev_count'] = int(r.get('ctx_prev_count') or 0)
        return sanic_json({"success": True, "results": rows})
    except Exception as e:
        if "doesn't exist" in str(e).lower() or "1146" in str(e):
            return sanic_json({"success": True, "results": []})
        return sanic_json({"success": False, "error": str(e)}, status=500)


@require_permission("read_telemetry")
@app.route("/shadow/pending", methods=["GET"])
async def list_shadow_pending_all(request):
    """Return pending shadow proposals across every agent."""
    try:
        def get_agent_names():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    return [d[0].replace('_db', '') for d in cursor.fetchall() if d[0].endswith('_db')]
                finally:
                    cursor.close()

        agents = await asyncio.to_thread(get_agent_names)
        out = []
        for ag in agents:
            try:
                async with agent_conn(ag) as cnx:
                    cur = await cnx.cursor(dictionary=True)
                    try:
                        await cur.execute(
                            """
                            SELECT a.id, a.timestamp, a.source_file, a.critical_summary, a.source_data,
                                   a.proposed_action, a.proposed_target, a.shadow_status,
                                   a.shadow_decided_at, a.shadow_decided_by, a.created_at,
                                   (SELECT COUNT(*) FROM automations au
                                    WHERE LOWER(au.action) = LOWER(a.proposed_action)
                                      AND au.target = a.proposed_target) AS ctx_prev_count,
                                   (SELECT MAX(au.updated_at) FROM automations au
                                    WHERE LOWER(au.action) = LOWER(a.proposed_action)
                                      AND au.target = a.proposed_target) AS ctx_last_seen,
                                   (SELECT au.status FROM automations au
                                    WHERE LOWER(au.action) = LOWER(a.proposed_action)
                                      AND au.target = a.proposed_target
                                    ORDER BY au.updated_at DESC LIMIT 1) AS ctx_last_status
                            FROM ai_analysis_results a
                            WHERE a.source_file = 'AI_DEFENSIVE_SHADOW'
                              AND a.shadow_status = 'pending'
                            ORDER BY a.id DESC LIMIT 100
                            """
                        )
                        for r in await cur.fetchall():
                            r['agent'] = ag
                            for k in ('created_at', 'timestamp', 'shadow_decided_at', 'ctx_last_seen'):
                                if r.get(k) and hasattr(r[k], 'isoformat'):
                                    r[k] = r[k].isoformat()
                            r['ctx_prev_count'] = int(r.get('ctx_prev_count') or 0)
                            out.append(r)
                    finally:
                        await cur.close()
            except Exception as e:
                if "doesn't exist" in str(e).lower() or "1146" in str(e):
                    continue
                print(f"[!] shadow/pending skip agent={ag}: {e}", flush=True)
                continue
        out.sort(key=lambda x: x.get('created_at') or '', reverse=True)
        return sanic_json({"success": True, "results": out})
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)


@require_permission("read_telemetry")
@app.route("/<agent>/shadow/chain/verify", methods=["GET"])
async def verify_shadow_chain(request, agent):
    """Verify the cryptographic hash chain for one agent's shadow audit log."""
    try:
        async with agent_conn(agent) as cnx:
            result = await _chain_verify(cnx)
        result['agent'] = agent
        return sanic_json({"success": True, **result})
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)


@require_permission("read_telemetry")
@app.route("/shadow/chain/verify", methods=["GET"])
async def verify_shadow_chain_global(request):
    """Verify shadow audit chain integrity across all agents."""
    try:
        def get_agent_names():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    return [d[0].replace('_db', '') for d in cursor.fetchall() if d[0].endswith('_db')]
                finally:
                    cursor.close()

        agents = await asyncio.to_thread(get_agent_names)
        results = []
        all_valid = True
        for ag in agents:
            try:
                async with agent_conn(ag) as cnx:
                    r = await _chain_verify(cnx)
                r['agent'] = ag
                results.append(r)
                if not r.get('valid', True):
                    all_valid = False
            except Exception:
                continue
        return sanic_json({"success": True, "all_valid": all_valid, "agents": results})
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)


@require_permission("manage_soar")
@app.route("/<agent>/shadow/<insight_id:int>/approve", methods=["POST"])
async def approve_shadow(request, agent, insight_id):
    """Approve a pending shadow proposal → dispatch the proposed SOAR action."""
    try:
        async with agent_conn(agent) as cnx:
            cur = await cnx.cursor(dictionary=True)
            try:
                await cur.execute(
                    """
                    SELECT id, proposed_action, proposed_target, shadow_status, critical_summary
                    FROM ai_analysis_results WHERE id = %s
                    """,
                    (insight_id,),
                )
                row = await cur.fetchone()
            finally:
                await cur.close()

        if not row:
            return sanic_json({"success": False, "error": "shadow proposal not found"}, status=404)
        if row.get('shadow_status') != 'pending':
            return sanic_json(
                {"success": False, "error": f"proposal already {row.get('shadow_status') or 'finalized'}"},
                status=409,
            )

        action = row.get('proposed_action') or ''
        target = row.get('proposed_target') or ''
        if not action or not target:
            return sanic_json({"success": False, "error": "proposal has no action/target"}, status=400)

        actor = ''
        try:
            actor = (request.ctx.session.get('username') if getattr(request.ctx, 'session', None) else '') or ''
        except Exception:
            actor = ''
        if not actor:
            actor = request.headers.get('X-Forwarded-User') or 'operator'

        soar_result = await call_agent_soar(
            agent,
            action=action,
            target=target,
            comment=f"Shadow approved by {actor}: insight#{insight_id}",
        )

        chain_hash = ''
        async with agent_conn(agent) as cnx:
            cur = await cnx.cursor()
            try:
                await cur.execute(
                    """
                    UPDATE ai_analysis_results
                    SET shadow_status = 'approved',
                        shadow_decided_at = NOW(),
                        shadow_decided_by = %s,
                        critical_summary = CONCAT(critical_summary, '\n[APPROVED] ', %s, ' by ', %s)
                    WHERE id = %s
                    """,
                    (actor, action.upper(), actor, insight_id),
                )
                await cnx.commit()
            finally:
                await cur.close()
            chain_hash = await _chain_append(cnx, insight_id, action, target, 'approved', actor)

        return sanic_json({
            "success": True,
            "insight_id": insight_id,
            "action": action,
            "target": target,
            "dispatched": bool(soar_result.get('ok')),
            "soar_result": soar_result,
            "chain_hash": chain_hash,
        })
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)


@require_permission("manage_soar")
@app.route("/<agent>/shadow/<insight_id:int>/reject", methods=["POST"])
async def reject_shadow(request, agent, insight_id):
    """Reject a pending shadow proposal → record decision, no action taken."""
    data = request.json or {}
    note = (data.get('note') or '').strip()[:240]
    try:
        actor = ''
        try:
            actor = (request.ctx.session.get('username') if getattr(request.ctx, 'session', None) else '') or ''
        except Exception:
            actor = ''
        if not actor:
            actor = request.headers.get('X-Forwarded-User') or 'operator'

        action_for_chain = ''
        target_for_chain = ''
        async with agent_conn(agent) as cnx:
            cur = await cnx.cursor(dictionary=True)
            try:
                await cur.execute(
                    "SELECT proposed_action, proposed_target FROM ai_analysis_results WHERE id = %s",
                    (insight_id,),
                )
                meta = await cur.fetchone()
                action_for_chain = (meta or {}).get('proposed_action') or ''
                target_for_chain = (meta or {}).get('proposed_target') or ''
            finally:
                await cur.close()

            cur2 = await cnx.cursor()
            try:
                await cur2.execute(
                    """
                    UPDATE ai_analysis_results
                    SET shadow_status = 'rejected',
                        shadow_decided_at = NOW(),
                        shadow_decided_by = %s,
                        critical_summary = CONCAT(critical_summary, '\n[REJECTED] by ', %s, %s)
                    WHERE id = %s AND shadow_status = 'pending'
                    """,
                    (actor, actor, (f' ({note})' if note else ''), insight_id),
                )
                affected = cur2.rowcount
                await cnx.commit()
            finally:
                await cur2.close()

            if affected and action_for_chain:
                await _chain_append(cnx, insight_id, action_for_chain, target_for_chain, 'rejected', actor, note)

        if not affected:
            return sanic_json({"success": False, "error": "not found or already finalized"}, status=404)
        return sanic_json({"success": True, "insight_id": insight_id, "actor": actor})
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)


DEFENSIVE_SWEEP_INTERVAL = int(os.getenv("AI_DEFENSIVE_SWEEP_SEC", "300"))
DEFENSIVE_SWEEP_BATCH = int(os.getenv("AI_DEFENSIVE_SWEEP_BATCH", "10"))


async def _defensive_auto_sweep():
    """Background loop: every DEFENSIVE_SWEEP_INTERVAL seconds pull a small
    batch of the latest alerts per agent into the defensive AI queue so the
    LLM keeps producing visible commentary even when nothing fresh is
    streaming through ingest.
    """
    await asyncio.sleep(30)
    while True:
        try:
            def _list_agents():
                with sync_mysql_conn() as conn:
                    cursor = conn.cursor()
                    try:
                        cursor.execute("SHOW DATABASES")
                        return [r[0].replace('_db', '') for r in cursor.fetchall() if r[0].endswith('_db')]
                    finally:
                        cursor.close()

            agents = await asyncio.to_thread(_list_agents)
            for ag in agents:
                try:
                    res = await _push_recent_alerts_to_defensive(ag, DEFENSIVE_SWEEP_BATCH)
                    if res.get("queued"):
                        print(f"[AI-Sweep] defensive pushed {res['queued']} alerts for {ag}", flush=True)
                except Exception as e:
                    print(f"[!] defensive sweep agent={ag}: {e}", flush=True)
        except Exception as e:
            print(f"[!] defensive sweep loop error: {e}", flush=True)
        await asyncio.sleep(DEFENSIVE_SWEEP_INTERVAL)


@app.before_server_start
async def start_defensive_sweep(app):
    if os.getenv("AI_DEFENSIVE_SWEEP_ENABLED", "1") == "1":
        app.add_task(_defensive_auto_sweep())
        print(f"[*] Defensive AI auto-sweep enabled (every {DEFENSIVE_SWEEP_INTERVAL}s, batch={DEFENSIVE_SWEEP_BATCH})", flush=True)

@require_permission("analyze_logs")
@app.route("/analyze-logs/<agent>", methods=["POST"])
async def analyze_logs_single_agent(request, agent):
    """Analyze SIEM logs for a specific agent using AI"""
    data = request.json or {}
    limit = int(data.get('limit', 100))
    
    try:
        result = await analyze_agent_logs(agent, limit)
        return sanic_json(result)
    except Exception as e:
        return sanic_json({
            "success": False,
            "error": f"Error analyzing logs for agent {agent}: {str(e)}",
            "logs_analyzed": 0
        }, status=500)

@app.route("/api/analyze-selected/<agent>", methods=["POST"])
@require_permission("analyze_logs")
async def analyze_selected_logs_route(request, agent):
    """Analyze a specific set of logs selected from the UI"""
    data = request.json or {}
    logs = data.get('logs', [])
    
    if not logs:
        return sanic_json({"success": False, "error": "No logs provided"}, status=400)
        
    try:
        result = await analyze_selected_logs(agent, logs)
        return sanic_json(result)
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)

@app.route("/api/ai-insights/all", methods=["GET"])
@require_permission("read_telemetry")
async def get_all_ai_insights(request):
    """Fetch latest AI insights from all agent databases"""
    try:
        def get_agent_names():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    return [db[0].replace('_db', '') for db in cursor.fetchall() if db[0].endswith('_db')]
                finally:
                    cursor.close()

        agents = await asyncio.to_thread(get_agent_names)

        all_results = []

        for agent in agents:
            try:
                async with agent_conn(agent) as cnx:
                    acur = await cnx.cursor(dictionary=True)
                    try:
                        await acur.execute("""
                            SELECT TABLE_NAME
                            FROM information_schema.tables
                            WHERE table_schema = %s AND table_name = 'ai_analysis_results'
                        """, (_agent_db_name(agent),))

                        if await acur.fetchone():
                            try:
                                await acur.execute(
                                    "ALTER TABLE ai_analysis_results ADD COLUMN source_data LONGTEXT NULL"
                                )
                            except Exception:
                                pass
                            await acur.execute("""
                                SELECT id, timestamp, source_file, critical_summary, source_data, created_at
                                FROM ai_analysis_results
                                ORDER BY created_at DESC LIMIT 100
                            """)
                            rows = await acur.fetchall()
                            for r in rows:
                                r['agent'] = agent
                                if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                                    r['created_at'] = r['created_at'].isoformat()
                                if r.get('timestamp') and hasattr(r['timestamp'], 'isoformat'):
                                    r['timestamp'] = r['timestamp'].isoformat()
                                all_results.append(r)
                    finally:
                        await acur.close()
            except Exception as e:
                print(f"[!] ai-insights skip agent={agent}: {e}", flush=True)
                continue

        sorted_results = sorted(
            all_results,
            key=lambda x: x.get('created_at') or '',
            reverse=True,
        )

        return sanic_json({
            "success": True,
            "results": sorted_results[:500],
            "agents_scanned": agents,
            "agents_with_insights": sorted({r['agent'] for r in sorted_results}),
        })
        
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)

@require_permission("analyze_logs")
@app.route("/ai-config/<agent>", methods=["GET"])
async def get_ai_config(request, agent):
    """Get AI configuration for a specific agent (Defaults to Ollama if not set)"""
    try:
        config = await load_ai_config(agent)
        if not config:
            config = {
                'model_name': OLLAMA_MODEL,
                'endpoint': OLLAMA_BASE_URL,
                'api_key': 'ollama',
                'updated_at': None
            }
        
        is_ollama_key = config.get('api_key') == 'ollama'
        safe_config = {
            'model_name': config.get('model_name') or OLLAMA_MODEL,
            'endpoint': config.get('endpoint') or OLLAMA_BASE_URL,
            'has_api_key': bool(config.get('api_key')) and not is_ollama_key,
            'updated_at': config.get('updated_at')
        }
        return sanic_json({"success": True, "config": safe_config})
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)

class ActionType(Enum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"
    KILL_PROCESS = "kill_process"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE = "delete_file"
    RUN_COMMAND = "run_cmd"
    RESTART_SERVICE = "restart_service"
    LOCK_MACHINE = "lock_machine"
    TAIL_LOG = "tail_log"

AUTOMATION_ALLOWED_ACTIONS = [
    "block_ip", "unblock_ip", "disable_user", "enable_user", "kill_process", 
    "isolate_host", "quarantine_file", "delete_file", "run_cmd",
    "restart_service", "lock_machine", "tail_log"
]

@require_permission("manage_agent")
@app.route("/<agent>/config/<cfg_type>", methods=["GET"])
async def get_agent_config_proxy(request, agent, cfg_type):
    """Proxy request to agent to get a YAML config file"""
    if cfg_type not in ["rules", "log_paths", "file_scan"]:
        return sanic_json({"status": "error", "message": "Invalid config type"}, status=400)
    
    try:
        base = await _get_agent_http_base(agent)
        keys = await _get_agent_keys(agent)
        url = f"{base}/config/{cfg_type}"

        resp = await asyncio.to_thread(_try_agent_request, "GET", url, keys, None, 5)
        return sanic_json(resp.json(), status=resp.status_code)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_agent")
@app.post("/<agent>/config/<cfg_type>/validate")
async def validate_agent_config(request, agent, cfg_type):
    """Check a config without pushing it, so the editor can lint as you type."""
    data = request.json or {}
    issues = config_validation.validate(cfg_type, data.get("content", ""))
    return sanic_json({
        "status": "success",
        "valid": not config_validation.blocking(issues),
        "issues": [i.to_dict() for i in issues],
    })


@require_permission("manage_agent")
@app.route("/<agent>/config/<cfg_type>", methods=["POST"])
async def set_agent_config_proxy(request, agent, cfg_type):
    """Validate a YAML config, then push it to the agent.

    This forwarded the request body unread. A typo therefore reached the
    sensor, where it surfaced as the agent quietly not detecting things any
    more — nothing in the UI looked wrong, which is the worst way for a
    security tool to fail. Nothing reaches an endpoint now unless it parses,
    has the right shape, and has regexes that actually compile.
    """
    if cfg_type not in config_validation.CONFIG_TYPES:
        return sanic_json({"status": "error", "message": "Invalid config type"}, status=400)

    data = request.json or {}
    content = data.get("content", "")

    issues = config_validation.validate(cfg_type, content)
    errors = config_validation.blocking(issues)
    if errors:
        await audit_log(request, "CONFIG_PUSH_REJECTED", f"{agent}/{cfg_type}",
                        f"{len(errors)} blocking issue(s)")
        return sanic_json({
            "status": "error",
            "message": f"Config rejected: {len(errors)} problem(s) found. Nothing was sent to the agent.",
            "issues": [i.to_dict() for i in issues],
        }, status=400)

    try:
        base = await _get_agent_http_base(agent)
        keys = await _get_agent_keys(agent)
        url = f"{base}/config/{cfg_type}"

        resp = await asyncio.to_thread(_try_agent_request, "POST", url, keys, data, 5)
        await audit_log(request, "CONFIG_PUSH", f"{agent}/{cfg_type}",
                        f"{len(content)} bytes, {len(issues)} warning(s)")
        body = resp.json()
        # Warnings survive a successful push so the operator still sees them.
        if isinstance(body, dict) and issues:
            body["issues"] = [i.to_dict() for i in issues]
        return sanic_json(body, status=resp.status_code)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_system")
@app.route("/ai-config/<agent>", methods=["POST"])
async def set_ai_config(request, agent):
    """Set AI configuration (agent param currently unused but kept for routing)"""
    data = request.json or {}
    
    required_fields = ['model_name', 'endpoint']
    for field in required_fields:
        if not data.get(field):
            return sanic_json({"success": False, "error": f"Missing required field: {field}"}, status=400)
    
    api_key = data.get('api_key')
    
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        
        if not api_key:
            if "ollama" in data.get('endpoint', '').lower() or "11434" in data.get('endpoint', ''):
                api_key = "ollama"
            else:
                await cursor.execute("SELECT api_key FROM ai_config ORDER BY updated_at DESC LIMIT 1")
                row = await cursor.fetchone()
                if row:
                    api_key = row[0]

        await cursor.execute("""
            INSERT INTO ai_config (model_name, api_key, endpoint, updated_at)
            VALUES (%s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                model_name = VALUES(model_name),
                api_key = VALUES(api_key),
                endpoint = VALUES(endpoint),
                updated_at = NOW()
        """, (data['model_name'], api_key, data['endpoint']))
        
        await cnx.commit()
        await cursor.close()
        await cnx.close()
        
        return sanic_json({"success": True, "message": "AI configuration updated successfully"})
        
    except Exception as e:
        return sanic_json({"success": False, "error": f"Database error: {str(e)}"}, status=500)


@require_permission("role_create")
@app.route("/roles/assign-permissions", methods=["POST"])
async def assign_permissions_to_role(request):
    data = request.json or {}
    role_name = data.get("role_name")
    permissions = data.get("permissions", []) 
    all_permissions = data.get("all_permissions", False)

    if not role_name:
        return sanic_json({"status": "error", "message": "role_name is required"}, status=400)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT id FROM roles WHERE role_name = %s", (role_name,))
        role_row = await cursor.fetchone()
        if not role_row:
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "error", "message": f"Role '{role_name}' not found."}, status=404)

        role_id = role_row[0]

        if all_permissions:
            await cursor.execute("""
                INSERT IGNORE INTO role_permissions (role_id, permission_id)
                SELECT %s, id FROM permissions
            """, (role_id,))
        else:
            for perm_name in permissions:
                await cursor.execute("""
                    INSERT IGNORE INTO role_permissions (role_id, permission_id)
                    SELECT %s, id FROM permissions WHERE name = %s
                """, (role_id, perm_name))

        await cnx.commit()
        await cursor.close(); await cnx.close()

        return sanic_json({
            "status": "success",
            "message": f"Permissions assigned to role '{role_name}' successfully."
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Failed to assign permissions: {str(e)}"
        }, status=500)
    
@app.route("/ai-analysis-status/<agent>")
async def get_ai_analysis_status(request, agent):
    try:
        db_name = _agent_db_name(agent)
        def _query():
            with sync_mysql_conn(db_name) as conn:
                cursor = conn.cursor(dictionary=True)
                try:
                    cursor.execute("SELECT COUNT(*) as total FROM siem_events")
                    total_logs = cursor.fetchone()['total']
                    cursor.execute("SELECT COUNT(*) as analyzed FROM siem_events WHERE ai_analyzed = TRUE")
                    analyzed_logs = cursor.fetchone()['analyzed']
                    cursor.execute("SELECT COUNT(*) as pending FROM siem_events WHERE (ai_analyzed IS NULL OR ai_analyzed = FALSE)")
                    pending_logs = cursor.fetchone()['pending']
                    cursor.execute("SELECT * FROM ai_log_checker_results ORDER BY created_at DESC LIMIT 10")
                    recent_results = cursor.fetchall()
                    return total_logs, analyzed_logs, pending_logs, recent_results
                finally:
                    cursor.close()
        total_logs, analyzed_logs, pending_logs, recent_results = await asyncio.to_thread(_query)
        
        return sanic_json({
            "success": True,
            "agent": agent,
            "total_logs": total_logs,
            "analyzed_logs": analyzed_logs,
            "pending_logs": pending_logs,
            "analysis_percentage": round((analyzed_logs / total_logs * 100) if total_logs > 0 else 0, 2),
            "recent_results": recent_results
        })
        
    except Exception as e:
        return sanic_json({"success": False, "error": str(e)}, status=500)
    

@require_permission("set_email_config")
@app.route("/send-critical-alerts", methods=["POST"])
async def send_critical_alerts_endpoint(request):
    """Manually trigger sending critical alerts for all agents"""
    try:
        total_alerts = dispatch_all_critical_alerts()
        return sanic_json({
            "status": "success",
            "message": f"Processed {total_alerts} critical alerts",
            "alerts_sent": total_alerts
        })
    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Error sending critical alerts: {str(e)}"
        }, status=500)

@require_permission("set_email_config")
@app.route("/send-critical-alerts/<agent>", methods=["POST"])
async def send_critical_alerts_agent(request, agent):
    """Manually trigger sending critical alerts for a specific agent"""
    try:
        alerts_count = dispatch_critical_alerts(agent)
        return sanic_json({
            "status": "success",
            "message": f"Processed {alerts_count} critical alerts for agent {agent}",
            "alerts_sent": alerts_count
        })
    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Error sending critical alerts for agent {agent}: {str(e)}"
        }, status=500)

@app.get("/email-templates")
@require_permission("set_email_config")
async def list_email_templates(request):
    """Templates with their bodies, for the editor.

    `/<agent>/notifications/templates` returns names only and exists for the
    playbook node picker. Editing content needs the whole row, and until now
    there was no way to see or change one outside the database.
    """
    try:
        async with userdb_conn() as cnx:
            cur = await cnx.cursor(dictionary=True)
            try:
                await cur.execute(
                    "SELECT id, template_name, subject_template, body_template, updated_at "
                    "FROM email_templates ORDER BY template_name"
                )
                rows = await cur.fetchall()
            finally:
                await cur.close()
        return sanic_json(
            {"status": "success", "templates": rows, "default_name": DEFAULT_ALERT_TEMPLATE},
            dumps=lambda o: pyjson.dumps(o, ensure_ascii=False, cls=CustomEncoder),
        )
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)


@app.post("/email-templates")
@require_permission("set_email_config")
async def upsert_email_template(request):
    """Create or replace a template, keyed on its name."""
    data = request.json or {}
    name = (data.get("template_name") or "").strip()
    subject = (data.get("subject_template") or "").strip()
    body = (data.get("body_template") or "").strip()

    missing = [f for f, v in (("template_name", name), ("subject_template", subject),
                              ("body_template", body)) if not v]
    if missing:
        return sanic_json(
            {"status": "error", "message": f"Missing required field(s): {', '.join(missing)}"},
            status=400,
        )

    try:
        async with userdb_conn() as cnx:
            cur = await cnx.cursor()
            try:
                await cur.execute(
                    """INSERT INTO email_templates (template_name, subject_template, body_template)
                       VALUES (%s, %s, %s)
                       ON DUPLICATE KEY UPDATE
                           subject_template = VALUES(subject_template),
                           body_template = VALUES(body_template)""",
                    (name, subject, body),
                )
                await cnx.commit()
            finally:
                await cur.close()
        await audit_log(request, "EMAIL_TEMPLATE_SAVE", name, "")
        return sanic_json({"status": "success", "message": f"Template '{name}' saved."})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)


@app.delete("/email-templates/<template_id:int>")
@require_permission("set_email_config")
async def delete_email_template(request, template_id):
    try:
        async with userdb_conn() as cnx:
            cur = await cnx.cursor()
            try:
                await cur.execute("SELECT template_name FROM email_templates WHERE id = %s", (template_id,))
                row = await cur.fetchone()
                if not row:
                    return sanic_json({"status": "error", "message": "Template not found"}, status=404)
                name = row[0]
                # Deleting the fallback would silently stop alert mail for every
                # agent that has no template of its own.
                if name == DEFAULT_ALERT_TEMPLATE:
                    return sanic_json({
                        "status": "error",
                        "message": f"'{name}' is the fallback used when an agent has no template of "
                                   f"its own. Edit it instead of deleting it.",
                    }, status=400)
                await cur.execute("DELETE FROM email_templates WHERE id = %s", (template_id,))
                await cnx.commit()
            finally:
                await cur.close()
        await audit_log(request, "EMAIL_TEMPLATE_DELETE", name, "")
        return sanic_json({"status": "success", "message": f"Template '{name}' deleted."})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)


@require_permission("set_email_config")
@require_permission("manage_system")
@app.route("/email-config", methods=["GET"])
async def get_email_config(request):
    """Get current email configuration status"""
    config = get_mail_config()
    return sanic_json({
        "enabled": config['enabled'],
        "smtp_server": config.get('smtp_server', 'Not configured') if config['enabled'] else 'Not configured',
        "from_addr": config.get('from_addr', 'Not configured') if config['enabled'] else 'Not configured',
        "to_addr": config.get('to_addr', 'Not configured') if config['enabled'] else 'Not configured'
    })

@require_permission("set_email_config")
@app.route("/email-config", methods=["POST"])
async def set_email_config(request):
    """Set email configuration"""
    data = request.json or {}
    
    required_fields = ['smtp_server', 'smtp_port', 'email_from', 'email_to']
    for field in required_fields:
        if not data.get(field):
            return sanic_json({"status": "error", "message": f"Missing required field: {field}"}, status=400)
    
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        
        query = """
            INSERT INTO email_config (smtp_server, smtp_port, smtp_user, smtp_password, 
                                    smtp_use_tls, email_from, email_to, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                smtp_server = VALUES(smtp_server),
                smtp_port = VALUES(smtp_port),
                smtp_user = VALUES(smtp_user),
                smtp_password = VALUES(smtp_password),
                smtp_use_tls = VALUES(smtp_use_tls),
                email_from = VALUES(email_from),
                email_to = VALUES(email_to),
                updated_at = NOW()
        """
        
        await cursor.execute(query, (
            data['smtp_server'],
            data['smtp_port'],
            data.get('smtp_user'),
            data.get('smtp_password'),
            data.get('smtp_use_tls', False),
            data['email_from'],
            data['email_to']
        ))
        
        await cnx.commit()
        await cursor.close()
        await cnx.close()
        
        return sanic_json({"status": "success", "message": "Email configuration updated successfully"})
        
    except Exception as e:
        return sanic_json({"status": "error", "message": f"Database error: {str(e)}"}, status=500)

def encrypt_password(password: str) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()

async def log_login_attempt(username, auth_type, status, reason, ip_address):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("""
            INSERT INTO login_logs (username, auth_type, status, reason, ip_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, auth_type, status, reason, ip_address))
        await cnx.commit()
        await cursor.close()
        await cnx.close()
    except Exception as e:
        print(f"[!] Error: {e}")


@app.route("/<agent>/soar_actions/<action_id>/resolve", methods=["PATCH"])
async def resolve_soar_action(request, agent, action_id):
    if not is_soar_enabled():
        return _soar_block_response()
    try:
        data = request.json or {}
        raw_ts = (data.get("resolved_at") or "").strip()
        if raw_ts:
            ts = raw_ts.replace("T", " ").rstrip("Z")
        else:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        new_status = (data.get("status") or "RESOLVED").upper()

        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()

        await cursor.execute(
            "UPDATE soar_actions SET resolved_at = %s, status = %s WHERE id = %s",
            (ts, new_status, action_id)
        )
        await cnx.commit()
        updated = cursor.rowcount
        await cursor.close()

        if not updated:
            await cnx.close()
            return sanic_json({"status": "error", "message": "SOAR action not found"}, status=404)

        cur2 = await cnx.cursor()
        await cur2.execute("SELECT * FROM soar_actions WHERE id = %s", (action_id,))
        columns = [c[0] for c in cur2.description]
        row = await cur2.fetchone()
        await cur2.close(); await cnx.close()

        body = pyjson.dumps(dict(zip(columns, row)), cls=CustomEncoder, ensure_ascii=False)
        return HTTPResponse(body=body, content_type="application/json; charset=utf-8")

    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)


@app.route("/<agent>/soar_actions/<action_id>/send", methods=["PATCH"])
async def mark_soar_action_sent(request, agent, action_id):
    if not is_soar_enabled():
        return _soar_block_response()
    try:
        data = request.json or {}
        sent_bool = _as_bool(data.get("sent", True))
        sent_val = 1 if sent_bool else 0

        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()
        await cursor.execute(
            "UPDATE soar_actions SET sent = %s WHERE id = %s",
            (sent_val, action_id)
        )
        await cnx.commit()
        updated = cursor.rowcount
        await cursor.close()

        if not updated:
            await cnx.close()
            return sanic_json({"status": "error", "message": "SOAR action not found"}, status=404)

        cur2 = await cnx.cursor()
        await cur2.execute("SELECT * FROM soar_actions WHERE id = %s", (action_id,))
        columns = [c[0] for c in cur2.description]
        row = await cur2.fetchone()
        await cur2.close(); await cnx.close()

        body = pyjson.dumps(dict(zip(columns, row)), cls=CustomEncoder, ensure_ascii=False)
        return HTTPResponse(body=body, content_type="application/json; charset=utf-8")

    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)


@app.route("/<agent>/soar_actions/<action_id>", methods=["DELETE"])
async def delete_soar_action(request, agent, action_id):
    if not is_soar_enabled():
        return _soar_block_response()
    try:
        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()
        await cursor.execute("DELETE FROM soar_actions WHERE id = %s", (action_id,))
        await cnx.commit()
        deleted = cursor.rowcount
        await cursor.close(); await cnx.close()

        if not deleted:
            return sanic_json({"status": "error", "message": "SOAR action not found"}, status=404)

        return sanic_json({"status": "success", "message": f"SOAR action {action_id} deleted"})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_soar")
@app.post("/<agent>/automations/<auto_id:int>/execute")
async def execute_automation(request, agent, auto_id):
    if not is_soar_enabled():
        return _soar_block_response()

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor(dictionary=True)
        await cur.execute("SELECT * FROM automations WHERE id=%s AND device=%s", (auto_id, agent))
        rec = await cur.fetchone()
        await cur.close(); await cnx.close()
        if not rec:
            return sanic_json({"error": "automation not found"}, status=404)

        if rec["action"] not in AUTOMATION_ALLOWED_ACTIONS:
            return sanic_json({"error": f"action not allowed: {rec['action']}"}, status=400)

        if rec["status"] not in ("pending", "paused", "failed", "active"):
            return sanic_json({"error": f"cannot execute in status={rec['status']}"}, status=409)

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute("UPDATE automations SET status='active', updated_at=NOW() WHERE id=%s", (auto_id,))
        await cnx.commit(); await cur.close(); await cnx.close()

        prefix = f"automation#{rec['id']}"
        result = await call_agent_soar(
            agent,
            action=rec["action"],
            target=rec["target"],
            comment=f"{prefix} | {rec.get('comment') or ''}".strip(),
            event_id=rec.get("event_id"),
        )

        auto_status = "completed" if result.get("ok") else "failed"
        final_comment = (rec.get("comment") or "").strip()
        if result.get("message"):
            add = f"{prefix} | {result['message']}"
            final_comment = (f"{final_comment} | {add}" if final_comment else add)[:500]

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "UPDATE automations SET status=%s, comment=%s, updated_at=NOW() WHERE id=%s",
            (auto_status, final_comment, rec["id"])
        )
        await cnx.commit(); await cur.close(); await cnx.close()

        return sanic_json({
            "status": "ok",
            "automation": {"id": rec["id"], "status": auto_status, "comment": final_comment},
            "agent_response": result,
        })

    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)


@require_permission("manage_soar")
@app.post("/<agent>/automations/run-due")
async def run_due_automations(request, agent):

    if not is_soar_enabled():
        return _soar_block_response()
    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor(dictionary=True)
        await cur.execute(
            """
            SELECT * FROM automations
            WHERE device=%s AND status='pending' AND `timestamp` <= NOW()
            ORDER BY `timestamp` ASC, id ASC
            """,
            (agent,)
        )
        rows = await cur.fetchall()
        await cur.close(); await cnx.close()

        results = []
        for rec in rows or []:
            cnx = await connect_db_for_agent(agent)
            cur = await cnx.cursor()
            await cur.execute("UPDATE automations SET status='active', updated_at=NOW() WHERE id=%s", (rec["id"],))
            await cnx.commit(); await cur.close(); await cnx.close()

            prefix = f"automation#{rec['id']}"
            try:
                r = await call_agent_soar(
                    agent,
                    action=rec["action"],
                    target=rec["target"],
                    comment=f"{prefix} | {rec.get('comment') or ''}".strip(),
                    event_id=rec.get("event_id"),
                )
                auto_status = "completed" if r.get("ok") else "failed"
                final_comment = (rec.get("comment") or "").strip()
                if r.get("message"):
                    add = f"{prefix} | {r['message']}"
                    final_comment = (f"{final_comment} | {add}" if final_comment else add)[:500]
            except Exception as ex:
                r = {"ok": False, "error": str(ex)}
                auto_status = "failed"
                final_comment = (rec.get("comment") or "")[:500]

            cnx = await connect_db_for_agent(agent)
            cur = await cnx.cursor()
            await cur.execute(
                "UPDATE automations SET status=%s, comment=%s, updated_at=NOW() WHERE id=%s",
                (auto_status, final_comment, rec["id"])
            )
            await cnx.commit(); await cur.close(); await cnx.close()

            results.append({"id": rec["id"], "status": auto_status, "agent_response": r})

        ok = sum(1 for r in results if r["status"] == "completed")
        fail = sum(1 for r in results if r["status"] == "failed")
        return sanic_json({"status": "ok", "count": len(results), "completed": ok, "failed": fail, "results": results})

    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)


@app.get("/<agent>/soar_actions")
async def get_soar_actions_api(request, agent):
    """
    Alias for /automations to support frontend SoarHub.
    """
    try:
        return await fixed_list_automations(request, agent)
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)


@app.post("/automations/report", name="report_automation_gen")
@app.post("/<agent>/automations/report", name="report_automation_agent")
@app.post("/api/agents/<agent>/automations/report", name="report_automation_api")
async def report_automation_result(request, agent=None):
    """
    Agent'ın aksiyon sonucunu bildirdiği yer.
    """
    try:
        data = request.json
        task_id = data.get("task_id")
        status = data.get("status", "SUCCESS").upper()
        output = data.get("output", "")
        
        if not agent:
            agent = data.get("metadata", {}).get("agent")
            
        if not agent or not task_id:
            return sanic_json({"error": "Missing agent or task_id"}, status=400)
            
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        
        query_soar = "UPDATE soar_actions SET status = %s, comment = %s, updated_at = NOW() WHERE id = %s"
        query_auto = "UPDATE automations SET status = %s, comment = %s, updated_at = NOW() WHERE id = %s"
        
        try:
            await cur.execute(query_soar, (status, output[:500], task_id))
        except:
            pass
            
        try:
            await cur.execute(query_auto, (status.lower(), output[:500], task_id))
        except:
            pass
            
        await cnx.commit(); await cur.close(); await cnx.close()
        return sanic_json({"status": "ok"})
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)





def _to_mysql_ts(raw: str | None) -> str | None:
    if not raw:
        return None
    s = str(raw).strip()
    s = s.replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1]
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s[:19]

@require_permission("manage_soar")
@app.get("/<agent>/automations")
async def fixed_list_automations(request, agent):
    """
    List both automations (playbooks/queued) and soar_actions (manual/pushed) for an agent.
    Merged into a unified view for the SOAR UI.
    """
    q = request.args
    status_filter = (q.get("status") or "").strip().lower()
    search = (q.get("search") or q.get("q") or "").strip().lower()
    order = (q.get("order") or "DESC").upper()
    if order not in ("ASC", "DESC"):
        order = "DESC"

    try:
        limit = int(q.get("limit", 500))
        limit = max(1, min(limit, 5000))
    except Exception:
        limit = 500

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()

        all_data = []

        try:
            await cur.execute("SELECT id, device, event_id, action, target, comment, status, `timestamp`, payload, created_at, updated_at, 'automation' as source FROM automations WHERE device = %s ORDER BY id DESC LIMIT %s", (agent, limit))
            cols = [d[0] for d in cur.description]
            all_data.extend([dict(zip(cols, r)) for r in await cur.fetchall()])
        except:
            await cur.execute("SELECT id, device, event_id, action, target, comment, status, `timestamp`, payload, created_at, created_at as updated_at, 'automation' as source FROM automations WHERE device = %s ORDER BY id DESC LIMIT %s", (agent, limit))
            cols = [d[0] for d in cur.description]
            all_data.extend([dict(zip(cols, r)) for r in await cur.fetchall()])

        rows_soar = []
        try:
            await cur.execute("SELECT id, action, target, comment, status, `timestamp`, created_at, updated_at, 'manual' as source FROM soar_actions ORDER BY id DESC LIMIT %s", (limit,))
            cols = [d[0] for d in cur.description]
            rows_soar = [dict(zip(cols, r)) for r in await cur.fetchall()]
        except:
            await cur.execute("SELECT id, action, target, comment, status, `timestamp`, created_at, created_at as updated_at, 'manual' as source FROM soar_actions ORDER BY id DESC LIMIT %s", (limit,))
            cols = [d[0] for d in cur.description]
            rows_soar = [dict(zip(cols, r)) for r in await cur.fetchall()]

        await cur.close(); await cnx.close()

        for r in rows_soar:
            r["device"] = agent
            r["event_id"] = 0
            r["payload"] = None
            if "updated_at" not in r: r["updated_at"] = r.get("created_at")
            all_data.append(r)

        def _ensure_ts(val):
            if val is None: return 0.0
            if hasattr(val, "timestamp"): return float(val.timestamp())
            if isinstance(val, (int, float)): return float(val)
            if isinstance(val, str):
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(val.replace(" ", "T"))
                    return float(dt.timestamp())
                except:
                    try: return float(val)
                    except: return 0.0
            return 0.0

        filtered = []
        for r in all_data:
            if status_filter and status_filter != str(r.get("status", "")).lower():
                continue
            if search:
                text = f"{r.get('action', '')} {r.get('target', '')} {r.get('comment', '')}".lower()
                if search not in text:
                    continue
            
            r["timestamp"] = _ensure_ts(r.get("timestamp"))
            r["updated_at"] = _ensure_ts(r.get("updated_at"))
            r["created_at"] = _ensure_ts(r.get("created_at"))

            if r.get("payload") and isinstance(r["payload"], str):
                try: 
                    import json as py_json
                    r["payload"] = py_json.loads(r["payload"])
                except: pass

            filtered.append(r)

        try:
            filtered.sort(key=lambda x: float(x.get("timestamp") or 0.0), reverse=(order == "DESC"))
        except Exception as e:
            print(f"[!] SORT ERROR in fixed_list_automations: {e}")
            raise e
            
        return sanic_json(filtered[:limit])

    except Exception as e:
        print(f"[!] Error in fixed_list_automations: {e}")
        return sanic_json({"error": str(e)}, status=500)

@require_permission("manage_soar")
@app.post("/<agent>/automations")
async def create_automation(request, agent):
    data = request.json or {}

    try:
        event_id = int(data.get("event_id"))
    except Exception:
        return sanic_json({"error": "event_id (int) required"}, status=400)

    action  = (data.get("action") or "").strip()
    target  = (data.get("target") or "").strip()
    status  = (data.get("status") or "pending").strip()
    comment = (data.get("comment") or "").strip()
    ts_in   = _to_mysql_ts(data.get("timestamp"))

    if not action or not target:
        return sanic_json({"error": "action and target required"}, status=400)
    if action not in AUTOMATION_ALLOWED_ACTIONS:
        return sanic_json({"error": f"action not allowed: {action}"}, status=400)
    if status not in AUTOMATION_ALLOWED_STATUSES:
        return sanic_json({"error": f"status not allowed: {status}"}, status=400)

    payload = data.get("payload")
    if payload is not None and not isinstance(payload, (dict, list, str)):
        return sanic_json({"error": "payload must be object/array/string"}, status=400)
    payload_str = None
    if isinstance(payload, (dict, list)):
        payload_str = pyjson.dumps(payload, ensure_ascii=False)
    elif isinstance(payload, str):
        payload_str = payload

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()

        await cur.execute("""
            INSERT INTO automations
                (device, event_id, action, target, comment, status, `timestamp`, payload, created_at, updated_at)
            VALUES
                (%s, %s, %s, %s, %s, %s, COALESCE(%s, NOW()), %s, NOW(), NOW())
        """, (agent, event_id, action, target, comment, status, ts_in, payload_str))
        new_id = cur.lastrowid
        await cnx.commit()
        await cur.close()

        cur2 = await cnx.cursor()
        await cur2.execute("SELECT id, device, event_id, action, target, comment, status, `timestamp`, payload, created_at, updated_at FROM automations WHERE id=%s AND device=%s", (new_id, agent))
        row = await cur2.fetchone()
        cols = [c[0] for c in cur2.description]
        await cur2.close(); await cnx.close()

        d = dict(zip(cols, row))
        if d.get("payload"):
            try:
                d["payload"] = pyjson.loads(d["payload"]) if isinstance(d["payload"], str) else d["payload"]
            except Exception:
                pass

        return sanic_json(
                d,
                status=201,
                dumps=lambda obj: pyjson.dumps(obj, ensure_ascii=False, cls=CustomEncoder),
            )
    
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)

@require_permission("manage_soar")
@app.put("/<agent>/automations/<auto_id:int>")
async def update_automation(request, agent, auto_id):
    data = request.json or {}
    fields, params = [], []

    if "event_id" in data:
        try:
            ev = int(data.get("event_id"))
            fields.append("event_id = %s"); params.append(ev)
        except Exception:
            return sanic_json({"error": "event_id must be int"}, status=400)

    if "action" in data:
        action = (data.get("action") or "").strip()
        if action not in AUTOMATION_ALLOWED_ACTIONS:
            return sanic_json({"error": f"action not allowed: {action}"}, status=400)
        fields.append("action = %s"); params.append(action)

    if "target" in data:
        fields.append("target = %s"); params.append((data.get("target") or "").strip())

    if "comment" in data:
        fields.append("comment = %s"); params.append((data.get("comment") or "").strip())

    if "status" in data:
        status = (data.get("status") or "").strip()
        if status not in AUTOMATION_ALLOWED_STATUSES:
            return sanic_json({"error": f"status not allowed: {status}"}, status=400)
        fields.append("status = %s"); params.append(status)

    if "timestamp" in data:
        fields.append("`timestamp` = %s"); params.append(_to_mysql_ts(data.get("timestamp")) or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if "payload" in data:
        payload = data.get("payload")
        if payload is not None and not isinstance(payload, (dict, list, str)):
            return sanic_json({"error": "payload must be object/array/string"}, status=400)
        payload_str = pyjson.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else (payload if isinstance(payload, str) else None)
        fields.append("payload = %s"); params.append(payload_str)

    if not fields:
        return sanic_json({"error": "no updatable fields provided"}, status=400)

    fields.append("updated_at = NOW()")

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        sql = f"UPDATE automations SET {', '.join(fields)} WHERE id=%s AND device=%s"
        params.extend([auto_id, agent])
        await cur.execute(sql, tuple(params))
        await cnx.commit()
        updated = cur.rowcount
        await cur.close()

        if not updated:
            await cnx.close()
            return sanic_json({"error": "automation not found"}, status=404)

        cur2 = await cnx.cursor()
        await cur2.execute("SELECT id, device, event_id, action, target, comment, status, `timestamp`, payload, created_at, updated_at FROM automations WHERE id=%s AND device=%s", (auto_id, agent))
        row = await cur2.fetchone()
        cols = [c[0] for c in cur2.description]
        await cur2.close(); await cnx.close()

        d = dict(zip(cols, row))
        if d.get("payload"):
            try:
                d["payload"] = pyjson.loads(d["payload"]) if isinstance(d["payload"], str) else d["payload"]
            except Exception:
                pass
        return sanic_json(
                    d,
                    status=201,
                    dumps=lambda obj: pyjson.dumps(obj, ensure_ascii=False, cls=CustomEncoder),
                )
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)

@app.patch("/<agent>/automations/<auto_id:int>/status")
async def patch_automation_status(request, agent, auto_id):
    data = request.json or {}
    new_status = (data.get("status") or "").strip()
    if new_status not in AUTOMATION_ALLOWED_STATUSES:
        return sanic_json({"error": f"status not allowed: {new_status}"}, status=400)

    extra_comment = (data.get("comment") or "").strip()

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()

        if extra_comment:
            await cur.execute("""
                UPDATE automations
                SET status=%s, comment=CONCAT(COALESCE(comment,''), CASE WHEN LENGTH(COALESCE(comment,''))>0 THEN ' | ' ELSE '' END, %s),
                    updated_at=NOW()
                WHERE id=%s AND device=%s
            """, (new_status, extra_comment, auto_id, agent))
        else:
            await cur.execute("""
                UPDATE automations
                SET status=%s, updated_at=NOW()
                WHERE id=%s AND device=%s
            """, (new_status, auto_id, agent))

        await cnx.commit()
        updated = cur.rowcount
        await cur.close()

        if not updated:
            await cnx.close()
            return sanic_json({"error": "automation not found"}, status=404)

        cur2 = await cnx.cursor()
        await cur2.execute("SELECT id, device, event_id, action, target, comment, status, `timestamp`, payload, created_at, updated_at FROM automations WHERE id=%s AND device=%s", (auto_id, agent))
        row = await cur2.fetchone()
        cols = [c[0] for c in cur2.description]
        await cur2.close(); await cnx.close()

        d = dict(zip(cols, row))
        if d.get("payload"):
            try:
                d["payload"] = pyjson.loads(d["payload"]) if isinstance(d["payload"], str) else d["payload"]
            except Exception:
                pass
        return sanic_json(
                d,
                status=201,
                dumps=lambda obj: pyjson.dumps(obj, ensure_ascii=False, cls=CustomEncoder),
            )
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)


@require_permission("manage_soar")
@app.delete("/<agent>/automations/<auto_id:int>")
async def delete_automation(request, agent, auto_id):
    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute("DELETE FROM automations WHERE id=%s AND device=%s", (auto_id, agent))
        await cnx.commit()
        deleted = cur.rowcount
        await cur.close(); await cnx.close()

        if not deleted:
            return sanic_json({"error": "automation not found"}, status=404)

        return sanic_json({"status": "success", "message": f"automation {auto_id} deleted"})
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)

@app.post("/<agent>/automations/<auto_id:int>/run")
async def run_automation_alias(request, agent, auto_id):
    return await execute_automation(request, agent, auto_id)


@app.post("/<agent>/automations/validate-target")
async def validate_automation_target(request, agent):
    if not is_soar_enabled():
        return _soar_block_response()
    data = request.json or {}
    action = (data.get("action") or "").strip()
    target = (data.get("target") or "").strip()

    if action not in AUTOMATION_ALLOWED_ACTIONS:
        return sanic_json({"ok": False, "error": f"action not allowed: {action}"}, status=400)

    try:
        if action == ActionType.BLOCK_IP.value:
            if not _is_valid_ipv4(target):
                return sanic_json({"ok": False, "error": "invalid IPv4"}, status=400)
            return sanic_json({"ok": True})

        elif action == ActionType.DISABLE_USER.value:
            if not _is_valid_username(target):
                return sanic_json({"ok": False, "error": "invalid username"}, status=400)
            return sanic_json({"ok": True})

        return sanic_json({"ok": False, "error": f"action not implemented: {action}"}, status=501)

    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)


def _set_session_cookie(resp, raw_token: str):
    """Attach the session cookie.

    Sanic 23.3+ exposes `add_cookie()`; older releases only have the mapping
    API. `sanic` is unpinned in requirements.txt, so support both.
    """
    add = getattr(resp.cookies, "add_cookie", None)
    if add is not None:
        add(
            session_store.SESSION_COOKIE, raw_token,
            path="/", httponly=True, samesite=SESSION_COOKIE_SAMESITE,
            secure=SESSION_COOKIE_SECURE,
            max_age=session_store.cookie_max_age(),
        )
        return
    resp.cookies[session_store.SESSION_COOKIE] = raw_token
    c = resp.cookies[session_store.SESSION_COOKIE]
    c["path"] = "/"
    c["httponly"] = True
    c["samesite"] = SESSION_COOKIE_SAMESITE
    c["secure"] = SESSION_COOKIE_SECURE
    c["max-age"] = session_store.cookie_max_age()


def _clear_session_cookie(resp):
    delete = getattr(resp.cookies, "delete_cookie", None)
    if delete is not None:
        # `secure` must mirror what _set_session_cookie used. Sanic's
        # delete_cookie defaults it to True, and a Secure deletion cookie
        # delivered over plain http is dropped by the browser — so on an
        # http deployment the cookie would survive logout. The session is
        # revoked server-side either way, but leaving a live-looking cookie
        # in the browser is not a state worth shipping.
        delete(session_store.SESSION_COOKIE, path="/", secure=SESSION_COOKIE_SECURE)
        return
    resp.cookies[session_store.SESSION_COOKIE] = ""
    resp.cookies[session_store.SESSION_COOKIE]["max-age"] = 0


async def _issue_session(request, *, user_id: int, username: str,
                         role: str | None, auth_type: str) -> str:
    async with userdb_conn() as cnx:
        cur = await cnx.cursor()
        try:
            raw = await session_store.create(
                cur,
                user_id=user_id, username=username, role=role,
                auth_type=auth_type, ip=_client_ip(request),
                user_agent=request.headers.get("User-Agent"),
            )
            await cnx.commit()
        finally:
            await cur.close()
    return raw


async def _upsert_ldap_user(username: str, role: str) -> int:
    """Give an LDAP identity a local `users` row.

    Sessions, RBAC and audit attribution all key off the same integer id, so an
    LDAP login needs one too — before this, the LDAP branch returned a user
    object with no `id` at all and the frontend threw on `user.id.toString()`.
    The password column gets an unusable placeholder: `bcrypt.checkpw` raises
    on it, which the local branch already treats as "fall through to LDAP".
    """
    async with userdb_conn() as cnx:
        cur = await cnx.cursor()
        try:
            await cur.execute("SELECT id FROM users WHERE username = %s LIMIT 1", (username,))
            row = await cur.fetchone()
            if row:
                await cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, row[0]))
                await cnx.commit()
                return int(row[0])
            await cur.execute(
                "INSERT INTO users (username, password, role, created_by) VALUES (%s, %s, %s, 'ldap')",
                (username, "!ldap-no-local-password", role),
            )
            await cnx.commit()
            await cur.execute("SELECT id FROM users WHERE username = %s LIMIT 1", (username,))
            row = await cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            await cur.close()


@app.route("/login", methods=["GET", "POST"])
async def login(request):
    if request.method == "GET":
        return await response.file("./frontend/dist/index.html")

    try:
        data_raw = request.json or {}
        login_data = LoginRequest(**data_raw)
        username = login_data.username
        password = login_data.password
    except Exception as e:
        return response.json({"status": "error", "message": f"Invalid input: {str(e)}"}, status=400)

    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.conn_info.peername[0] if request.conn_info and request.conn_info.peername else "unknown"

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute(
            "SELECT id, username, password, created_at, role FROM users WHERE username = %s LIMIT 1",
            (username,),
        )
        row = await cursor.fetchone()
        await cursor.close()
        await cnx.close()

        if row:
            user_id, db_username, db_password, created_at, db_role = row
            if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
                await log_login_attempt(username, "local", "success", "", ip)

                print(f"[+] Local login successful for user: {username}")
                user_perms = await get_user_permissions(user_id)
                raw_token = await _issue_session(
                    request, user_id=user_id, username=db_username,
                    role=db_role, auth_type="local",
                )
                resp = response.json({
                    "status": "success",
                    "message": "Login successful (local).",
                    "user": {
                        "id": user_id,
                        "username": db_username,
                        "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(created_at, 'strftime') else str(created_at),
                        "auth_type": "local",
                        # Was hardcoded to `"admin" if username == "admin"`,
                        # which silently ignored the role column.
                        "role": db_role,
                        "permissions": user_perms
                    }
                })
                _set_session_cookie(resp, raw_token)
                return resp
            else:
                await log_login_attempt(username, "local", "failure", "Invalid local password", ip)
                print(f"[-] Local password mismatch for user: {username}")
                return response.json({"status": "error", "message": "Invalid username or password."}, status=401)
        else:
            print(f"[-] User {username} not found in local DB. Trying LDAP...")

    except Exception as e:
        await log_login_attempt(username, "Local", "failure", f"{e} Looking for LDAP", ip)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("""
            SELECT ldap_host, ldap_port, bind_dn, bind_password, users_base, group_base, login_filter 
            FROM ldap_conf
            LIMIT 1
        """)
        row = await cursor.fetchone()
        await cursor.close()
        await cnx.close()

        if not row:
            await log_login_attempt(username, "ldap", "failure", "No LDAP config", ip)
            return response.json({"status": "error", "message": "Invalid username or password."}, status=401)

        ldap_host, ldap_port, bind_dn, encrypted_password, users_base, group_base, login_filter = row
        bind_password = decrypt_password(encrypted_password)
        tls_config = Tls(validate=ssl.CERT_REQUIRED)
        max_retries = 3

        server = Server(ldap_host, port=ldap_port, use_ssl=True, tls=tls_config, connect_timeout=3)

        for attempt in range(max_retries):
            try:
                admin_conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

                search_filter = login_filter % username
                admin_conn.search(users_base, search_filter, attributes=["cn"])
                if not admin_conn.entries:
                    admin_conn.unbind()
                    await log_login_attempt(username, "ldap", "failure", "User not found", ip)
                    return response.json({"status": "error", "message": "Invalid username or password."}, status=401)

                user_dn = admin_conn.entries[0].entry_dn

                admin_conn.search(
                    search_base=group_base,
                    search_filter=f"(member={user_dn})",
                    attributes=["cn"]
                )
                group_dns = [entry.entry_dn for entry in admin_conn.entries]
                admin_conn.unbind()

                try:
                    user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
                    user_conn.unbind()
                except LDAPBindError:
                    await log_login_attempt(username, "ldap", "failure", "Wrong password", ip)
                    return response.json({"status": "error", "message": "Invalid username or password."}, status=401)

                app_role = "user"
                try:
                    cnx = await connect_userdb()
                    cursor = await cnx.cursor()
                    for group_dn in group_dns:
                        await cursor.execute(
                            "SELECT app_role FROM ldap_role_mappings WHERE ldap_group_dn = %s LIMIT 1",
                            (group_dn,)
                        )
                        r = await cursor.fetchone()
                        if r:
                            app_role = r[0]
                            print(app_role)
                            break
                    await cursor.close()
                    await cnx.close()
                except Exception:
                    pass

                await log_login_attempt(username, "ldap", "success", "", ip)
                user_perms = await get_role_permissions(app_role)
                ldap_uid = await _upsert_ldap_user(username, app_role)
                raw_token = await _issue_session(
                    request, user_id=ldap_uid, username=username,
                    role=app_role, auth_type="ldap",
                )
                resp = response.json({
                    "status": "success",
                    "message": "Login successful (LDAP).",
                    "user": {
                        "id": ldap_uid,
                        "username": username,
                        "auth_type": "ldap",
                        "role": app_role,
                        "permissions": user_perms
                    }
                })
                _set_session_cookie(resp, raw_token)
                return resp

            except LDAPSocketOpenError as e:
                if attempt == max_retries - 1:
                    await log_login_attempt(username, "ldap", "failure", f"Ldap server unreachable: {e}", ip)
                    return response.json({"status": "error", "message": "Invalid username or password."}, status=504)
                await asyncio.sleep(1)

    except Exception as e:
        await log_login_attempt(username, "ldap", "failure", f"Exception: {e}", ip)
        return response.json({"status": "error", "message": "Invalid username or password."}, status=401)

    await log_login_attempt(username, "combined", "failure", "All methods failed", ip)
    return response.json({"status": "error", "message": "Invalid username or password."}, status=401)


@app.post("/logout")
async def logout(request):
    """Revoke the current session server-side and clear the cookie.

    Public so that a request carrying an already-dead session still clears the
    browser's cookie instead of bouncing off the 401 in `authenticate`.
    """
    raw_token = request.cookies.get(session_store.SESSION_COOKIE)
    if raw_token:
        try:
            async with userdb_conn() as cnx:
                cur = await cnx.cursor()
                try:
                    await session_store.revoke(cur, raw_token)
                    await cnx.commit()
                finally:
                    await cur.close()
        except Exception as e:
            print(f"[!] Logout revoke failed: {e}")

    resp = sanic_json({"status": "success", "message": "Logged out."})
    _clear_session_cookie(resp)
    return resp



def _sync_ldap_bind(ldap_host, ldap_port, bind_dn, bind_password, use_ssl: bool):
    tls_config = Tls(validate=ssl.CERT_REQUIRED)

    server = Server(
        ldap_host,
        port=int(ldap_port),
        use_ssl=use_ssl,
        tls=tls_config,
        connect_timeout=3,   
        get_info=None        
    )

    conn = Connection(
        server,
        user=bind_dn,
        password=bind_password,
        auto_bind=True,
        raise_exceptions=True,
        receive_timeout=3
    )
    try:
        pass
    finally:
        conn.unbind()

@app.route("/ldap/test-connection", methods=["POST"])
async def test_ldap_connection(request):
    data = request.json or {}
    ldap_host = data.get("ldap_host")
    ldap_port = data.get("ldap_port")
    bind_dn = data.get("bind_dn")
    bind_password = data.get("bind_password")
    use_ssl = bool(data.get("use_ssl", True))

    if not all([ldap_host, ldap_port, bind_dn, bind_password]):
        return response.json({"status": "error", "message": "Missing LDAP parameters"}, status=400)
    try:
        ldap_port = int(ldap_port)
        if not (1 <= ldap_port <= 65535):
            raise ValueError()
    except Exception:
        return response.json({"status": "error", "message": "Invalid ldap_port"}, status=400)

    overall_timeout = float(data.get("timeout", 5))

    try:
        await asyncio.wait_for(
            asyncio.to_thread(_sync_ldap_bind, ldap_host, ldap_port, bind_dn, bind_password, use_ssl),
            timeout=overall_timeout
        )
        return response.json({"status": "success", "message": "LDAP connection successful"})

    except asyncio.TimeoutError:
        return response.json(
            {"status": "error", "message": f"LDAP connection timed out (>{overall_timeout}s)"},
            status=504
        )
    except LDAPBindError as e:
        return response.json(
            {"status": "error", "message": f"LDAP bind failed: {e}"},
            status=401
        )
    except LDAPSocketOpenError as e:
        return response.json(
            {"status": "error", "message": f"LDAP socket error: {e}"},
            status=502
        )
    except Exception as e:
        return response.json(
            {"status": "error", "message": f"LDAP connection failed: {e}"},
            status=500
        )


@require_permission("role_create")
@app.route("/roles/<role_id>", methods=["PUT"])
async def update_role(request, role_id):
    data = request.json or {}
    new_role_name = data.get("role_name")
    permissions = data.get("permissions", [])
    
    updated_by = current_username(request)

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT role_name FROM roles WHERE id = %s", (role_id,))
        result = await cursor.fetchone()
        if not result:
            await cursor.close()
            await cnx.close()
            return sanic_json({
                "status": "error",
                "message": "Role not found."
            }, status=404)

        current_role_name = result[0]

        if current_role_name in ["admin", "user", "guest"]:
            await cursor.close()
            await cnx.close()
            return sanic_json({
                "status": "error",
                "message": f"System-defined role '{current_role_name}' cannot be edited."
            }, status=403)

        if new_role_name and new_role_name != current_role_name:
            await cursor.execute("SELECT id FROM roles WHERE role_name = %s AND id != %s", (new_role_name, role_id))
            if await cursor.fetchone():
                await cursor.close()
                await cnx.close()
                return sanic_json({
                    "status": "error",
                    "message": f"Role name '{new_role_name}' already exists."
                }, status=409)

            await cursor.execute("""
                UPDATE roles 
                SET role_name = %s, updated_by = %s, updated_at = NOW()
                WHERE id = %s
            """, (new_role_name, updated_by, role_id))

            await cursor.execute("""
                UPDATE users 
                SET role = %s 
                WHERE role = %s
            """, (new_role_name, current_role_name))

        if permissions is not None:
            await cursor.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))

            if permissions:
                placeholders = ','.join(['%s'] * len(permissions))
                await cursor.execute(f"SELECT name FROM permissions WHERE name IN ({placeholders})", permissions)
                valid_permissions = [row[0] for row in await cursor.fetchall()]

                invalid_permissions = set(permissions) - set(valid_permissions)
                if invalid_permissions:
                    await cursor.close()
                    await cnx.close()
                    return sanic_json({
                        "status": "error",
                        "message": f"Invalid permissions: {', '.join(invalid_permissions)}"
                    }, status=400)

                for perm_name in permissions:
                    await cursor.execute("""
                        INSERT INTO role_permissions (role_id, permission_id)
                        SELECT %s, id FROM permissions WHERE name = %s
                    """, (role_id, perm_name))

        await cnx.commit()
        await cursor.close()
        await cnx.close()

        final_role_name = new_role_name if new_role_name else current_role_name

        return sanic_json({
            "status": "success",
            "message": f"Role '{final_role_name}' updated successfully.",
            "role_id": int(role_id),
            "role_name": final_role_name,
            "permissions_updated": permissions is not None
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }, status=500)


@require_permission("manage_users") 
@app.route("/roles/<role_id>", methods=["GET"])
async def get_role_details(request, role_id):
    """Get detailed information about a specific role"""
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("""
            SELECT id, role_name, created_by, created_at, updated_by, updated_at 
            FROM roles WHERE id = %s
        """, (role_id,))
        role_row = await cursor.fetchone()

        if not role_row:
            await cursor.close()
            await cnx.close()
            return sanic_json({
                "status": "error",
                "message": "Role not found."
            }, status=404)

        role_id, role_name, created_by, created_at, updated_by, updated_at = role_row

        await cursor.execute("""
            SELECT p.id, p.name, p.description
            FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.role_id = %s
            ORDER BY p.name
        """, (role_id,))
        permission_rows = await cursor.fetchall()

        permissions = [
            {
                "id": perm_id,
                "name": perm_name,
                "description": perm_desc or ""
            }
            for perm_id, perm_name, perm_desc in permission_rows
        ]

        await cursor.execute("""
            SELECT id, username FROM users WHERE role = %s ORDER BY username
        """, (role_name,))
        user_rows = await cursor.fetchall()

        users = [
            {"id": user_id, "username": username}
            for user_id, username in user_rows
        ]

        await cursor.close()
        await cnx.close()

        return sanic_json({
            "status": "success",
            "role": {
                "id": role_id,
                "role_name": role_name,
                "created_by": created_by,
                "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S") if created_at else None,
                "updated_by": updated_by,
                "updated_at": updated_at.strftime("%Y-%m-%d %H:%M:%S") if updated_at else None,
                "permissions": permissions,
                "users": users,
                "user_count": len(users),
                "permission_count": len(permissions)
            }
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }, status=500)

@require_permission("manage_users")
@app.route("/ldap", methods=["GET"])
async def get_ldap_config(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        # Was `FROM ldap_config ORDER BY updated_at` — neither exists. The
        # table is `ldap_conf` (init_userdb.sql, and every other query in this
        # file) and it has created_at, not updated_at. It is also a
        # single-row table pinned to id=1 by the upsert below, so there is
        # nothing to order by.
        await cursor.execute("SELECT * FROM ldap_conf LIMIT 1")
        columns = [col[0] for col in cursor.description]
        row = await cursor.fetchone()
        await cursor.close(); await cnx.close()
        
        if row:
            config = dict(zip(columns, row))
            config["bind_password"] = "********" if config.get("bind_password") else ""
            return sanic_json({"status": "success", "config": config})
        else:
            return sanic_json({"status": "success", "config": None})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_users")
@app.route("/ldap", methods=["POST"])
async def upsert_ldap(request):
    data = request.json or {}

    required_fields = [
        "ldap_host", "ldap_port", "bind_dn", "bind_password",
        "users_base", "group_base", "login_filter"
    ]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return sanic_json({
            "status": "error",
            "message": f"Missing required fields: {', '.join(missing)}"
        }, status=400)

    try:
        ldap_port = int(data["ldap_port"])
    except ValueError:
        return sanic_json({"status": "error", "message": "ldap_port must be integer"}, status=400)

    encrypted_password = encrypt_password(data["bind_password"])

    sql = """
    INSERT INTO ldap_conf
        (id, ldap_host, ldap_port, bind_dn, bind_password, users_base, group_base, login_filter)
    VALUES
        (1, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        ldap_host = VALUES(ldap_host),
        ldap_port = VALUES(ldap_port),
        bind_dn = VALUES(bind_dn),
        bind_password = VALUES(bind_password),
        users_base = VALUES(users_base),
        group_base = VALUES(group_base),
        login_filter = VALUES(login_filter)
    """

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute(sql, (
            data["ldap_host"],
            ldap_port,
            data["bind_dn"],
            encrypted_password,
            data["users_base"],
            data["group_base"],
            data["login_filter"],
        ))
        await cnx.commit()
        await cursor.close(); await cnx.close()

        return sanic_json({
            "status": "success",
            "message": "LDAP configuration upserted (single-row table enforced)."
        })
    except Exception as e:
        return sanic_json({"status": "error", "message": f"Database error: {str(e)}"}, status=500)


@app.route("/ldap/groups", methods=["GET"])
async def get_ldap_groups(request):
    data = request.json or {}
     
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("""
            SELECT ldap_host, ldap_port, bind_dn, bind_password, group_base
            FROM ldap_conf
        """, )
        row = await cursor.fetchone()
        await cursor.close(); await cnx.close()

        if not row:
            return response.json({"status": "error", "message": "LDAP Conf. Error"}, status=404)

        ldap_host, ldap_port, bind_dn, encrypted_password, group_base = row
        bind_password = decrypt_password(encrypted_password)

        tls_config = Tls(validate=ssl.CERT_REQUIRED)

        server = Server(ldap_host, port=ldap_port, use_ssl=True, tls=tls_config, connect_timeout=3)
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
 
        conn.search(
            search_base=group_base,
            search_filter="(objectClass=groupOfNames)",
            attributes=["cn", "member"]
        )

        groups = [{
            "dn": entry.entry_dn,
            "cn": entry.cn.value,
            "members": entry.member.values if "member" in entry else []
        } for entry in conn.entries]

        conn.unbind()

        return response.json({"status": "success", "groups": groups})

    except Exception as e:
        print(f"[!] LDAP group listing error: {e}")
        return response.json({"status": "error", "message": "LDAP error"}, status=500)

@app.route("/change-password", methods=["POST"])
async def change_password(request):
    try:
        data_raw = request.json or {}
        pw_data = ChangePasswordRequest(**data_raw)
        username = pw_data.username
        current_password = pw_data.current_password
        new_password = pw_data.new_password
    except Exception as e:
        return sanic_json({"status": "error", "message": f"Invalid input: {str(e)}"}, status=400)

    # The username used to come from the request body, so anyone who knew
    # another account's current password could rotate it out from under them.
    # Self-service means self: bind to the session.
    session_user = current_user(request)
    if not session_user:
        return _unauthorized("Authentication required")
    if username != session_user["username"]:
        return sanic_json(
            {"status": "error", "message": "You can only change your own password."},
            status=403,
        )

    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("SELECT password FROM users WHERE username = %s LIMIT 1", (username,))
        row = await cursor.fetchone()
        if not row:
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "error", "message": "No user found"}, status=404)

        db_password = row[0]
        if not bcrypt.checkpw(current_password.encode('utf-8'), db_password.encode('utf-8')):
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "error", "message": "Current password is wrong"}, status=401)

        new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        await cursor.execute("UPDATE users SET password = %s WHERE username = %s", (new_hashed, username))
        await cnx.commit()
        await cursor.close(); await cnx.close()

        # Includes this browser's own session: changing a password should end
        # every session that was issued against the old one.
        await revoke_user_sessions(int(session_user["user_id"]), "password changed")

        resp = sanic_json({
            "status": "success",
            "message": "Password changed. Please sign in again.",
            "reauth_required": True,
        })
        _clear_session_cookie(resp)
        return resp

    except Exception as e:
        return sanic_json({"status": "error", "message": f"Database Error: {e}"}, status=500)

@require_permission("manage_agent")
@app.route("/<agent>/restart", methods=["POST"])
async def trigger_restart(request, agent):
    try:
        if is_soar_enabled():
            resp = await call_agent_soar(agent, "restart_service", "sentora-agent", comment="Restart from UI", background_queue=True)
            cnx = await connect_db_for_agent(agent)
            cursor = await cnx.cursor()
            await cursor.execute(
                "INSERT INTO soar_actions (action, target, status, comment) VALUES (%s, %s, %s, %s)",
                ("restart_service", "sentora-agent", "SUCCESS" if resp.get("ok") else "FAILED", "Restart from UI")
            )
            await cnx.commit()
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "success", "message": resp.get("message", "Restart command processed")})
        return sanic_json({"status": "error", "message": "SOAR is disabled, cannot queue action"}, status=400)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_agent")
@app.route("/<agent>/reload_auth", methods=["POST"])
async def trigger_reload_auth(request, agent):
    try:
        if is_soar_enabled():
            resp = await call_agent_soar(agent, "reload_auth", "sentora-agent", comment="Auth reload from UI", background_queue=True)
            cnx = await connect_db_for_agent(agent)
            cursor = await cnx.cursor()
            await cursor.execute(
                "INSERT INTO soar_actions (action, target, status, comment) VALUES (%s, %s, %s, %s)",
                ("reload_auth", "sentora-agent", "SUCCESS" if resp.get("ok") else "FAILED", "Auth reload from UI")
            )
            await cnx.commit()
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "success", "message": resp.get("message", "Auth reload command processed")})
        return sanic_json({"status": "error", "message": "SOAR is disabled, cannot queue action"}, status=400)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_agent")
@app.route("/<agent>/self_destruct", methods=["POST"])
async def trigger_self_destruct(request, agent):
    try:
        if is_soar_enabled():
            resp = await call_agent_soar(agent, "self_destruct", "agent", comment="Self-destruct from UI", background_queue=True)
            cnx = await connect_db_for_agent(agent)
            cursor = await cnx.cursor()
            await cursor.execute(
                "INSERT INTO soar_actions (action, target, status, comment) VALUES (%s, %s, %s, %s)",
                ("self_destruct", "agent", "SUCCESS" if resp.get("ok") else "FAILED", "Self-destruct from UI")
            )
            await cnx.commit()
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "success", "message": resp.get("message", "Self-destruct command processed")})
        return sanic_json({"status": "error", "message": "SOAR is disabled, cannot queue action"}, status=400)
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("manage_agent")
@app.route("/devices/<agent>")
async def device_health(request, agent):
    try:
        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()

        await cursor.execute("SELECT COUNT(*) FROM agent_info")
        row = await cursor.fetchone()

        await cursor.close()
        await cnx.close()

        exists = row[0] > 0
        status = "healthy" if exists else "unhealthy"

        return sanic_json({
            "agent": agent,
            "exists": exists,
            "status": status
        })
    
    except Exception as e:
        return sanic_json({
            "agent": agent,
            "status": "unreachable",
            "error": f"DB error: {str(e)}"
        }, status=500)

    except Exception as e:
        return sanic_json({
            "agent": agent,
            "status": "unreachable",
            "error": str(e)
        }, status=500)

@app.route("/<agent>/automations/pending", methods=["GET"], name="get_pending_auto_compat")
@app.route("/api/agents/<agent>/automations/pending", methods=["GET"], name="get_pending_auto_api")
async def get_pending_automations_for_agent(request, agent):
    """Endpoint for agent to pull pending tasks. Polled every few seconds by
    every active agent — must NEVER 500 on a fresh agent whose `automations`
    table hasn't been created yet (the schema is provisioned lazily). Without
    this, agents log a flood of `fetch_pending_tasks failed ... 500 ...`.
    """
    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor(dictionary=True)
        try:
            await cur.execute(
                "SELECT id as task_id, action as type, target as target, comment as params_comment FROM automations "
                "WHERE status='pending' AND `timestamp` <= NOW()"
            )
        except Exception as qerr:
            err_str = str(qerr)
            if "1146" in err_str or "doesn't exist" in err_str.lower():
                await cur.close(); await cnx.close()
                return sanic_json({"status": "success", "tasks": []})
            raise
        rows = await cur.fetchall()
        await cur.close(); await cnx.close()

        def _params_for(action: str, target_raw):
            params: dict = {"target": target_raw}
            act = (action or "").strip().lower()
            if act == "run_cmd":
                cmd_list = None
                if isinstance(target_raw, list):
                    cmd_list = [str(x) for x in target_raw if x not in (None, "")]
                elif isinstance(target_raw, (str, bytes)):
                    s = target_raw.decode() if isinstance(target_raw, bytes) else target_raw
                    s = (s or "").strip()
                    if s.startswith("[") and s.endswith("]"):
                        try:
                            parsed = pyjson.loads(s)
                            if isinstance(parsed, list):
                                cmd_list = [str(x) for x in parsed if x not in (None, "")]
                        except Exception:
                            cmd_list = None
                    if cmd_list is None and s:
                        import shlex
                        try:
                            cmd_list = shlex.split(s, posix=False)
                        except Exception:
                            cmd_list = [s]
                params["cmd"] = cmd_list or []
            return params

        tasks = [
            {
                "id": r["task_id"],
                "type": r["type"],
                "params": {
                    **_params_for(r["type"], r["target"]),
                    "comment": r["params_comment"],
                },
            }
            for r in rows
        ]
        return sanic_json({"status": "success", "tasks": tasks})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@app.route("/automations/<task_id:int>/report", methods=["POST"])
async def report_automation_result_by_id(request, task_id):
    """Endpoint for agent to report task completion"""
    data = request.json or {}
    status = data.get("status", "completed")
    output = data.get("output", "")
    agent = data.get("agent")
    
    if not agent:
        return sanic_json({"status": "error", "message": "agent name required"}, status=400)

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "UPDATE automations SET status=%s, comment=CONCAT(comment, %s), updated_at=NOW() WHERE id=%s",
            (status, f" | Agent Report: {output}"[:200], task_id)
        )
        await cnx.commit(); await cur.close(); await cnx.close()
        return sanic_json({"status": "success"})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@app.route("/db-status")
async def db_status(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("SELECT VERSION();")
        results = await cursor.fetchall()
        version_str = results[0][0] if results else "Unknown"
        await cursor.close(); await cnx.close()
        return sanic_json({"mysql": f"online, version: {version_str}"})
    except Exception as e:
        return sanic_json({"error": f"Database connection failed: {e}"}, status=500)

@require_permission("read_telemetry")
@app.route("/devices")
async def list_agents(request):
    try:
        def get_agent_names():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    databases = cursor.fetchall()
                    return sorted([db[0].replace('_db', '') for db in databases if db[0].endswith('_db')])
                finally:
                    cursor.close()

        agents_names = await asyncio.to_thread(get_agent_names)

        async def get_agent_details(name):
            try:
                cnx = await connect_db_for_agent(name)
                cur = await cnx.cursor(dictionary=True)
                await cur.execute("SELECT public_ip, os_info, last_seen FROM agent_info ORDER BY last_seen DESC LIMIT 1")
                row = await cur.fetchone()
                await cur.close()
                await cnx.close()

                status = "Offline"
                last_seen_str = "Never"
                if row:
                    ls = row.get("last_seen")
                    if isinstance(ls, datetime):
                        last_seen_str = ls.strftime("%Y-%m-%d %H:%M:%S")
                        delta = abs((datetime.now() - ls).total_seconds())
                        if delta < 90:
                            status = "Online"
                    
                    return {
                        "name": name,
                        "status": status,
                        "last_seen": last_seen_str,
                        "public_ip": row.get("public_ip", "-"),
                        "os_info": row.get("os_info", "Generic Linux")
                    }
                return {"name": name, "status": "Offline", "last_seen": "Never", "public_ip": "-", "os_info": "Unknown"}
            except Exception as e:
                return {"name": name, "status": "Error", "last_seen": "DB Error", "public_ip": "-", "os_info": "Unknown"}

        agent_details = await asyncio.gather(*(get_agent_details(n) for n in agents_names))
        
        return sanic_json({"agents": agent_details})
    except Exception as e:
        return sanic_json({"error": f"Database error while listing agents: {e}"}, status=500)


    
@require_permission("manage_db")
@app.route("/restart-db", methods=["POST"])
async def restart_db(request):
    try:
        result = subprocess.run(
            ["docker", "compose", "restart", "mysql"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return sanic_json({
                "status": "error",
                "message": f"Restart failed: {result.stderr.strip()}"
            }, status=500)

        return sanic_json({
            "status": "success",
            "message": "MySQL container restarted using docker compose."
        })

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Exception while restarting container: {str(e)}"
        }, status=500)



@require_permission("clear_logs")
@app.route("/<agent>/clear/<table>", methods=["POST"])
async def clear_table(request, agent, table):
    allowed_tables = ["events_alert", "siem_events"]
    if table not in allowed_tables:
        return sanic_json({"status": "error", "message": f"{table} Can't be cleaned."}, status=403)

    try:
        cnx = await connect_db_for_agent(agent)
        cursor = await cnx.cursor()
        await cursor.execute(f"TRUNCATE TABLE {table}")
        await cnx.commit()
        await cursor.close(); await cnx.close()
        return sanic_json({"status": "success", "message": f"{table} tablosu temizlendi."})
    except Exception as e:
        return sanic_json({"status": "error", "message": f"DB error: {e}"}, status=500)

@require_permission("clear_logs")
@app.route("/<agent>/clear_delayed/<table>", methods=["POST"])
async def clear_table_delayed(request, agent, table):
    allowed_tables = ["events_alert", "siem_events"]
    data = request.json or {}
    delay = int(data.get("delay", 0))

    if table not in allowed_tables:
        return sanic_json({"status": "error", "message": f"{table} no permission"}, status=403)

    if delay <= 0:
        return sanic_json({"status": "error", "message": "Give a valid entr"}, status=400)

    async def delayed_clear():
        await asyncio.sleep(delay)
        try:
            cnx = await connect_db_for_agent(agent)
            cursor = await cnx.cursor()
            await cursor.execute(f"TRUNCATE TABLE {table}")
            await cnx.commit()
            await cursor.close(); await cnx.close()
            print(f"{table} {delay} cleaned after this.")
        except Exception as e:
            print(f"Error occurred: {e}")

    request.app.add_task(delayed_clear())  
    return sanic_json({
        "status": "scheduled",
        "message": f"{table} {delay} going to be clean after."
    })

@require_permission("read_telemetry")
@app.route("/all_alerts")
async def get_all_alerts(request):

    try:
        def _list_agents():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    return [db[0].replace('_db', '') for db in cursor.fetchall() if db[0].endswith('_db')]
                finally:
                    cursor.close()
        agents = await asyncio.to_thread(_list_agents)

        all_alerts = []

        for agent in agents:
            try:
                async with agent_conn(agent) as cnx:
                    cursor = await cnx.cursor()
                    try:
                        await cursor.execute("SELECT * FROM events_alert ORDER BY id DESC LIMIT 100")
                        columns = [col[0] for col in cursor.description]
                        rows = await cursor.fetchall()
                    finally:
                        await cursor.close()

                for row in rows:
                    alert = dict(zip(columns, row))
                    alert['agent'] = agent
                    all_alerts.append(alert)

            except Exception as e:
                print(f"[!] Error fetching alerts for agent {agent}: {e}")

        json_stream = '[' + ','.join(
            [pyjson.dumps(alert, cls=CustomEncoder, ensure_ascii=False) for alert in all_alerts]
        ) + ']'

        return HTTPResponse(
            body=json_stream,
            content_type="application/json; charset=utf-8"
        )

    except Exception as e:
        return sanic_json({
            "status": "error",
            "message": f"Error while streaming alerts from all agents: {e}"
        }, status=500)


async def periodic_critical_alerts_check():
    while True:
        try:
            await asyncio.sleep(300)
            print("[+] Running periodic critical alerts check...")
            await asyncio.to_thread(dispatch_all_critical_alerts)
        except Exception as e:
            print(f"[!] Error in periodic critical alerts check: {e}")

async def periodic_soar_automation_check():
    while True:
        try:
            await asyncio.sleep(30)
            def _list_agents():
                with sync_mysql_conn() as c:
                    cur = c.cursor()
                    cur.execute("SHOW DATABASES")
                    agents = [db[0].replace('_db', '') for db in cur.fetchall() if db[0].endswith('_db')]
                    cur.close()
                    return agents
            agents = await asyncio.to_thread(_list_agents)

            for agent in agents:
                try:
                    await _run_due_automations_logic(agent)
                except Exception as e:
                    print(f"[SOAR] Periodic check failed for agent {agent}: {e}")
        except Exception as e:
            print(f"[SOAR] Global periodic check failed: {e}")

async def _run_due_automations_logic(agent):
    async with agent_conn(agent) as cnx:
        cur = await cnx.cursor(dictionary=True)
        try:
            await cur.execute(
                "SELECT * FROM automations WHERE status='pending' AND `timestamp` <= NOW() ORDER BY `timestamp` ASC"
            )
            rows = await cur.fetchall()
        finally:
            await cur.close()

    for rec in rows or []:
        async with agent_conn(agent) as cnx:
            cur = await cnx.cursor()
            try:
                await cur.execute("UPDATE automations SET status='active' WHERE id=%s", (rec["id"],))
                await cnx.commit()
            finally:
                await cur.close()

        result = await call_agent_soar(
            agent,
            action=rec["action"],
            target=rec["target"],
            comment=f"automation#{rec['id']} | {rec.get('comment') or ''}".strip(),
            event_id=rec.get("event_id"),
        )

        status = "completed" if result.get("ok") else "failed"
        async with agent_conn(agent) as cnx:
            cur = await cnx.cursor()
            try:
                await cur.execute("UPDATE automations SET status=%s WHERE id=%s", (status, rec["id"]))
                await cnx.commit()
            finally:
                await cur.close()

@app.before_server_start
async def setup_background_tasks(app, _):
    worker_name = os.environ.get("SANIC_WORKER_NAME", "")
    if "0-0" in worker_name or not worker_name:
        print(f"[*] Starting background tasks in worker: {worker_name or 'single'}")
        app.add_task(periodic_critical_alerts_check())
        app.add_task(periodic_soar_automation_check())
        app.add_task(periodic_threat_intel_update())
        app.add_task(periodic_vuln_scan())
        app.add_task(periodic_session_purge())
    else:
        pass


async def periodic_session_purge():
    """Drop expired/revoked session rows hourly so the table stays bounded."""
    while True:
        await asyncio.sleep(3600)
        try:
            async with userdb_conn() as cnx:
                cur = await cnx.cursor()
                try:
                    removed = await session_store.purge_expired(cur)
                    await cnx.commit()
                finally:
                    await cur.close()
            if removed:
                print(f"[Session] Purged {removed} expired session row(s).")
        except Exception as e:
            print(f"[!] Session purge failed: {e}")


VULN_SCAN_INTERVAL = int(os.getenv("VULN_SCAN_INTERVAL", "1800"))


async def _list_agent_names_sync() -> list:
    """Return all `*_db` agent names by querying SHOW DATABASES via the
    sync-root pool, mirroring the /devices endpoint."""
    def _q():
        with sync_mysql_conn() as conn:
            cur = conn.cursor()
            try:
                cur.execute("SHOW DATABASES")
                return [r[0].replace("_db", "") for r in cur.fetchall() if r[0].endswith("_db")]
            finally:
                cur.close()
    return await asyncio.to_thread(_q)


async def periodic_vuln_scan():
    """Periodic OSV vulnerability scan against every agent's `packages` table.
    Moved off the agent so endpoints don't burn CPU on a 5-minute find_vuln run.

    On first run, the OSV endpoint (public vs air-gap mirror) is resolved
    once — see modules/vuln_scanner.resolve_osv_endpoint for the selection
    logic. Subsequent cycles reuse the same URL.
    """
    await asyncio.sleep(60)
    from scanners.vuln import scan_all_agents, resolve_osv_endpoint
    await asyncio.to_thread(resolve_osv_endpoint)
    while True:
        try:
            key_b64 = getattr(app.ctx, "fernet_key", None) or bootstrap_client.get_fernet_key()
            print("[VulnScanner] starting cycle...", flush=True)
            stats = await scan_all_agents(key_b64, connect_db_for_agent, _list_agent_names_sync)
            total_inserted = sum(s.get("inserted", 0) for s in stats)
            print(f"[VulnScanner] cycle done — agents={len(stats)} new_findings={total_inserted}", flush=True)
        except Exception as e:
            print(f"[VulnScanner] cycle failed: {e}", flush=True)
        await asyncio.sleep(VULN_SCAN_INTERVAL)


@app.post("/<agent>/vulns/scan")
@require_permission("read_telemetry")
async def trigger_agent_vuln_scan(request, agent):
    """Manual trigger for a single-agent OSV scan."""
    try:
        from scanners import vuln as _vs
        if _vs._OSV_BASE is None:
            await asyncio.to_thread(_vs.resolve_osv_endpoint)
        scan_agent = _vs.scan_agent
        key_b64 = getattr(app.ctx, "fernet_key", None) or bootstrap_client.get_fernet_key()
        stat = await scan_agent(agent, key_b64, connect_db_for_agent)
        return sanic_json({"ok": True, **stat})
    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)

MOCK_INDICATORS_TO_PURGE = [
    # Seeded by the previous mock updater. The empty-string SHA-256 was
    # labelled CRITICAL malware: matching against it would flag every empty
    # file on every endpoint. The two IPs were illustrative, not sourced.
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "185.220.101.5",
    "45.146.165.37",
]


async def purge_mock_threat_intel():
    """Delete the hardcoded indicators the old updater wrote.

    Removing them from the code is not enough — they are already in every
    deployment's database, and the empty-hash row is an active false-positive
    source. Matched on source too, so an operator who has legitimately added
    one of these addresses by hand keeps it.
    """
    try:
        with sync_mysql_conn("sentora_hub") as conn:
            cur = conn.cursor()
            try:
                placeholders = ",".join(["%s"] * len(MOCK_INDICATORS_TO_PURGE))
                cur.execute(
                    f"""DELETE FROM threat_intel
                         WHERE value IN ({placeholders})
                           AND source IN ('TorExitNode', 'BruteForceList', 'MalwareDB')""",
                    MOCK_INDICATORS_TO_PURGE,
                )
                removed = cur.rowcount
                conn.commit()
            finally:
                cur.close()
        if removed:
            print(f"[ThreatIntel] Purged {removed} mock indicator(s) from the previous seeder.")
    except Exception as e:
        print(f"[ThreatIntel] Could not purge mock indicators: {e}")


async def periodic_threat_intel_update():
    """Refresh indicators from real feeds, hourly.

    This used to insert three hardcoded rows. See core/threat_feeds.py for
    what replaced it and how to point it at an internal mirror.
    """
    await purge_mock_threat_intel()

    while True:
        try:
            if threat_feeds.mode() == "off":
                print("[ThreatIntel] Disabled (THREAT_INTEL_MODE=off).")
            else:
                indicators, errors = await asyncio.to_thread(threat_feeds.fetch_all)

                for err in errors:
                    print(f"[ThreatIntel] feed error — {err}")

                if indicators:
                    def _write():
                        with sync_mysql_conn("sentora_hub") as conn:
                            cur = conn.cursor()
                            try:
                                cur.execute(
                                    "ALTER TABLE threat_intel ADD COLUMN last_seen "
                                    "TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP"
                                )
                            except Exception:
                                pass  # already present
                            cur.executemany(
                                """INSERT INTO threat_intel
                                       (type, value, source, severity, description, last_seen)
                                   VALUES (%s, %s, %s, %s, %s, NOW())
                                   ON DUPLICATE KEY UPDATE
                                       source = VALUES(source),
                                       severity = VALUES(severity),
                                       description = VALUES(description),
                                       last_seen = NOW()""",
                                [(i.type, i.value, i.source, i.severity, i.description)
                                 for i in indicators],
                            )
                            written = cur.rowcount
                            # Indicators that stopped appearing in the feeds.
                            # An IP that hosted a C2 last quarter usually
                            # belongs to someone else now.
                            cur.execute(
                                "DELETE FROM threat_intel "
                                "WHERE source LIKE 'abuse.ch/%%' "
                                "AND last_seen < (NOW() - INTERVAL %s DAY)",
                                (threat_feeds.STALE_AFTER_DAYS,),
                            )
                            stale = cur.rowcount
                            conn.commit()
                            return written, stale

                    written, stale = await asyncio.to_thread(_write)
                    print(f"[ThreatIntel] {len(indicators)} indicator(s) from "
                          f"{len(threat_feeds.enabled_feeds())} feed(s); pruned {stale} stale.")
                elif not errors:
                    print("[ThreatIntel] Feeds returned no indicators.")
        except Exception as e:
            print(f"[ThreatIntel] Refresh failed: {e}")

        await asyncio.sleep(3600)

@require_permission("read_telemetry")
@app.route("/threat-intel")
async def get_threat_intel(request):
    try:
        async with aiomysql.create_pool(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, db="sentora_hub", autocommit=True) as pool:
            async with pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute("SELECT * FROM threat_intel ORDER BY created_at DESC")
                    rows = await cur.fetchall()
        # `created_at` is a datetime, which the default serializer cannot
        # encode — so this 500'd for every populated table and only ever
        # looked healthy while threat_intel was empty. Every other endpoint
        # in this file already passes CustomEncoder; this one was missed.
        return sanic_json(
            rows,
            dumps=lambda obj: pyjson.dumps(obj, ensure_ascii=False, cls=CustomEncoder),
        )
    except Exception as e:
        # There was no handler at all, so failures fell through to the global
        # one and surfaced as "Contact administrator" with the cause hidden.
        print(f"[!] threat-intel fetch failed: {e}")
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("read_telemetry")
@app.route("/api/exposure/report", name="exposure_report")
# Kept so anything already pointing at the old path keeps working. The name is
# wrong for what it returns, which is why it is not the primary route.
@app.route("/api/compliance/report", name="compliance_report_legacy")
async def get_exposure_report(request):
    """Fleet exposure: unpatched packages and recent file-integrity changes.

    This was `/api/compliance/report` and returned
    `100 - (vulns * 2) - (fim * 5)` as a "compliance score". That is not
    compliance — it maps to no framework, so it cannot be shown to an auditor;
    it does not scale with fleet size, so ten vulnerabilities on one agent and
    ten across fifty score identically; and at fifty vulnerabilities it pins to
    zero, which is an ordinary state for a real fleet. A number nobody can
    define is a number nobody can act on.

    It also queried `sentora_hub` for two tables that only exist per-agent, so
    it had never returned anything but a 500. Creating them empty there would
    have made it answer EXCELLENT/100 forever.

    What is reported now is only what is actually measured: counts, per agent,
    with explicit coverage. No score.

    Severity breakdown is deliberately absent — `vulnerabilities_report` has no
    severity column and its fields are encrypted at rest, so any grading would
    have to be invented here.
    """
    try:
        agents = await _list_agent_names_sync()

        per_agent: list[dict] = []
        unreachable: list[str] = []
        totals = {"vulnerabilities": 0, "fim_changed": 0, "fim_new": 0, "fim_deleted": 0}

        for agent in agents:
            try:
                async with agent_conn(agent) as cnx:
                    cur = await cnx.cursor()
                    try:
                        await cur.execute("SELECT COUNT(*) FROM vulnerabilities_report")
                        row = await cur.fetchone()
                        vulns = int(row[0]) if row else 0

                        # Grouped rather than summed: "12 files changed" and
                        # "12 files deleted" are very different mornings.
                        await cur.execute(
                            "SELECT status, COUNT(*) FROM fim_data "
                            "WHERE status IS NOT NULL AND status <> 'baseline' "
                            "AND last_seen > NOW() - INTERVAL 1 DAY "
                            "GROUP BY status"
                        )
                        fim_rows = await cur.fetchall() or []
                    finally:
                        await cur.close()

                fim = {str(s).lower(): int(c) for s, c in fim_rows}
                entry = {
                    "agent": agent,
                    "vulnerabilities": vulns,
                    "fim_changed": fim.get("changed", 0),
                    "fim_new": fim.get("new", 0),
                    "fim_deleted": fim.get("deleted", 0),
                }
                per_agent.append(entry)
                for key in totals:
                    totals[key] += entry[key]
            except Exception as e:
                # A newly-enrolled agent may not have provisioned these tables
                # yet. Skipping is correct; hiding it is not — a total over
                # half the fleet is not a fleet total.
                print(f"[exposure] skipped {agent}: {e}")
                unreachable.append(agent)

        # Worst first: the operator wants to know where to start.
        per_agent.sort(key=lambda a: (a["vulnerabilities"], a["fim_changed"]), reverse=True)

        return sanic_json({
            "status": "success",
            "totals": totals,
            "agents": per_agent,
            "coverage": {
                "agents_total": len(agents),
                "agents_scanned": len(per_agent),
                "agents_unreachable": unreachable,
                # False when the numbers do not cover the whole fleet, so the
                # UI can mark them partial rather than authoritative.
                "complete": bool(agents) and not unreachable,
            },
            "window": "fim counts cover the last 24 hours",
            "timestamp": datetime.now().isoformat(),
        })
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

@require_permission("read_telemetry")
@app.route("/api/assets")
async def get_assets(request):
    """
    Returns consolidated hardware inventory.
    """
    try:
        async with aiomysql.create_pool(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, db="sentora_hub", autocommit=True) as pool:
            async with pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute("SELECT * FROM hardware_inventory ORDER BY timestamp DESC")
                    rows = await cur.fetchall()
                    return sanic_json(rows)
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)



@require_permission("manage_users")
@app.route("/login-logs", methods=["GET"])
async def stream_login_logs(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("SELECT * FROM login_logs ORDER BY id DESC")
        columns = [col[0] for col in cursor.description]
        rows = await cursor.fetchall()
        await cursor.close(); await cnx.close()

        json_lines = [
            pyjson.dumps(dict(zip(columns, row)), cls=CustomEncoder, ensure_ascii=False)
            for row in rows
        ]

        return HTTPResponse(
            body='[' + ','.join(json_lines) + ']',
            content_type="application/json; charset=utf-8"
        )
    except Exception as e:
        return sanic_json({"status": "error", "message": f"DB error: {e}"}, status=500)

@app.route("/test-audit", methods=["GET"])
async def test_audit_log(request):
    await audit_log(request, "TEST_ACTION", "TEST_RESOURCE", "Testing audit log insertion")
    return sanic_json({"status": "success", "message": "Test audit log triggered"})

@require_permission("manage_users")
@app.route("/audit-logs", methods=["GET"])
async def stream_audit_logs(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()
        await cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
        columns = [col[0] for col in cursor.description]
        rows = await cursor.fetchall()
        await cursor.close(); await cnx.close()

        json_lines = [
            pyjson.dumps(dict(zip(columns, row)), cls=CustomEncoder, ensure_ascii=False)
            for row in rows
        ]

        return HTTPResponse(
            body='[' + ','.join(json_lines) + ']',
            content_type="application/json; charset=utf-8"
        )
    except Exception as e:
        return sanic_json({"status": "error", "message": f"DB error: {e}"}, status=500)


@require_permission("manage_db")
@require_permission("manage_db")
@app.route("/databases", methods=["GET"])
async def list_databases(request):

    try:
        def _q():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW DATABASES")
                    excluded = {"information_schema", "mysql", "performance_schema", "sys"}
                    return [row[0] for row in cursor.fetchall() if row[0] not in excluded]
                finally:
                    cursor.close()
        all_dbs = await asyncio.to_thread(_q)
        return sanic_json({"status": "success", "databases": all_dbs})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)

# MySQL: 1049 unknown database, 1146 table doesn't exist. Both mean the
# client named something that isn't there — a 404, not a server fault. They
# were surfacing as 500s, which makes a mistyped name in the DB browser look
# like the platform is broken and buries real faults in the same bucket.
_MISSING_OBJECT_CODES = (1049, 1146)


def _db_object_error(e: Exception):
    code = getattr(e, "errno", None)
    if code is None:
        m = re.search(r"\b(1049|1146)\b", str(e))
        code = int(m.group(1)) if m else None
    if code in _MISSING_OBJECT_CODES:
        return sanic_json({"status": "error", "message": str(e)}, status=404)
    return sanic_json({"status": "error", "message": str(e)}, status=500)


@require_permission("manage_db")
@app.route("/databases/<db_name>/tables", methods=["GET"])
async def list_tables_in_database(request, db_name):
    try:
        def _q():
            with sync_mysql_conn(db_name) as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SHOW TABLES")
                    return [row[0] for row in cursor.fetchall()]
                finally:
                    cursor.close()
        tables = await asyncio.to_thread(_q)
        return sanic_json({"status": "success", "tables": tables})
    except Exception as e:
        return _db_object_error(e)

@require_permission("manage_db")
@app.route("/databases/<db_name>/tables/<table_name>/columns", methods=["GET"])
async def list_table_columns(request, db_name, table_name):
    try:
        def _q():
            with sync_mysql_conn(db_name) as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(f"DESCRIBE `{table_name}`")
                    return [
                        {"name": row[0], "type": row[1], "null": row[2], "key": row[3], "default": row[4], "extra": row[5]}
                        for row in cursor.fetchall()
                    ]
                finally:
                    cursor.close()
        columns = await asyncio.to_thread(_q)
        return sanic_json({"status": "success", "columns": columns})
    except Exception as e:
        return _db_object_error(e)

@require_permission("manage_db")
@app.route("/databases/<db_name>/tables/<table_name>/data", methods=["GET"])
async def get_table_data(request, db_name, table_name):
    try:
        limit = int(request.args.get("limit", 100))
        def _q():
            with sync_mysql_conn(db_name) as conn:
                cursor = conn.cursor(dictionary=True)
                try:
                    cursor.execute(f"SELECT * FROM `{table_name}` LIMIT %s", (limit,))
                    return cursor.fetchall()
                finally:
                    cursor.close()
        rows = await asyncio.to_thread(_q)
        
        json_rows = [
            pyjson.dumps(row, cls=CustomEncoder, ensure_ascii=False)
            for row in rows
        ]
        
        return HTTPResponse(
            body='{"status": "success", "data": [' + ','.join(json_rows) + ']}',
            content_type="application/json; charset=utf-8"
        )
    except Exception as e:
        return _db_object_error(e)

@require_permission("manage_users")
@app.route("/roles/<role_id>", methods=["DELETE"])
async def delete_role(request, role_id):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT role_name FROM roles WHERE id = %s", (role_id,))
        result = await cursor.fetchone()
        if not result:
            await cursor.close(); await cnx.close()
            return sanic_json({"status": "error", "message": "Role not found"}, status=404)

        role_name = result[0]
        if role_name in ["admin"]:
            return sanic_json({"status": "error", "message": f"System-defined role '{role_name}' cannot be deleted."}, status=403)

        await cursor.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))
        await cursor.execute("DELETE FROM roles WHERE id = %s", (role_id,))
        await cnx.commit()

        await cursor.close(); await cnx.close()
        return sanic_json({"status": "success", "message": f"Role '{role_name}' deleted successfully."})
    
    except Exception as e:
        return sanic_json({"status": "error", "message": f"Database error: {e}"}, status=500)

@require_permission("manage_users")
@app.route("/permissions", methods=["GET"])
async def list_permissions(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT id, name, description FROM permissions")
        rows = await cursor.fetchall()
        await cursor.close(); await cnx.close()

        permissions = [
            {
                "id": row[0],
                "name": row[1],
                "description": row[2] or ""
            }
            for row in rows
        ]
        return sanic_json({"status": "success", "permissions": permissions})

    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)




@require_permission("manage_users")
@app.route("/roles", methods=["GET"])
async def list_roles(request):
    try:
        cnx = await connect_userdb()
        cursor = await cnx.cursor()

        await cursor.execute("SELECT id, role_name, created_by, created_at FROM roles")
        role_rows = await cursor.fetchall()

        roles = []
        for role in role_rows:
            role_id, role_name, created_by, created_at = role

            await cursor.execute("""
                SELECT p.name, p.description
                FROM role_permissions rp
                JOIN permissions p ON rp.permission_id = p.id
                WHERE rp.role_id = %s
            """, (role_id,))
            permission_rows = await cursor.fetchall()

            permissions = [
                {"name": perm_name, "description": perm_desc or ""}
                for perm_name, perm_desc in permission_rows
            ]

            roles.append({
                "id": role_id,
                "role_name": role_name,
                "created_by": created_by,
                "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S") if created_at else None,
                "permissions": permissions
            })

        await cursor.close(); await cnx.close()

        return sanic_json({
            "status": "success",
            "roles": roles
        })

    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)


async def _get_agent_keys(agent: str) -> list:
    """Return the candidate `X-Agent-Key` values to try for outbound
    server→agent calls. Order: enrolled per-agent key first, then the
    master AGENT_SHARED_SECRET as fallback. Trying both covers freshly
    enrolled agents and agents still on the shared secret without
    operators tracking which mode each one is in.
    """
    keys: list = []
    try:
        cnx = await connect_userdb()
        cur = await cnx.cursor()
        try:
            await cur.execute(
                "SELECT agent_key FROM agent_identities WHERE agent_name=%s AND revoked_at IS NULL LIMIT 1",
                (agent,),
            )
            row = await cur.fetchone()
        finally:
            await cur.close()
            await cnx.close()
        if row and row[0]:
            keys.append(row[0])
    except Exception as e:
        print(f"[!] _get_agent_keys lookup failed for {agent}: {e}", flush=True)
    if AGENT_SHARED_SECRET and AGENT_SHARED_SECRET not in keys:
        keys.append(AGENT_SHARED_SECRET)
    return keys


def _try_agent_request(method: str, url: str, keys: list, json_body=None, timeout: int = 5):
    """Issue an HTTP request to an agent, retrying with each candidate key on
    401 unauthorized. Returns the first non-401 response (success or other error).

    Logs which key fingerprint matched/failed so operators can diagnose stale
    agent_identities rows, mismatched master AGENT_SHARED_SECRET env, etc.
    """
    last_resp = None
    candidates = list(keys) if keys else [""]
    for idx, k in enumerate(candidates):
        kfp = (k[:6] + "…") if k else "<empty>"
        headers = {"X-Agent-Key": k}
        if method.upper() == "GET":
            resp = requests.get(url, headers=headers, timeout=timeout)
        else:
            resp = requests.post(url, json=json_body, headers=headers, timeout=timeout)
        last_resp = resp
        if resp.status_code != 401:
            if idx > 0:
                print(f"[agent-proxy] {url} matched key#{idx} ({kfp})", flush=True)
            return resp
        print(f"[agent-proxy] {url} 401 with key#{idx} ({kfp})", flush=True)
    return last_resp


async def _get_agent_http_base(agent: str) -> str:
    """
    Agent'ın HTTP base URL'sini döner.
    - IP'yi ilgili agent'ın kendi DB'sindeki agent_info tablosundan çeker.
    - IP yoksa veya bozuksa 127.0.0.1'e düşer.
    - Port env'den AGENT_PORT ile override edilebilir (default 9099).
    """
    host = "127.0.0.1"

    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "SELECT public_ip FROM agent_info "
            "ORDER BY last_seen DESC LIMIT 1"
        )
        row = await cur.fetchone()
        await cur.close()
        await cnx.close()

        if row and row[0]:
            candidate = str(row[0]).strip()
            if _is_valid_ipv4(candidate):
                host = candidate
            else:
                pass
        else:
            pass

    except Exception as e:
        pass

    agent_port = int(os.getenv("AGENT_PORT", "9099"))
    return f"http://{host}:{agent_port}"


def _shape_soar_target(action: str, target):
    """Normalize a target value into the shape each SOAR action expects.

    run_cmd on the agent requires a non-empty *list* (argv form); everything
    else takes a single string. Accept strings, lists, JSON-encoded lists,
    and shape consistently.

    CRITICAL: must be idempotent. If a previous trigger already JSON-encoded
    the list to `'["dir"]'` and stored it in the automations table, the next
    poll cycle that re-shapes the value MUST NOT wrap it again (otherwise
    each retry escapes the quotes once more and the target eventually
    explodes into a multi-kilobyte chain of backslashes).
    """
    act = (action or "").strip().lower()
    if act == "run_cmd":
        # already a list — just clean it
        if isinstance(target, list):
            return [str(x) for x in target if x is not None and str(x) != ""]
        s = "" if target is None else str(target).strip()
        if not s:
            return []
        # JSON-encoded list ('["dir"]') from a previous shaping round — unwrap
        # and keep unwrapping while we still find a nested JSON list, so we
        # never double-escape.
        for _ in range(6):
            if not (s.startswith('[') and s.endswith(']')):
                break
            try:
                parsed = pyjson.loads(s)
            except Exception:
                break
            if not isinstance(parsed, list):
                break
            cleaned = [str(x) for x in parsed if x is not None and str(x) != ""]
            if len(cleaned) == 1 and cleaned[0].startswith('[') and cleaned[0].endswith(']'):
                s = cleaned[0]
                continue
            return cleaned
        # plain shell-style string — split with shlex (POSIX off for Windows paths)
        import shlex
        try:
            return shlex.split(s, posix=False)
        except Exception:
            return [s]
    if isinstance(target, list):
        return " ".join(str(x) for x in target).strip()
    return str(target).strip() if target is not None else ""


async def call_agent_soar(
    agent: str,
    action: str,
    target,
    *,
    comment: str = "",
    event_id: int | None = None,
    ttl: int | None = None,
    background_queue: bool = True
) -> dict:
    """
    Server → Agent /soar/execute çağrısı.
    background_queue=True (default) ise, ajan direkt push'u kaçırsa bile polling ile alsın diye DB'ye yazar.
    """
    target = _shape_soar_target(action, target)

    if background_queue:
        try:
            eid = int(event_id) if event_id is not None else 0
            db_target = pyjson.dumps(target) if isinstance(target, list) else target
            cnx = await connect_db_for_agent(agent)
            cur = await cnx.cursor()
            await cur.execute("""
                INSERT INTO automations
                (device, event_id, action, target, comment, status, `timestamp`, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'pending', NOW(), NOW(), NOW())
            """, (agent, eid, action, db_target, comment))
            await cnx.commit()
            await cur.close(); await cnx.close()
        except Exception as e:
            print(f"[!] Background skip: Failed to queue '{action}' for {agent}: {e}")

    base = await _get_agent_http_base(agent)
    keys = await _get_agent_keys(agent)
    url = f"{base}/soar/execute"

    payload: dict = {
        "action": action,
        "target": target,
    }
    if comment: payload["comment"] = comment
    if event_id is not None: payload["event_id"] = int(event_id)
    if ttl is not None: payload["ttl"] = int(ttl)

    def _post():
        return _try_agent_request("POST", url, keys, payload, 5)

    try:
        resp = await asyncio.to_thread(_post)
        
        try:
            data = resp.json() or {}
        except Exception:
            data = {}

        http_ok = 200 <= resp.status_code < 300
        agent_ok = bool(data.get("ok", True))
        
        if http_ok and agent_ok:
            return {
                "ok": True,
                "queued": background_queue,
                "message": data.get("message", "Action pushed to agent"),
                "soar_action_id": data.get("soar_action_id"),
                **data
            }
        else:
            msg = data.get("error") or data.get("message") or f"HTTP {resp.status_code}"
            return {
                "ok": False,
                "queued": background_queue,
                "message": f"Direct push failed ({msg}), command will be polled by agent.",
                "error": msg
            }

    except Exception as e:
        return {
            "ok": True,
            "queued": background_queue,
            "message": f"Agent unreachable, command queued for polling. ({e})",
            "warning": str(e)
        }

    except requests.Timeout:
        error = "Agent request timeout (>10s)"
        print(f"[!] {error} (agent={agent}, url={url})")
        return {"ok": False, "error": error, "status": "failed", "message": error}

    except requests.ConnectionError as e:
        error = f"Cannot connect to agent: {e}"
        print(f"[!] {error} (agent={agent}, url={url})")
        return {"ok": False, "error": error, "status": "failed", "message": error}

    except Exception as e:
        error = f"Agent SOAR call exception: {e}"
        print(f"[!] {error} (agent={agent}, url={url})")
        return {"ok": False, "error": error, "status": "failed", "message": error}

async def ensure_playbooks_table(agent: str):
    """<agent>_db.playbooks tablosu yoksa oluştur."""
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute("""
        CREATE TABLE IF NOT EXISTS playbooks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            agent_name VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL UNIQUE,
            description TEXT,
            nodes LONGTEXT NOT NULL,
            connections LONGTEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    try:
        await cur.execute("ALTER TABLE playbooks ADD COLUMN description TEXT AFTER name")
    except:
        pass
    try:
        await cur.execute("ALTER TABLE playbooks ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")
    except:
        pass
    
    await cnx.commit()
    await cur.close(); await cnx.close()


def _parse_json_field(val):
    """DB'den gelen nodes/connections alanını dict/list'e çevir (string ise)."""
    if isinstance(val, (dict, list)):
        return val
    try:
        return pyjson.loads(val) if isinstance(val, str) else val
    except Exception:
        return val


@require_permission("manage_soar")
@app.route("/<agent>/playbooks", methods=["GET"])
async def list_playbooks(request, agent):
    """
    Frontend: listeyi doldurmak için. 
    Artık nodes ve connections da dönüyor ki edit açıldığında kaybolmasın.
    """
    try:
        await ensure_playbooks_table(agent)
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        
        try:
            await cur.execute(
                "SELECT id, name, description, nodes, connections, created_at, updated_at FROM playbooks ORDER BY updated_at DESC"
            )
        except:
            await cur.execute(
                "SELECT id, name, '' as description, nodes, connections, created_at, created_at as updated_at FROM playbooks ORDER BY created_at DESC"
            )
        cols = [c[0] for c in cur.description]
        rows = await cur.fetchall()
        await cur.close(); await cnx.close()

        data = []
        for r in rows:
            pb = dict(zip(cols, r))
            pb["nodes"] = _parse_json_field(pb.get("nodes"))
            pb["connections"] = _parse_json_field(pb.get("connections"))
            data.append(pb)

        body = pyjson.dumps(data, cls=CustomEncoder, ensure_ascii=False)
        return HTTPResponse(body=body, content_type="application/json; charset=utf-8")
    except Exception as e:
        return sanic_json({"status": "error", "message": f"{e}"}, status=500)


@require_permission("manage_soar")
@app.route("/<agent>/playbooks/<playbook_id:int>", methods=["GET"])
async def get_playbook(request, agent, playbook_id):
    try:
        await ensure_playbooks_table(agent)
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "SELECT id, name, description, nodes, connections, created_at, updated_at FROM playbooks WHERE id=%s LIMIT 1",
            (int(playbook_id),)
        )
        row = await cur.fetchone()
        await cur.close(); await cnx.close()

        if not row:
            return sanic_json({"status": "error", "message": "Playbook not found"}, status=404)

        cols = ["id", "name", "description", "nodes", "connections", "created_at", "updated_at"]
        pb = dict(zip(cols, row))
        pb["nodes"] = _parse_json_field(pb["nodes"])
        pb["connections"] = _parse_json_field(pb["connections"])

        body = pyjson.dumps(pb, cls=CustomEncoder, ensure_ascii=False)
        return HTTPResponse(body=body, content_type="application/json; charset=utf-8")
    except Exception as e:
        return sanic_json({"status": "error", "message": f"{e}"}, status=500)


@require_permission("manage_soar")
@app.route("/<agent>/playbooks", methods=["POST"])
async def save_playbook(request, agent):
    try:
        await ensure_playbooks_table(agent)
        data = request.json or {}

        name = (data.get("name") or "").strip()
        description = data.get("description") or ""
        if not name:
            return sanic_json({"status": "error", "message": "name is required"}, status=400)

        nodes_json = pyjson.dumps(data.get("nodes") or [], ensure_ascii=False)
        conns_json = pyjson.dumps(data.get("connections") or [], ensure_ascii=False)

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()

        pid = data.get("id")
        if pid:
            await cur.execute(
                """
                UPDATE playbooks 
                SET name=%s, description=%s, nodes=%s, connections=%s, updated_at=NOW() 
                WHERE id=%s
                """,
                (name, description, nodes_json, conns_json, int(pid))
            )
            await cnx.commit()
            updated = cur.rowcount
            await cur.close(); await cnx.close()
            if updated == 0:
                return sanic_json({"status": "error", "message": "Playbook not found"}, status=404)
            return sanic_json({"status": "success", "id": int(pid), "mode": "updated"}, status=200)

        await cur.execute("SELECT id FROM playbooks WHERE name=%s LIMIT 1", (name,))
        row = await cur.fetchone()
        if row:
            pid = int(row[0])
            await cur.execute(
                """
                UPDATE playbooks 
                SET description=%s, nodes=%s, connections=%s, updated_at=NOW() 
                WHERE id=%s
                """,
                (description, nodes_json, conns_json, pid)
            )
            await cnx.commit()
            await cur.close(); await cnx.close()
            return sanic_json({"status": "success", "id": pid, "mode": "updated"}, status=200)
        else:
            await cur.execute(
                """
                INSERT INTO playbooks (agent_name, name, description, nodes, connections, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                """,
                (agent, name, description, nodes_json, conns_json)
            )
            pid = cur.lastrowid
            await cnx.commit()
            await cur.close(); await cnx.close()
            return sanic_json({"status": "success", "id": int(pid), "mode": "created"}, status=201)
    except Exception as e:
        return sanic_json({"status": "error", "message": f"{e}"}, status=500)




@require_permission("manage_soar")
@app.route("/<agent>/playbooks/<playbook_id:int>", methods=["PUT"])
async def update_playbook(request, agent, playbook_id):
    try:
        await ensure_playbooks_table(agent)
        payload = request.json or {}
        name = (payload.get("name") or "").strip()
        description = payload.get("description") or ""
        nodes_json = pyjson.dumps(payload.get("nodes") or [], ensure_ascii=False)
        conns_json = pyjson.dumps(payload.get("connections") or [], ensure_ascii=False)

        if not name:
            return sanic_json({"status": "error", "message": "name is required"}, status=400)

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            """
            UPDATE playbooks 
            SET name=%s, description=%s, nodes=%s, connections=%s, updated_at=NOW() 
            WHERE id=%s
            """,
            (name, description, nodes_json, conns_json, int(playbook_id))
        )
        await cnx.commit()
        await cur.close(); await cnx.close()
        return sanic_json({"status": "success", "message": "Updated"})
    except Exception as e:
        return sanic_json({"status": "error", "message": f"{e}"}, status=500)

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "UPDATE playbooks SET name=%s, nodes=%s, connections=%s, updated_at=NOW() WHERE id=%s",
            (name, nodes_json, conns_json, int(playbook_id))
        )
        await cnx.commit()
        changed = cur.rowcount
        await cur.close(); await cnx.close()

        if changed == 0:
            return sanic_json({"status": "error", "message": "Playbook not found"}, status=404)
        return sanic_json({"status": "success", "id": int(playbook_id)}, status=200)

    except Exception as e:
        return sanic_json({"status": "error", "message": f"{e}"}, status=500)


@require_permission("manage_soar")
@app.delete("/<agent>/playbooks/<playbook_id:int>")
async def delete_playbook(request, agent, playbook_id):
    """
    Delete a playbook by its ID.  Returns a JSON payload with status and
    number of deleted rows (0 or 1).
    """
    try:
        await ensure_playbooks_table(agent)
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "DELETE FROM playbooks WHERE id=%s",
            (int(playbook_id),)
        )
        await cnx.commit()
        deleted = cur.rowcount
        await cur.close(); await cnx.close()
        if not deleted:
            return sanic_json({"status": "error", "message": "playbook not found"}, status=404)
        return sanic_json({"status": "success", "deleted": int(playbook_id)})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)





def _palette_actions_enabled():
    return bool(is_soar_enabled())

def _node_schema(type_name, label, category, inputs=None, outputs=None, config_schema=None, disabled=False, help_text=""):
    return {
        "type": type_name,
        "label": label,
        "category": category,
        "disabled": bool(disabled),
        "inputs": inputs or [{"name": "in", "accept": "*"}],
        "outputs": outputs or [{"name": "out"}],
        "config_schema": config_schema or {},
        "help": help_text,
    }

def _build_node_palette():
    actions_enabled = _palette_actions_enabled()

    nodes = []

    nodes.append(_node_schema(
        "trigger",
        "Trigger (Generic)",
        "trigger",
        inputs=[],
        outputs=[{"name": "out"}],
        config_schema={
            "triggerType": {"type": "string", "placeholder": "manual"},
            "schedule": {"type": "string", "placeholder": ""},
            "webhook": {"type": "string", "placeholder": ""},
            "conditions": {"type": "array", "default": []}
        },
        help_text="Generic trigger placeholder. Use triggerType to specify the real trigger."
    ))
    nodes.append(_node_schema(
        "action",
        "Action (Generic)",
        "action",
        config_schema={
            "actionType": {"type": "string", "placeholder": "http_request"},
            "target": {"type": "string", "placeholder": ""},
            "comment": {"type": "string", "placeholder": ""},
            "ttl": {"type": "number", "default": 0},
            "params": {"type": "string", "placeholder": "{}"}
        },
        disabled=not actions_enabled,
        help_text="Generic action placeholder. actionType determines the SOAR action or HTTP request."
    ))

    nodes.append(_node_schema(
        "trigger.events_alert",
        "When Events Alert Arrives",
        "trigger",
        inputs=[],
        outputs=[{"name": "on_alert"}],
        config_schema={
            "source": {"type": "string", "required": False, "title": "Source contains"},
            "min_severity": {"type": "string", "enum": ["LOW","MEDIUM","HIGH","CRITICAL"], "default": "MEDIUM"},
        },
        help_text="events_alert tablosuna yeni kayıt düşünce tetikler (UI simülasyonunda filtreler).",
    ))

    nodes.append(_node_schema(
        "trigger.time",
        "Cron/Time Trigger",
        "trigger",
        inputs=[],
        outputs=[{"name": "tick"}],
        config_schema={"cron": {"type": "string", "placeholder": "*/5 * * * *"}},
        help_text="Zaman bazlı tetik (UI simülasyonu için).",
    ))

    nodes.append(_node_schema(
        "condition.severity_at_least",
        "Severity ≥",
        "condition",
        config_schema={"threshold": {"type": "string", "enum": ["LOW","MEDIUM","HIGH","CRITICAL"], "default": "HIGH"}},
        help_text="context.severity ile eşik karşılaştırır.",
    ))
    nodes.append(_node_schema(
        "condition.text_match",
        "Text contains",
        "condition",
        config_schema={"field": {"type": "string", "default": "message"}, "needle": {"type": "string"}},
        help_text="context[field] içinde needle arar.",
    ))

    nodes.append(_node_schema(
        "action.soar.block_ip",
        "SOAR: Block IP",
        "action",
        config_schema={"ip": {"type": "string", "placeholder": "{{event.ip}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> block_ip.",
    ))
    nodes.append(_node_schema(
        "action.soar.disable_user",
        "SOAR: Disable User",
        "action",
        config_schema={"username": {"type": "string", "placeholder": "{{event.username}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> disable_user.",
    ))

    nodes.append(_node_schema(
        "action.soar.unblock_ip",
        "SOAR: Unblock IP",
        "action",
        config_schema={"ip": {"type": "string", "placeholder": "{{event.ip}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> unblock_ip."
    ))
    nodes.append(_node_schema(
        "action.soar.enable_user",
        "SOAR: Enable User",
        "action",
        config_schema={"username": {"type": "string", "placeholder": "{{event.username}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> enable_user."
    ))
    nodes.append(_node_schema(
        "action.soar.kill_process",
        "SOAR: Kill Process",
        "action",
        config_schema={"pid": {"type": "string", "placeholder": "{{event.pid}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> kill_process."
    ))
    nodes.append(_node_schema(
        "action.soar.restart_service",
        "SOAR: Restart Service",
        "action",
        config_schema={"service": {"type": "string", "placeholder": "{{event.service}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> restart_service."
    ))
    nodes.append(_node_schema(
        "action.soar.lock_machine",
        "SOAR: Lock Machine",
        "action",
        config_schema={"machine": {"type": "string", "placeholder": "{{event.host}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> lock_machine."
    ))
    nodes.append(_node_schema(
        "action.soar.quarantine_file",
        "SOAR: Quarantine File",
        "action",
        config_schema={"filepath": {"type": "string", "placeholder": "/path/to/file"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> quarantine_file."
    ))
    nodes.append(_node_schema(
        "action.soar.tail_log",
        "SOAR: Tail Log",
        "action",
        config_schema={"logfile": {"type": "string", "placeholder": "/var/log/syslog"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> tail_log."
    ))
    nodes.append(_node_schema(
        "action.soar.run_cmd",
        "SOAR: Run Command",
        "action",
        config_schema={"command": {"type": "string", "placeholder": "uptime"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> run_cmd."
    ))

    nodes.append(_node_schema(
        "notify.email",
        "Send Email (template)",
        "notify",
        config_schema={
            "template_name": {"type": "string", "placeholder": "Critical Alerts - Agent: {{agent}}"},
            "context_json": {"type": "string", "placeholder": "{\"agent\":\"{{agent}}\",\"body\":\"...\"}"}
        },
        help_text="userdb.email_templates içinden şablonla mail atar.",
    ))

    nodes.append(_node_schema(
        "util.delay",
        "Delay",
        "util",
        config_schema={"ms": {"type": "number", "default": 1000}},
        help_text="Akışı N ms bekletir (icrada üst sınır 5sn).",
    ))

    return {"nodes": nodes, "soar_enabled": actions_enabled}

@app.get("/playbooks/palette")
async def get_node_palette(request):
    """UI paletini doldurur."""
    return sanic_json(_build_node_palette())

@app.get("/playbooks/examples")
async def get_playbook_examples(request):
    """UI'ya birkaç hazır örnek verelim."""
    examples = [
        {
            "name": "Critical Alert → Block IP → Email",
            "nodes": [
                {"id": "t1", "type": "trigger.events_alert", "config": {"min_severity": "CRITICAL"}},
                {"id": "c1", "type": "condition.severity_at_least", "config": {"threshold": "CRITICAL"}},
                {"id": "a1", "type": "action.soar.block_ip", "config": {"ip": "{{event.ip}}"}},
                {"id": "n1", "type": "notify.email", "config": {"template_name": "Critical Alerts - Agent: {{agent}}", "context_json": "{\"agent\":\"{{agent}}\",\"body\":\"Blocked {{event.ip}}\"}"}}
            ],
            "connections": [
                {"from": "t1", "to": "c1"},
                {"from": "c1", "to": "a1"},
                {"from": "a1", "to": "n1"}
            ]
        }
    ]
    return sanic_json({"examples": examples})

@app.post("/<agent>/playbooks/<playbook_id:int>/webhook")
async def playbook_webhook(request, agent, playbook_id):
    """
    This endpoint allows external systems to trigger a playbook via webhook.
    For now it acknowledges the call. In a real implementation this could look up
    the playbook, evaluate trigger conditions, and enqueue a run based on the
    provided event payload.
    """
    try:
        event = request.json or {}
        return sanic_json({"ok": True, "message": "Webhook received", "event": event})
    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)


def _validate_graph_payload(payload: dict):
    errs = []
    nodes = payload.get("nodes") or []
    conns = payload.get("connections") or []
    known_types = {n["type"] for n in _build_node_palette()["nodes"]}

    ids = set()
    for i, n in enumerate(nodes):
        nid = n.get("id")
        ntype = n.get("type")
        if not nid or not isinstance(nid, str):
            errs.append(f"nodes[{i}].id missing/invalid")
        elif nid in ids:
            errs.append(f"duplicate node id: {nid}")
        else:
            ids.add(nid)
        if not ntype or ntype not in known_types:
            errs.append(f"nodes[{i}].type unknown: {ntype}")

    for i, c in enumerate(conns):
        f = c.get("from"); t = c.get("to")
        if f not in ids or t not in ids:
            errs.append(f"connections[{i}] invalid endpoints: {f}->{t}")

    return errs



def _render_with_ctx(template_str: str, ctx: dict) -> str:
    try:
        return render_template(template_str, ctx)
    except Exception:
        return template_str

async def _ensure_playbook_runs_table(agent: str):
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute("""
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            agent_name    VARCHAR(255) NOT NULL,
            playbook_name VARCHAR(255) NOT NULL,
            status ENUM('running','success','failed','cancelled') NOT NULL DEFAULT 'running',
            started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP NULL,
            timeline   LONGTEXT NULL,
            last_error TEXT NULL,
            KEY idx_runs_agent_started (agent_name, started_at),
            KEY idx_runs_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    await cnx.commit()
    await cur.close(); await cnx.close()

async def _append_run_log(agent: str, run_id: int, timeline: list, status: str = None):
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    tjson = pyjson.dumps(timeline, ensure_ascii=False, cls=CustomEncoder)
    if status:
        await cur.execute(
            "UPDATE playbook_runs SET timeline=%s, status=%s, finished_at=NOW() WHERE id=%s",
            (tjson, status, run_id)
        )
    else:
        await cur.execute("UPDATE playbook_runs SET timeline=%s WHERE id=%s", (tjson, run_id))
    await cnx.commit()
    await cur.close(); await cnx.close()

def _sev_rank(v: str) -> int:
    order = {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    return order.get((v or "").upper(), 0)

def _eval_condition(ntype: str, config: dict, ctx: dict) -> bool:
    if ntype == "condition.severity_at_least":
        thr = (config or {}).get("threshold","HIGH")
        sev = (ctx.get("event") or {}).get("severity","LOW")
        return _sev_rank(sev) >= _sev_rank(thr)
    if ntype == "condition.text_match":
        field = (config or {}).get("field","message")
        needle = (config or {}).get("needle","")
        val = str(((ctx.get("event") or {}).get(field)) or "")
        return (needle or "") in val
    return True


@app.get("/<agent>/playbooks/catalog")
async def get_playbooks_catalog(request, agent):
    try:
        catalog = {
            "triggers": [
                {"key": "manual", "label": "Manual Trigger", "description": "Start manually"},
                {"key": "schedule", "label": "Scheduled (CRON)", "description": "Time-based trigger"},
                {"key": "webhook", "label": "Webhook", "description": "HTTP callback trigger"},
                {"key": "events_alert", "label": "Events Alert", "description": "Trigger on alert"}
            ],
                "actions": [
                     {"key": "http_request", "label": "HTTP Request", "description": "Make HTTP call"},
                     {"key": "block_ip", "label": "Block IP (SOAR)", "description": "Block IP address"},
                     {"key": "unblock_ip", "label": "Unblock IP (SOAR)", "description": "Unblock IP address"},
                     {"key": "disable_user", "label": "Disable User (SOAR)", "description": "Disable user account"},
                     {"key": "enable_user", "label": "Enable User (SOAR)", "description": "Enable user account"},
                     {"key": "kill_process", "label": "Kill Process (SOAR)", "description": "Kill a running process"},
                     {"key": "restart_service", "label": "Restart Service (SOAR)", "description": "Restart a system service"},
                     {"key": "lock_machine", "label": "Lock Machine (SOAR)", "description": "Lock the machine"},
                     {"key": "quarantine_file", "label": "Quarantine File (SOAR)", "description": "Quarantine a file"},
                     {"key": "tail_log", "label": "Tail Log (SOAR)", "description": "Tail system logs"},
                     {"key": "run_cmd", "label": "Run Command (SOAR)", "description": "Execute a shell command"}
                 ],
            "notifications": [
                {"key": "email", "label": "Email", "description": "Send email"},
                {"key": "slack", "label": "Slack", "description": "Send Slack message"},
                {"key": "teams", "label": "MS Teams", "description": "Send Teams notification"}
            ],
            "scripts": [
                {"key": "python", "label": "Python Script"},
                {"key": "bash", "label": "Bash Script"},
                {"key": "powershell", "label": "PowerShell Script"}
            ],
            "fields": []
        }
        
        return sanic_json(catalog)
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500) 
        
@app.get("/<agent>/notifications/templates")
async def get_email_templates(request, agent):
    """
    Notification node'ları için email template listesi.
    """
    try:
        cnx = await connect_userdb()
        cur = await cnx.cursor()
        await cur.execute("SELECT id, template_name as name FROM email_templates ORDER BY template_name")
        rows = await cur.fetchall()
        await cur.close()
        await cnx.close()
        
        templates = [{"id": row[0], "name": row[1]} for row in rows]
        return sanic_json(templates)
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)

@app.post("/<agent>/playbooks/validate")
async def validate_playbook(request, agent):
    try:
        data = request.json or {}
        nodes = data.get("nodes", [])
        connections = data.get("connections", [])
        
        issues = []
        
        triggers = [n for n in nodes if n.get("type") == "trigger"]
        if not triggers:
            issues.append({
                "type": "error",
                "message": "Workflow must have at least one trigger node"
            })
        
        node_ids = {n["id"] for n in nodes}
        connected = set()
        for c in connections:
            connected.add(c.get("from"))
            connected.add(c.get("to"))
        
        for node in nodes:
            nid = node["id"]
            if nid not in connected and node.get("type") != "trigger":
                issues.append({
                    "type": "warning",
                    "message": f"Node '{node.get('data', {}).get('name', nid)}' is not connected",
                    "nodeId": nid
                })
        
        for node in nodes:
            if node.get("type") == "script":
                cfg = node.get("data", {}).get("config", {})
                if not cfg.get("scriptContent", "").strip():
                    issues.append({
                        "type": "error",
                        "message": f"Script node '{node.get('data', {}).get('name', node['id'])}' has no script content",
                        "nodeId": node["id"]
                    })
        
        for node in nodes:
            if node.get("type") == "action":
                cfg = node.get("data", {}).get("config", {})
                action_type = cfg.get("actionType", "http_request")
                
                if action_type == "http_request" and not cfg.get("url"):
                    issues.append({
                        "type": "error",
                        "message": f"HTTP action '{node.get('data', {}).get('name', node['id'])}' requires URL",
                        "nodeId": node["id"]
                    })
                
                if action_type in ["block_ip", "disable_user"] and not cfg.get("target"):
                    issues.append({
                        "type": "error",
                        "message": f"SOAR action '{node.get('data', {}).get('name', node['id'])}' requires target",
                        "nodeId": node["id"]
                    })
        
        return sanic_json({"issues": issues})
    
    except Exception as e:
        return sanic_json({"error": str(e)}, status=500)


@app.post("/_proxy/http")
@require_permission("manage_system")
async def http_proxy(request):
    """Proxy a UI-originated HTTP request (works around CORS on third-party
    endpoints used by playbook nodes).

    Inert until `PROXY_ALLOWED_HOSTS` names destinations. Every request is
    checked by `security.ssrf.check_target` first — scheme, host allowlist,
    and the resolved address — and both the outbound and returned headers are
    filtered. See that module for the reasoning behind each layer.
    """
    data = request.json or {}
    url = data.get("url")

    method = (data.get("method") or "GET").upper()
    if method not in ssrf.ALLOWED_METHODS:
        return sanic_json({"error": f"Method not allowed: {method}"}, status=400)

    error = ssrf.check_target(url)
    if error:
        # Denials are audit-logged: a burst of them is somebody probing the
        # proxy, and that is worth being able to see after the fact.
        await audit_log(request, "PROXY_DENIED", str(url)[:255], error)
        return sanic_json({"error": error}, status=403)

    headers = ssrf.clean_request_headers(data.get("headers"))
    body = data.get("body")
    timeout = ssrf.clamp_timeout(data.get("timeout", 15))
    max_bytes = ssrf.max_response_bytes()

    await audit_log(request, "PROXY_REQUEST", str(url)[:255], f"{method} timeout={timeout}s")

    def _make_request():
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body if method not in ("GET", "HEAD") else None,
            timeout=timeout,
            # An allowlisted host answering 302 -> 169.254.169.254 would walk
            # straight past every check above, so hops are not followed. The
            # caller gets the redirect response and can re-submit the target,
            # which puts it back through validation.
            allow_redirects=False,
            stream=True,
        )

    try:
        resp = await asyncio.to_thread(_make_request)
    except requests.Timeout:
        return sanic_json({"error": "Request timeout"}, status=504)
    except Exception as e:
        return sanic_json({"error": str(e)}, status=502)

    try:
        # Read one byte past the cap so an oversized body is detectable
        # without buffering the whole thing. decode_content undoes any
        # transport compression, since the framing headers are dropped below.
        content = await asyncio.to_thread(resp.raw.read, max_bytes + 1, decode_content=True)
    except Exception as e:
        return sanic_json({"error": f"Failed reading response: {e}"}, status=502)
    finally:
        await asyncio.to_thread(resp.close)

    if len(content) > max_bytes:
        return sanic_json({"error": f"Response exceeds {max_bytes} bytes"}, status=502)

    return HTTPResponse(
        body=content,
        status=resp.status_code,
        headers=ssrf.clean_response_headers(resp.headers),
        content_type=resp.headers.get("Content-Type", "application/octet-stream"),
    )



@require_permission("manage_agent")
@app.post("/<agent>/playbooks/execute")
async def playbook_execute_real(request, agent):
    if not is_soar_enabled():
        return _soar_block_response()

    payload = request.json or {}
    errs = _validate_graph_payload(payload)
    if errs:
        return sanic_json({"ok": False, "errors": errs}, status=400)

    await _ensure_playbook_runs_table(agent)
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    pb_name = (payload.get("name") or "unnamed")[:255]
    await cur.execute(
        "INSERT INTO playbook_runs (agent_name, playbook_name) VALUES (%s, %s)",
        (agent, pb_name),
    )
    run_id = cur.lastrowid
    await cnx.commit()
    await cur.close(); await cnx.close()

    ctx = {
        "agent": agent,
        "event": payload.get("sample_event") or {"ip":"10.10.10.10","username":"alice","severity":"HIGH","message":"sample"},
    }

    timeline = []
    try:
        for n in payload.get("nodes", []):
            ntype = n["type"]
            conf  = n.get("config") or {}
            step  = {"node": n["id"], "type": ntype, "ok": True}

            if ntype.startswith("trigger."):
                step["info"] = "triggered"
                timeline.append(step); continue

            if ntype.startswith("condition."):
                res = _eval_condition(ntype, conf, ctx)
                step["result"] = bool(res)
                timeline.append(step)
                if not res:
                    pass
                continue

            if ntype == "util.delay":
                ms = int(conf.get("ms", 1000))
                ms = max(0, min(ms, 5000))
                await asyncio.sleep(ms/1000.0)
                step["result"] = f"waited {ms}ms"
                timeline.append(step); continue

            if ntype == "notify.email":
                tname = conf.get("template_name") or f"Critical Alerts - Agent: {agent}"
                ctx_str = conf.get("context_json") or "{}"
                try:
                    raw_ctx = pyjson.loads(_render_with_ctx(ctx_str, ctx)) if ctx_str.strip().startswith("{") else {"body": _render_with_ctx(ctx_str, ctx)}
                except Exception:
                    raw_ctx = {"body": _render_with_ctx(ctx_str, ctx)}
                ok = send_email(_render_with_ctx(tname, ctx), raw_ctx,
                                fallback=DEFAULT_ALERT_TEMPLATE)
                step["result"] = "sent" if ok else "failed"
                step["ok"] = bool(ok)
                timeline.append(step); continue

            if ntype == "action.soar.block_ip":
                ip = _render_with_ctx(str(conf.get("ip") or "{{event.ip}}"), ctx)
                r = await call_agent_soar(agent, action="block_ip", target=ip, comment=f"playbook#{run_id}:{pb_name}")
                step["agent_response"] = r
                step["ok"] = bool(r.get("ok"))
                timeline.append(step); continue

            if ntype == "action.soar.disable_user":
                username = _render_with_ctx(str(conf.get("username") or "{{event.username}}"), ctx)
                r = await call_agent_soar(agent, action="disable_user", target=username, comment=f"playbook#{run_id}:{pb_name}")
                step["agent_response"] = r
                step["ok"] = bool(r.get("ok"))
                timeline.append(step); continue

            if ntype.startswith("action.soar."):
                action_name = ntype.split(".")[-1]
                tgt_raw = (
                    conf.get("target") or
                    conf.get("username") or
                    conf.get("ip") or
                    conf.get("pid") or
                    conf.get("service") or
                    conf.get("machine") or
                    conf.get("filepath") or
                    conf.get("logfile") or
                    conf.get("command") or
                    ""
                )
                target_val = _render_with_ctx(str(tgt_raw), ctx)
                r = await call_agent_soar(agent, action=action_name, target=target_val, comment=f"playbook#{run_id}:{pb_name}")
                step["agent_response"] = r
                step["ok"] = bool(r.get("ok"))
                timeline.append(step); continue

            step["ok"] = False
            step["error"] = f"unknown node type: {ntype}"
            timeline.append(step)

        await _append_run_log(
            agent, run_id, timeline,
            status="success" if all(s.get("ok") for s in timeline) else "failed"
        )
        return sanic_json({"ok": True, "run_id": run_id, "timeline": timeline})

    except Exception as e:
        timeline.append({"node": None, "type": "runtime", "ok": False, "error": str(e)})
        await _append_run_log(agent, run_id, timeline, status="failed")
        return sanic_json({"ok": False, "run_id": run_id, "error": str(e), "timeline": timeline}, status=500)
    
@require_permission("manage_agent")
@app.get("/<agent>/playbooks/runs")
async def list_playbook_runs(request, agent):
    """
    Query params:
      - status: running|completed|failed
      - order: ASC|DESC (default DESC)
      - limit: int (default 50, max 1000)
    """
    q = request.args
    status = (q.get("status") or "").strip().lower()
    order = (q.get("order") or "DESC").strip().upper()
    if order not in ("ASC", "DESC"):
        order = "DESC"

    try:
        limit = int(q.get("limit", 50))
        limit = max(1, min(limit, 1000))
    except Exception:
        limit = 50

    where = []
    params = []

    if status:
        where.append("status = %s")
        params.append(status)

    await _ensure_playbook_runs_table(agent)
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()

    sql = "SELECT id, playbook_name, status, started_at, finished_at, last_error FROM playbook_runs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY id {order} LIMIT %s"
    params.append(limit)

    try:
        await cur.execute(sql, tuple(params))
    except Exception:
        await cur.close(); await cnx.close()
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        sql_fallback = "SELECT id, playbook_name, status, started_at, finished_at, NULL as last_error FROM playbook_runs"
        if where:
            sql_fallback += " WHERE " + " AND ".join(where)
        sql_fallback += f" ORDER BY id {order} LIMIT %s"
        await cur.execute(sql_fallback, tuple(params))
    cols = [c[0] for c in cur.description]
    rows = await cur.fetchall()
    await cur.close(); await cnx.close()

    data = [dict(zip(cols, r)) for r in rows]
    body = pyjson.dumps(data, ensure_ascii=False, cls=CustomEncoder)
    return HTTPResponse(body=body, content_type="application/json; charset=utf-8")


@require_permission("manage_agent")
@app.delete("/<agent>/playbooks/runs/<run_id:int>")
async def delete_playbook_run(request, agent, run_id):
    await _ensure_playbook_runs_table(agent)
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute("DELETE FROM playbook_runs WHERE id=%s", (int(run_id),))
    await cnx.commit()
    deleted = cur.rowcount
    await cur.close(); await cnx.close()

    if not deleted:
        return sanic_json({"status": "error", "message": "run not found"}, status=404)
    return sanic_json({"status": "success", "deleted": int(run_id)})

@require_permission("manage_agent")
@app.get("/<agent>/playbooks/runs/<run_id:int>/download")
async def download_playbook_run(request, agent, run_id):
    """
    Run detayını JSON dosyası olarak indir.
    """
    await _ensure_playbook_runs_table(agent)
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute(
        "SELECT id, playbook_name, status, started_at, finished_at, timeline FROM playbook_runs WHERE id=%s",
        (int(run_id),)
    )
    row = await cur.fetchone()
    await cur.close(); await cnx.close()

    if not row:
        return sanic_json({"status": "error", "message": "run not found"}, status=404)

    cols = ["id", "playbook_name", "status", "started_at", "finished_at", "timeline"]
    d = dict(zip(cols, row))

    tl = d.get("timeline")
    if isinstance(tl, (bytes, bytearray)):
        tl = tl.decode("utf-8", "ignore")
    if isinstance(tl, str):
        try:
            d["timeline"] = pyjson.loads(tl)
        except Exception:
            pass

    payload = pyjson.dumps(d, ensure_ascii=False, cls=CustomEncoder)
    filename = f"playbook_run_{run_id}.json"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    return HTTPResponse(body=payload, headers=headers)


@app.post("/<agent>/playbooks/<playbook_id:int>/run")
async def run_playbook(request, agent, playbook_id):
    if not is_soar_enabled():
        return _soar_block_response()

    import traceback as _tb
    import json as pyjson

    run_id = None
    timeline: list = []

    try:
        await ensure_playbooks_table(agent)
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute("SELECT nodes, connections, name FROM playbooks WHERE id=%s", (playbook_id,))
        row = await cur.fetchone()
        await cur.close(); await cnx.close()
        if not row:
            return sanic_json({"ok": False, "error": "playbook not found"}, status=404)

        raw_nodes = _parse_json_field(row[0])
        raw_conns = _parse_json_field(row[1])
        nodes = raw_nodes if isinstance(raw_nodes, list) else []
        conns = raw_conns if isinstance(raw_conns, list) else []
        pb_name = (row[2] or "unnamed")[:255]

        nexts: dict = {}
        for c in conns:
            if not isinstance(c, dict):
                continue
            f, t = c.get("from"), c.get("to")
            if f and t:
                nexts.setdefault(f, []).append(t)

        await _ensure_playbook_runs_table(agent)
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute(
            "INSERT INTO playbook_runs (agent_name, playbook_name, status, started_at) VALUES (%s, %s, 'running', NOW())",
            (agent, pb_name),
        )
        run_id = cur.lastrowid
        await cnx.commit()
        await cur.close(); await cnx.close()

        nid_map = {n["id"]: n for n in nodes if isinstance(n, dict) and "id" in n}
        visited = set()
        heads = set(nid_map.keys())
        for c in conns:
            if isinstance(c, dict):
                heads.discard(c.get("to"))
        queue = list(heads) if heads else (list(nid_map.keys())[:1])

        async def do_action(node):
            t = node.get("type", "")
            if t == "action":
                data = node.get("data") or {}
                action_name = data.get("action", "")
                params = data.get("params") or {}
                target_val = params.get("target") or (next(iter(params.values())) if params else "")
                target_for_call = _shape_soar_target(action_name, target_val)
                r = await call_agent_soar(agent, action_name, target_for_call, comment=f"playbook#{playbook_id}:{node['id']}")
                timeline.append({"node": node["id"], "type": action_name, "result": r})
                return

            cfg = node.get("config") or {}
            if t == "action.soar.block_ip":
                ip = str(cfg.get("ip", "")).strip()
                r = await call_agent_soar(agent, "block_ip", ip, comment=f"playbook#{playbook_id}:{node['id']}")
                timeline.append({"node": node["id"], "type": t, "result": r})
            elif t == "action.soar.disable_user":
                u = str(cfg.get("username", "")).strip()
                r = await call_agent_soar(agent, "disable_user", u, comment=f"playbook#{playbook_id}:{node['id']}")
                timeline.append({"node": node["id"], "type": t, "result": r})
            elif t.startswith("action.soar."):
                action_name = t.split(".")[-1]
                tgt_raw = (
                    cfg.get("target") or cfg.get("username") or cfg.get("ip") or
                    cfg.get("pid") or cfg.get("service") or cfg.get("machine") or
                    cfg.get("filepath") or cfg.get("logfile") or cfg.get("command") or ""
                )
                r = await call_agent_soar(agent, action_name, str(tgt_raw).strip(), comment=f"playbook#{playbook_id}:{node['id']}")
                timeline.append({"node": node["id"], "type": t, "result": r})
            else:
                timeline.append({"node": node["id"], "type": t, "result": "ok"})

        while queue:
            cur_id = queue.pop(0)
            if cur_id in visited or cur_id not in nid_map:
                continue
            visited.add(cur_id)
            try:
                await do_action(nid_map[cur_id])
            except Exception as node_err:
                timeline.append({
                    "node": cur_id,
                    "type": nid_map[cur_id].get("type", ""),
                    "result": {"ok": False, "error": str(node_err)},
                })
                print(f"[!] playbook node {cur_id} failed: {node_err}", flush=True)
            for nxt in nexts.get(cur_id, []):
                if nxt not in visited:
                    queue.append(nxt)

        def _step_ok(step):
            r = step.get("result")
            if isinstance(r, dict):
                return bool(r.get("ok"))
            return r == "ok" or r is True

        overall_status = "success" if (timeline and all(_step_ok(s) for s in timeline)) else "failed"
        last_err = None
        if overall_status == "failed":
            for s in timeline:
                r = s.get("result")
                if isinstance(r, dict) and not r.get("ok"):
                    last_err = r.get("error") or r.get("message")
                    if last_err:
                        break

        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        timeline_json = pyjson.dumps(timeline, ensure_ascii=False, cls=CustomEncoder)
        await cur.execute(
            "UPDATE playbook_runs SET status=%s, finished_at=NOW(), timeline=%s, last_error=%s WHERE id=%s",
            (overall_status, timeline_json, last_err, run_id),
        )
        await cnx.commit()
        await cur.close(); await cnx.close()

        return sanic_json({"ok": True, "run_id": run_id, "status": overall_status, "timeline": timeline})

    except Exception as e:
        err_msg = str(e)
        print(f"[!] run_playbook failed agent={agent} pb={playbook_id}: {err_msg}", flush=True)
        print(_tb.format_exc(), flush=True)
        if run_id is not None:
            try:
                cnx = await connect_db_for_agent(agent)
                cur = await cnx.cursor()
                tjson = pyjson.dumps(timeline + [{"error": err_msg}], ensure_ascii=False, cls=CustomEncoder)
                await cur.execute(
                    "UPDATE playbook_runs SET status='failed', finished_at=NOW(), timeline=%s WHERE id=%s",
                    (tjson, run_id),
                )
                await cnx.commit()
                await cur.close(); await cnx.close()
            except Exception as upd_err:
                print(f"[!] could not mark run {run_id} failed: {upd_err}", flush=True)
        return sanic_json({"ok": False, "error": err_msg, "run_id": run_id}, status=500)


@app.post("/<agent_name>/create_playbooks")
async def create_playbook_compat(request, agent_name):
    data = request.json or {}
    name = (data.get("name") or "").strip()
    nodes = data.get("nodes") or []
    connections = data.get("connections") or []

    if not name:
        return sanic_json({"status": "error", "message": "name is required"}, status=400)

    await ensure_playbooks_table(agent_name)

    nodes_json = pyjson.dumps(nodes, ensure_ascii=False)
    conns_json = pyjson.dumps(connections, ensure_ascii=False)

    try:
        cnx = await connect_db_for_agent(agent_name)
        cur = await cnx.cursor()

        await cur.execute("SELECT id FROM playbooks WHERE name=%s LIMIT 1", (name,))
        row = await cur.fetchone()
        if row:
            await cur.close(); await cnx.close()
            return sanic_json(
                {"status": "error", "message": "playbook already exists for this agent"},
                status=409,
            )

        await cur.execute(
            """
            INSERT INTO playbooks (name, nodes, connections, created_at, updated_at)
            VALUES (%s, %s, %s, NOW(), NOW())
            """,
            (name, nodes_json, conns_json),
        )
        new_id = cur.lastrowid
        await cnx.commit()
        await cur.close(); await cnx.close()

        return sanic_json(
            {
                "status": "ok",
                "id": int(new_id),
                "agent_name": agent_name,
                "mode": "created",
            }
        )
    except Exception as e:
        return sanic_json(
            {"status": "error", "message": f"DB error: {e}"},
            status=500,
        )



@app.post("/<agent>/playbooks/runs/clear")
async def clear_playbook_runs(request, agent):
    await _ensure_playbook_runs_table(agent)
    try:
        cnx = await connect_db_for_agent(agent)
        cur = await cnx.cursor()
        await cur.execute("TRUNCATE TABLE playbook_runs")
        await cnx.commit()
        await cur.close(); await cnx.close()
        return sanic_json({"status": "success", "message": "playbook_runs truncated"})
    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)



@require_permission("manage_agent")
@app.get("/<agent>/playbooks/runs/<run_id:int>")
async def get_playbook_run(request, agent, run_id):
    await _ensure_playbook_runs_table(agent)
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    await cur.execute(
        "SELECT id, playbook_name, status, started_at, finished_at, timeline FROM playbook_runs WHERE id=%s",
        (int(run_id),)
    )
    row = await cur.fetchone()
    await cur.close(); await cnx.close()

    if not row:
        return sanic_json({"status": "error", "message": "run not found"}, status=404)

    cols = ["id", "playbook_name", "status", "started_at", "finished_at", "timeline"]
    d = dict(zip(cols, row))

    tl = d.get("timeline")
    if isinstance(tl, (bytes, bytearray)):
        tl = tl.decode("utf-8", "ignore")
    if isinstance(tl, str):
        try:
            d["timeline"] = pyjson.loads(tl)
        except Exception:
            pass

    return sanic_json(d, dumps=lambda obj: pyjson.dumps(obj, ensure_ascii=False, cls=CustomEncoder))
  

@require_permission("manage_agent")
@require_permission("manage_soar")
@app.post("/<agent>/soar/execute")
async def soar_execute(request, agent):

    if not is_soar_enabled():
        return _soar_block_response()
    data = request.json or {}
    action  = (data.get("action") or "").strip()
    target  = (data.get("target") or "").strip()
    comment = (data.get("comment") or "").strip()
    event_id = data.get("event_id")
    ttl = data.get("ttl")

    if action not in AUTOMATION_ALLOWED_ACTIONS:
        return sanic_json({"ok": False, "error": f"action not allowed: {action}"}, status=400)

    if action == ActionType.BLOCK_IP.value and not _is_valid_ipv4(target):
        return sanic_json({"ok": False, "error": "invalid IPv4"}, status=400)
    if action == ActionType.DISABLE_USER.value and not _is_valid_username(target):
        return sanic_json({"ok": False, "error": "invalid username"}, status=400)

    try:
        res = await call_agent_soar(
            agent, action=action, target=target,
            comment=comment, event_id=event_id, ttl=ttl
        )
        return sanic_json(res, status=(200 if res.get("ok") else 502))
    except Exception as e:
        return sanic_json({"ok": False, "error": str(e)}, status=500)


@require_permission("manage_db")
@app.route("/databases/<db_name>", methods=["DELETE"])
async def drop_database(request, db_name):

    try:
        if not db_name:
            return sanic_json({"status": "error", "message": "db_name cannot be empty"}, status=400)

        raw = str(db_name)
        safe = re.sub(r"[^A-Za-z0-9_]", "_", raw).strip("_")
        if not safe:
            return sanic_json({"status": "error", "message": "Invalid db_name"}, status=400)

        candidates = {safe}
        if not safe.endswith("_db"):
            candidates.add(f"{safe}_db")

        def _drop():
            with sync_mysql_conn() as conn:
                cursor = conn.cursor()
                try:
                    for name in candidates:
                        sql = f"DROP DATABASE IF EXISTS `{name}`"
                        print(f"[*] Dropping candidate DB: {sql}")
                        cursor.execute(sql)
                    conn.commit()
                finally:
                    cursor.close()
        await asyncio.to_thread(_drop)

        await audit_log(request, "DROP_DATABASE", db_name, f"Databases dropped: {', '.join(candidates)}")

        return sanic_json(
            {
                "status": "success",
                "message": "Databases dropped (if existed).",
                "dropped_candidates": list(candidates),
            }
        )

    except Exception as e:
        return sanic_json({"status": "error", "message": str(e)}, status=500)



@app.websocket("/vnc-proxy/<agent>")
@require_permission("read_telemetry")
async def vnc_proxy(request, ws, agent):
    """Browser ↔ agent VNC/screen relay.

    Registered at module scope (was previously nested under `if __name__ ==
    "__main__":`) so it survives Sanic worker subprocesses and any embedding
    that imports app.py instead of running it as the main script.
    """
    import websockets

    fps = request.args.get("fps", "10")
    q = request.args.get("q", "60")
    w = request.args.get("w", "1280")

    try:
        base = await _get_agent_http_base(agent)
        keys = await _get_agent_keys(agent)
    except Exception as e:
        print(f"[screen-proxy] resolve {agent} failed: {e}", flush=True)
        try:
            await ws.send(pyjson.dumps({"error": "agent_lookup_failed", "detail": str(e)}))
        except Exception:
            pass
        await ws.close()
        return

    agent_key = (keys[0] if keys else "")
    target = (base or "").replace("http://", "ws://").replace("https://", "wss://").rstrip("/")
    if not target:
        try:
            await ws.send(pyjson.dumps({"error": "agent_unreachable", "detail": "no base url for agent"}))
        except Exception:
            pass
        await ws.close()
        return

    target_url = f"{target}/screen/ws?key={agent_key}&fps={fps}&q={q}&w={w}"
    headers = {"X-Agent-Key": agent_key} if agent_key else None

    try:
        async with websockets.connect(
            target_url,
            max_size=20 * 1024 * 1024,
            additional_headers=headers,
            open_timeout=10,
            ping_interval=20,
            ping_timeout=20,
        ) as upstream:
            async def browser_to_agent():
                try:
                    while True:
                        data = await ws.recv()
                        if data is None:
                            break
                        await upstream.send(data)
                except Exception:
                    pass

            async def agent_to_browser():
                try:
                    async for data in upstream:
                        await ws.send(data)
                except Exception:
                    pass

            await asyncio.gather(browser_to_agent(), agent_to_browser())
    except TypeError:
        try:
            async with websockets.connect(
                target_url,
                max_size=20 * 1024 * 1024,
                extra_headers=headers,
                open_timeout=10,
            ) as upstream:
                async def b2a():
                    try:
                        while True:
                            data = await ws.recv()
                            if data is None:
                                break
                            await upstream.send(data)
                    except Exception:
                        pass

                async def a2b():
                    try:
                        async for data in upstream:
                            await ws.send(data)
                    except Exception:
                        pass

                await asyncio.gather(b2a(), a2b())
        except Exception as e:
            print(f"[screen-proxy] legacy connect failed → {target_url}: {e}", flush=True)
            try:
                await ws.send(pyjson.dumps({"error": "agent_unreachable", "detail": str(e)}))
            except Exception:
                pass
            await ws.close()
    except Exception as e:
        print(f"[screen-proxy] connect failed → {target_url}: {e}", flush=True)
        try:
            await ws.send(pyjson.dumps({"error": "agent_unreachable", "detail": str(e)}))
        except Exception:
            pass
        await ws.close()


if __name__ == "__main__":
    tls_enabled = os.getenv("TLS_ENABLED", "0").lower() in ("1", "true", "yes")
    cert_path = os.getenv("TLS_CERT", os.path.join("certs", "server.crt"))
    key_path = os.getenv("TLS_KEY", os.path.join("certs", "server.key"))

    ssl_config = None
    if tls_enabled:
        try:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_config = {"cert": cert_path, "key": key_path}
                print(f"[i] TLS enabled with cert={cert_path} key={key_path}")
            else:
                print(f"[!] TLS files not found: {cert_path} or {key_path}. Falling back to HTTP.")
        except Exception as e:
            print(f"[!] TLS setup error: {e}. Falling back to HTTP.")

    default_port = "8000"
    port = int(os.getenv("PORT", default_port))

    import multiprocessing
    multiprocessing.freeze_support()

@app.route("/", name="frontend_root")
async def serve_root(request):
    return await response.file("./frontend/dist/index.html")

@require_permission("read_telemetry")
@app.route("/api/logs/search")
async def search_logs_api(request):
    agent = request.args.get("agent", "*")
    table = request.args.get("table", "*")
    query_str = request.args.get("q", "*")
    limit = int(request.args.get("limit", 100))
    
    if query_str == "*":
        query_body = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"agent_name": agent}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    else:
        query_body = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"agent_name": agent}},
                        {"multi_match": {"query": query_str, "fields": ["*"]}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    index_mask = f"sentora-logs-{table.replace('_', '-')}" if table != "*" else "sentora-logs-*"
    
    resp = os_utils.search_logs(query_body, index_mask=index_mask)
    if not resp:
        return sanic_json({"hits": []})
        
    hits = [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
    return sanic_json({"hits": hits, "total": resp.get("hits", {}).get("total", {}).get("value", 0)})

@app.route("/<path:path>", name="frontend_spa")
async def serve_index(request, path=""):
    if path.startswith(("api/", "health", "assets/", "vite.svg")):
         return sanic_json({"error": "Not Found", "path": path}, status=404)
         
    return await response.file("./frontend/dist/index.html")

@app.route("/health")
async def health_check(request):
    return sanic_json({"status": "healthy", "timestamp": datetime.now().isoformat()})

if __name__ == "__main__":
    app.config.AUTO_RELOAD = False
    app.config.TOUCHUP = False
    app.config.ACCESS_LOG = True
    
    num_workers = multiprocessing.cpu_count() if os.name != 'nt' else 1
    
    app.run(
        host="0.0.0.0",
        port=8000,
        single_process=(num_workers == 1),
        workers=num_workers,
        access_log=True,
        auto_reload=False
    )
