import os
import re
import json
import requests
import mysql.connector
import hashlib
from contextlib import contextmanager
from datetime import datetime

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "my-secret-pw")
USERDB_NAME = os.getenv("USERDB_NAME", "userdb")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434/api")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


def _agent_db(agent: str) -> str:
    """Map an agent identifier to its MySQL database name.

    Windows hostnames contain '-' (e.g. DESKTOP-EVS8H9J) which is not a valid
    MySQL identifier character. The ingest path (`server.py:_sanitize_db_name`)
    replaces non-[A-Za-z0-9_] with `_` when CREATING the database, so the worker
    MUST use the same mapping when READING/WRITING — otherwise we end up
    asking MySQL for `DESKTOP-EVS8H9J_db` while the actual DB is
    `DESKTOP_EVS8H9J_db` and every save_ai_results raises "Unknown database".
    """
    safe = re.sub(r'[^A-Za-z0-9_]', '_', agent or 'agent')
    safe = safe.strip('_') or 'agent'
    return f"{safe}_db"


@contextmanager
def _conn(db_name: str):
    """Sync MySQL connection with guaranteed close on exception."""
    c = mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=db_name
    )
    try:
        yield c
    finally:
        try:
            c.close()
        except Exception:
            pass

async def load_ai_config(agent: str):
    """Load AI configuration. ai_config lives in userdb (global, not per-agent)."""
    default_config = {
        'model_name': OLLAMA_MODEL,
        'endpoint': OLLAMA_BASE_URL,
        'api_key': 'ollama',
    }
    try:
        with _conn(USERDB_NAME) as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(
                    "SELECT model_name, endpoint, api_key FROM ai_config "
                    "ORDER BY updated_at DESC LIMIT 1"
                )
                row = cursor.fetchone()
            finally:
                cursor.close()
        if not row:
            return default_config
        if not row.get('model_name'):
            row['model_name'] = OLLAMA_MODEL
        if not row.get('endpoint'):
            row['endpoint'] = OLLAMA_BASE_URL
        if not row.get('api_key'):
            row['api_key'] = 'ollama'
        return row
    except Exception as e:
        print(f"[!] load_ai_config: falling back to defaults ({e})", flush=True)
        return default_config

def _normalize_ollama_url(endpoint: str) -> str:
    """Build the /generate URL no matter what the user typed in the config.
    Accepts: http://host:11434, http://host:11434/, http://host:11434/api,
    http://host:11434/api/, http://host:11434/api/generate, .../v1/...
    """
    if not endpoint:
        endpoint = OLLAMA_BASE_URL
    url = endpoint.strip().rstrip('/')
    if url.endswith('/generate'):
        return url
    if url.endswith('/api'):
        return f"{url}/generate"
    return f"{url}/api/generate"


def analyze_with_ai(api_key, text, prompt_template, endpoint=None, agent=None, model=None):
    """Generic AI analysis function for different worker types.

    `model` overrides the global OLLAMA_MODEL when supplied so the model
    configured in `ai_config` is actually used by the worker.
    """
    target_url = _normalize_ollama_url(endpoint)
    model_name = (model or OLLAMA_MODEL or '').strip() or OLLAMA_MODEL

    prompt = prompt_template.format(log_text=text)
    prompt_hash = hashlib.md5(f"{model_name}|{prompt}".encode()).hexdigest()

    if agent:
        cached = get_ai_cache(agent, prompt_hash)
        if cached:
            return cached

    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
    }

    try:
        resp = requests.post(target_url, json=payload, timeout=600)
        if resp.status_code == 200:
            ai_resp = resp.json().get('response', '').strip()
            if agent and ai_resp:
                set_ai_cache(agent, prompt_hash, ai_resp)
            return ai_resp
        if resp.status_code == 404:
            body = (resp.text or '').lower()
            if 'model' in body and ('not found' in body or 'not exist' in body or 'pull' in body):
                return (
                    f"Error: AI model '{model_name}' is not installed on the Ollama "
                    f"server at {target_url}. Run `ollama pull {model_name}` "
                    f"or change the model in AI Config."
                )
            return (
                f"Error: AI endpoint not found at {target_url} (HTTP 404). "
                f"Check OLLAMA_BASE_URL / AI Config endpoint value."
            )
        return f"Error: AI service returned {resp.status_code}"
    except Exception as e:
        return f"Error connecting to AI service: {str(e)}"

def get_ai_cache(agent: str, prompt_hash: str):
    """Retrieve cached AI result if available"""
    db_name = _agent_db(agent)
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT response FROM ai_cache WHERE prompt_hash = %s", (prompt_hash,))
                row = cursor.fetchone()
            finally:
                cursor.close()
        return row[0] if row else None
    except Exception:
        return None

def set_ai_cache(agent: str, prompt_hash: str, response: str):
    """Store AI result in cache"""
    db_name = _agent_db(agent)
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_cache (
                        prompt_hash CHAR(32) PRIMARY KEY,
                        response TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute(
                    "INSERT INTO ai_cache (prompt_hash, response) VALUES (%s, %s) ON DUPLICATE KEY UPDATE response=VALUES(response)",
                    (prompt_hash, response),
                )
                conn.commit()
            finally:
                cursor.close()
    except Exception:
        pass

def is_critical_log(api_key, log_text, endpoint=None, agent=None):
    """Analyze log text using Ollama AI to determine if it's critical"""
    prompt_template = """
    Analyze the following security logs and determine if there is any critical threat or suspicious activity.
    If it is critical, provide a short summary. If not critical, say 'No critical logs.'
    
    LOGS:
    {log_text}
    
    RESPONSE FORMAT:
    Summary: [Summary of the threat] OR 'No critical logs.'
    """
    
    result = analyze_with_ai(api_key, log_text, prompt_template, endpoint, agent=agent)
    if "No critical logs." in result:
        return "No critical logs."
    return result.replace("Summary:", "").strip()

def queue_soar_action(agent: str, action: str, target: str, comment: str = "") -> bool:
    """Queue an autonomous SOAR action by inserting into the agent's `automations`
    table. The agent polls this table and executes pending rows, so this is the
    safest way for the defensive AI worker to trigger a real response without
    touching app.py's HTTP layer.
    """
    db_name = _agent_db(agent)
    if not action or not target:
        return False
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    INSERT INTO automations
                        (device, event_id, action, target, comment, status, `timestamp`, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, 'pending', NOW(), NOW(), NOW())
                    """,
                    (agent, 0, action, target, comment or "AI defensive auto-action"),
                )
                conn.commit()
            finally:
                cursor.close()
        return True
    except Exception as e:
        print(f"[!] queue_soar_action failed agent={agent} action={action}: {e}", flush=True)
        return False


def save_ai_results(agent: str, results: list):
    """Save AI analysis results to the database. Raises on DB failure so the
    caller's logger surfaces the problem instead of silently dropping insights.
    `source_data` (raw log text fed to the model) is optional but recommended so
    the UI can show "what did the AI actually look at" for each insight.
    """
    db_name = _agent_db(agent)
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_analysis_results (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp DATETIME,
                        source_file VARCHAR(255),
                        critical_summary TEXT,
                        source_data LONGTEXT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                try:
                    cursor.execute("ALTER TABLE ai_analysis_results ADD COLUMN source_data LONGTEXT NULL")
                except Exception:
                    pass
                for res in results:
                    cursor.execute("""
                        INSERT INTO ai_analysis_results (timestamp, source_file, critical_summary, source_data)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        res['timestamp'],
                        res['source_file'],
                        res['critical_summary'],
                        res.get('source_data'),
                    ))
                conn.commit()
            finally:
                cursor.close()
        return len(results)
    except Exception as e:
        print(f"[!] Error saving AI results for {agent}: {e}", flush=True)
        raise
