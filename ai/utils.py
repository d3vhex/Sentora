import os
import re
import time
import requests
import mysql.connector
import hashlib
from contextlib import contextmanager

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


# Bump when a prompt template changes. It is part of the cache key, so a
# reworded prompt cannot keep serving verdicts produced by the old one — the
# previous cache had no such notion and a stale answer lived forever.
# v2: the triage prompt was rewritten and the schema field order changed.
# v3: `observed` added, and the criteria rewritten as literal evidence rather
#     than technique descriptions - v2 copied its own criterion text into the
#     summary and escalated an EID 4672 SYSTEM logon as credential dumping.
# Each of these changes what the model answers, so cached verdicts from an
# earlier version answer a different question and must not be reused.
PROMPT_VERSION = os.getenv("AI_PROMPT_VERSION", "v3")

# Observed: llama3.2:3b on CPU takes ~47s for a single 2 KB event. The manual
# worker batches ten events into one prompt, so its prompts are an order of
# magnitude larger and 120s was not enough — every batch timed out.
#
# 600s was the original value and that was a hang, not a timeout. 300 is the
# compromise: long enough for a batched prompt on CPU, short enough that a
# genuinely stuck request frees the slot within a few minutes. Transient
# failures are requeued rather than recorded, so an occasional overrun costs
# a retry, not a lost event.
AI_TIMEOUT_SEC = int(os.getenv("AI_TIMEOUT_SEC", "300"))


def analyze_with_ai(api_key, text, prompt_template, endpoint=None, agent=None, model=None):
    """Generic AI analysis function for different worker types.

    `model` overrides the global OLLAMA_MODEL when supplied so the model
    configured in `ai_config` is actually used by the worker.
    """
    target_url = _normalize_ollama_url(endpoint)
    model_name = (model or OLLAMA_MODEL or '').strip() or OLLAMA_MODEL

    prompt = prompt_template.format(log_text=text)
    # Keyed on the exact prompt, deliberately. Normalising the log text to
    # raise the hit rate would let one event answer for a different one, and
    # in a triage pipeline a wrong cache hit is a missed detection. Dedup of
    # similar events belongs upstream, where server.py already fingerprints
    # them before publishing.
    prompt_hash = hashlib.sha256(
        f"{PROMPT_VERSION}|{model_name}|{prompt}".encode()
    ).hexdigest()

    if agent:
        cached = get_ai_cache(agent, prompt_hash)
        if cached:
            return cached

    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
    }

    started = time.monotonic()
    try:
        resp = requests.post(target_url, json=payload, timeout=AI_TIMEOUT_SEC)
        elapsed = time.monotonic() - started
        if resp.status_code == 200:
            ai_resp = resp.json().get('response', '').strip()
            # Latency was invisible, so there was no way to tell a slow model
            # from a stuck one, or to know whether raising concurrency helped.
            print(f"[ai] {model_name} responded in {elapsed:.1f}s "
                  f"({len(prompt)} char prompt, {len(ai_resp)} char reply)", flush=True)
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
    except requests.Timeout:
        elapsed = time.monotonic() - started
        print(f"[ai] {model_name} timed out after {elapsed:.0f}s "
              f"(AI_TIMEOUT_SEC={AI_TIMEOUT_SEC})", flush=True)
        return f"Error: AI service timed out after {AI_TIMEOUT_SEC}s"
    except Exception as e:
        return f"Error connecting to AI service: {str(e)}"


# Cached verdicts expire. Without this a single bad answer was served forever:
# the old cache had no TTL and no prompt version, so the only way to clear one
# was to drop the table by hand.
AI_CACHE_TTL_HOURS = int(os.getenv("AI_CACHE_TTL_HOURS", "24"))


class AITransientError(Exception):
    """The model could not be reached or ran out of time.

    Distinct from a bad verdict on purpose. A timeout says nothing about the
    event — it says the inference did not happen — so it must not become an
    insight row. The worker requeues these instead, and the operator sees the
    problem in the worker log rather than as a wall of
    "did not return a usable verdict" cards in the UI.
    """


def analyze_structured(prompt_template, text, schema_model, *,
                       endpoint=None, agent=None, model=None, api_key=None):
    """Ask the model for a verdict and get back a validated object.

    Returns `(verdict, raw, error)`. Exactly one of `verdict` / `error` is set.

    Raises `AITransientError` when the model could not be reached at all —
    that is not a verdict and the caller should requeue rather than record it.

    Two things separate this from analyze_with_ai:

    1. The JSON schema is passed to Ollama's `format` parameter, so the model
       is constrained to the shape rather than asked for it in the prompt and
       parsed hopefully afterwards. That removes the failure mode where a
       missing brace loses a whole verdict.
    2. The result is validated with Pydantic. On failure there is exactly one
       repair attempt, and if that also fails the caller gets an error to
       record honestly — not a fabricated narrative.

    Requires Ollama 0.5+ for schema-constrained output. Older versions ignore
    an unknown `format` value and return prose, which then fails validation
    and surfaces as a parse error rather than silently wrong data.
    """
    from ai.schemas import constrained_schema

    target_url = _normalize_ollama_url(endpoint)
    model_name = (model or OLLAMA_MODEL or '').strip() or OLLAMA_MODEL
    prompt = prompt_template.format(log_text=text)
    # Every field marked required — otherwise the model omits the ones with
    # defaults and every verdict comes back INFO / 0.00.
    schema = constrained_schema(schema_model)

    prompt_hash = hashlib.sha256(
        f"{PROMPT_VERSION}|{model_name}|structured|{prompt}".encode()
    ).hexdigest()

    if agent:
        cached = get_ai_cache(agent, prompt_hash)
        if cached:
            try:
                return schema_model.model_validate_json(cached), cached, None
            except Exception:
                pass  # cached value predates a schema change; re-ask

    def _call(extra_instruction: str = "") -> tuple[str, float]:
        payload = {
            "model": model_name,
            "prompt": prompt + extra_instruction,
            "stream": False,
            "format": schema,
            # Triage wants the same answer for the same evidence. Sampling
            # variance here shows up as an event being CRITICAL on one run and
            # benign on the next, which is impossible to tune against.
            "options": {"temperature": 0},
        }
        started = time.monotonic()
        resp = requests.post(target_url, json=payload, timeout=AI_TIMEOUT_SEC)
        elapsed = time.monotonic() - started
        if resp.status_code != 200:
            raise RuntimeError(f"AI service returned {resp.status_code}: {(resp.text or '')[:200]}")
        return (resp.json().get("response") or "").strip(), elapsed

    raw = ""
    try:
        raw, elapsed = _call()
        print(f"[ai] {model_name} structured reply in {elapsed:.1f}s "
              f"({len(prompt)} char prompt)", flush=True)
        verdict = schema_model.model_validate_json(raw)
    except (requests.Timeout, requests.ConnectionError) as e:
        # Transient: the model is slow or Ollama is restarting. The caller
        # requeues rather than recording a verdict — see AITransientError.
        raise AITransientError(f"{type(e).__name__}: {e}") from e
    except Exception as first_error:
        # One repair attempt. More than one is throwing good money after bad:
        # a model that cannot produce the schema twice will not manage it on
        # the third try, and the queue is waiting.
        try:
            raw, _ = _call(
                "\n\nYour previous reply did not match the required JSON schema. "
                "Reply with ONLY the JSON object, no prose and no markdown fences."
            )
            verdict = schema_model.model_validate_json(raw)
            print(f"[ai] {model_name} needed a repair round", flush=True)
        except Exception as second_error:
            return None, raw, f"{first_error} (repair also failed: {second_error})"

    if agent and raw:
        set_ai_cache(agent, prompt_hash, verdict.model_dump_json())
    return verdict, raw, None


def get_ai_cache(agent: str, prompt_hash: str):
    """Return a cached response, or None when absent or expired."""
    db_name = _agent_db(agent)
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT response FROM ai_cache "
                    "WHERE prompt_hash = %s "
                    "AND created_at > (NOW() - INTERVAL %s HOUR)",
                    (prompt_hash, AI_CACHE_TTL_HOURS),
                )
                row = cursor.fetchone()
            finally:
                cursor.close()
        return row[0] if row else None
    except Exception:
        return None


def purge_ai_cache(agent: str) -> int:
    """Drop expired rows. Called opportunistically on write."""
    db_name = _agent_db(agent)
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "DELETE FROM ai_cache WHERE created_at < (NOW() - INTERVAL %s HOUR)",
                    (AI_CACHE_TTL_HOURS,),
                )
                removed = cursor.rowcount or 0
                conn.commit()
            finally:
                cursor.close()
        return removed
    except Exception:
        return 0

# Purging on every write would be a DELETE per inference. Once every N writes
# keeps the table bounded without that cost.
_PURGE_EVERY = 50
_writes_since_purge = 0


def set_ai_cache(agent: str, prompt_hash: str, response: str):
    """Store an AI result.

    The key widened from CHAR(32) (MD5) to CHAR(64) (SHA-256) and now carries
    the prompt version, so the ALTER below migrates tables created by an older
    worker. Without it every write would fail on a truncated key and the cache
    would silently stop working.
    """
    global _writes_since_purge
    db_name = _agent_db(agent)
    try:
        with _conn(db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_cache (
                        prompt_hash CHAR(64) PRIMARY KEY,
                        response TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_created (created_at)
                    )
                """)
                for ddl in (
                    "ALTER TABLE ai_cache MODIFY COLUMN prompt_hash CHAR(64) NOT NULL",
                    "ALTER TABLE ai_cache ADD INDEX idx_created (created_at)",
                ):
                    try:
                        cursor.execute(ddl)
                    except Exception:
                        pass  # already migrated
                cursor.execute(
                    "INSERT INTO ai_cache (prompt_hash, response) VALUES (%s, %s) "
                    "ON DUPLICATE KEY UPDATE response=VALUES(response), created_at=NOW()",
                    (prompt_hash, response),
                )
                conn.commit()
            finally:
                cursor.close()
    except Exception:
        return

    _writes_since_purge += 1
    if _writes_since_purge >= _PURGE_EVERY:
        _writes_since_purge = 0
        purge_ai_cache(agent)

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
                        proposed_action VARCHAR(64) NULL,
                        proposed_target VARCHAR(512) NULL,
                        shadow_status VARCHAR(16) NULL,
                        shadow_decided_at DATETIME NULL,
                        shadow_decided_by VARCHAR(128) NULL,
                        verdict VARCHAR(24) NULL,
                        severity VARCHAR(16) NULL,
                        confidence DECIMAL(4,3) NULL,
                        model VARCHAR(64) NULL,
                        prompt_version VARCHAR(16) NULL,
                        payload JSON NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_air_verdict (verdict),
                        INDEX idx_air_created (created_at)
                    )
                """)
                # Backfill columns for tables created by an older worker so
                # we don't blow up on INSERT when newer fields are pushed.
                #
                # verdict/severity/confidence are the point of this set: they
                # used to exist only inside the rendered `critical_summary`
                # string, so the UI parsed them back out with a regex and no
                # query could filter on them.
                for ddl in (
                    "ALTER TABLE ai_analysis_results ADD COLUMN source_data LONGTEXT NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN proposed_action VARCHAR(64) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN proposed_target VARCHAR(512) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN shadow_status VARCHAR(16) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN shadow_decided_at DATETIME NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN shadow_decided_by VARCHAR(128) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN verdict VARCHAR(24) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN severity VARCHAR(16) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN confidence DECIMAL(4,3) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN model VARCHAR(64) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN prompt_version VARCHAR(16) NULL",
                    "ALTER TABLE ai_analysis_results ADD COLUMN payload JSON NULL",
                    # Links a verdict back to the ai_dedup counter, so repeats
                    # of the same event attach to this insight instead of
                    # producing another inference.
                    "ALTER TABLE ai_analysis_results ADD COLUMN fingerprint CHAR(64) NULL",
                    "ALTER TABLE ai_analysis_results ADD INDEX idx_air_fp (fingerprint)",
                    "ALTER TABLE ai_analysis_results ADD INDEX idx_air_verdict (verdict)",
                    "ALTER TABLE ai_analysis_results ADD INDEX idx_air_created (created_at)",
                ):
                    try:
                        cursor.execute(ddl)
                    except Exception:
                        pass
                for res in results:
                    cursor.execute(
                        """
                        INSERT INTO ai_analysis_results
                            (timestamp, source_file, critical_summary, source_data,
                             proposed_action, proposed_target, shadow_status,
                             verdict, severity, confidence, model, prompt_version,
                             payload, fingerprint)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            res['timestamp'],
                            res['source_file'],
                            res['critical_summary'],
                            res.get('source_data'),
                            res.get('proposed_action'),
                            res.get('proposed_target'),
                            res.get('shadow_status'),
                            res.get('verdict'),
                            res.get('severity'),
                            res.get('confidence'),
                            res.get('model'),
                            res.get('prompt_version', PROMPT_VERSION),
                            res.get('payload'),
                            res.get('fingerprint'),
                        ),
                    )
                conn.commit()
            finally:
                cursor.close()
        return len(results)
    except Exception as e:
        print(f"[!] Error saving AI results for {agent}: {e}", flush=True)
        raise
