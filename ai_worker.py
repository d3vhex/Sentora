import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "Sentora"))

import asyncio
import json
import re
import time
import logging
import aio_pika
import os
from datetime import datetime
from ai.utils import (
    AITransientError,
    analyze_structured,
    load_ai_config,
    queue_soar_action,
    save_ai_results,
)
from ai.schemas import TriageVerdict, DeepAnalysis, DefensiveDecision, render_summary
from ai.intel import get_threat_intel_summary
from core import mq as mq_utils

from modules.soar.soar import SOARAutomation, SOARConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AI-Worker")

WORKER_TYPE = os.getenv("WORKER_TYPE", "automation").lower()
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")

CRITICAL_CONFIDENCE_THRESHOLD = float(os.getenv("AI_CRIT_CONF", "0.6"))
SUSPICIOUS_CONFIDENCE_THRESHOLD = float(os.getenv("AI_SUS_CONF", "0.75"))

PROMPTS = {
    "automation": """You are a senior SOC analyst triaging telemetry. Be strict. Most logs are benign noise (routine logons, service checks, dev activity). Only escalate when a SPECIFIC, CONCRETE indicator of attack is present in the log.

A finding is CRITICAL only if AT LEAST ONE is clearly evidenced in the log:
- Confirmed credential theft / dumping (LSASS access, mimikatz, registry SAM)
- Active lateral movement with sensitive accounts (psexec, wmic /node, RDP from unusual host)
- Known-bad indicator hit (malware family, C2 IP/domain, ransomware extension)
- Privilege escalation attempt (token impersonation, UAC bypass, SeDebugPrivilege abuse)
- Data exfiltration (large outbound transfer, archive uploaded to external host)
- Adversary persistence (suspicious scheduled task, registry Run key, service install)

Default to NOT_CRITICAL. Do NOT flag generic warnings, single failed logon, normal admin actions, missing optional fields, or benign event IDs. If unsure, choose NOT_CRITICAL.

Return ONLY a single JSON object, no prose, no markdown fences:
{{"verdict":"CRITICAL|SUSPICIOUS|NOT_CRITICAL","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","confidence":<0.0-1.0>,"indicator":"<MITRE ID + short label or 'none'>","summary":"<one sentence, <=180 chars>","recommended_action":"MONITOR|INVESTIGATE|ISOLATE_HOST|BLOCK_IP|KILL_PROCESS|DISABLE_USER|QUARANTINE_FILE"}}

LOGS:
{log_text}
""",
    "manual": """You are a senior SOC analyst performing a deep investigation on this telemetry batch. Be honest: if data is benign or insufficient, say so plainly instead of inventing threats.

Return ONLY a single JSON object, no prose, no markdown fences:
{{"verdict":"CRITICAL|SUSPICIOUS|NOT_CRITICAL|INSUFFICIENT_DATA","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","confidence":<0.0-1.0>,"kill_chain_stage":"recon|delivery|exploitation|installation|c2|actions|none","techniques":["<MITRE ATT&CK ID>"],"iocs":["<ip|hash|domain|path>"],"summary":"<2-4 sentence technical narrative>","next_steps":["<concrete analyst step>"]}}

LOGS:
{log_text}
""",
    "defensive": """You are a senior SOC analyst writing a SHORT technical incident note for the operator. The log below is a real security telemetry event that the SIEM already flagged as worth a look. Your job is to READ the log carefully and explain WHAT happened in plain language, then say what defensive action (if any) makes sense.

Rules:
- NEVER say "insufficient information" or "insufficient evidence". If the data is thin, describe exactly what you CAN see (process name, event ID, source IP, account name, log channel) and what threat class it most resembles.
- Identify the event by name where possible (e.g. "Windows Event 4625 - failed logon", "vmauthd recv() failure on local socket", "Microsoft-Windows-SMBServer suspicious connection from ::1").
- If the event is benign / routine noise, say WHY it is routine (loopback, expected service noise, no privileged account, etc) — do not just stamp MONITOR.
- The `reason` field MUST be a complete English sentence (15-50 words) that a tier-1 analyst can paste into a ticket. NEVER repeat the verdict ("MONITOR") as the reason.
- Use ACT only when there is a concrete indicator (known-bad IP, credential theft pattern, lateral-movement command, ransomware file extension). Use IGNORE for clear false positives. Otherwise MONITOR.

Return ONLY a single JSON object, no prose, no markdown fences:
{{"verdict":"ACT|MONITOR|IGNORE","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","confidence":<0.0-1.0>,"event_name":"<short label of the event>","action":"BLOCK_IP|KILL_PROCESS|RESTART_SERVICE|ISOLATE_HOST|DISABLE_USER|QUARANTINE_FILE|MONITOR","target":"<IP/PID/Username/Path or 'none'>","reason":"<full sentence, what you actually see in the log and why this verdict>"}}

LOG:
{log_text}
"""
}


# `_extract_json` and `_format_insight` used to live here.
#
# The first counted braces to pull a JSON object out of whatever prose the
# model wrapped it in — necessary when the model was merely *asked* for JSON.
# Ollama's `format` parameter now constrains it to the schema, so there is
# nothing to salvage. See ai/schemas.py.
#
# The second flattened a verdict into one display line, which then became the
# only stored record of it. Verdict, severity and confidence are columns now;
# `render_summary` still produces the line, but it is derived from the data
# rather than standing in for it.

QUEUES = {
    "automation": mq_utils.AI_AUTOMATION,
    "manual": mq_utils.AI_MANUAL,
    "defensive": mq_utils.AI_SOAR
}

soar = SOARAutomation(SOARConfig())

def _parse_failure_entry(source_file: str, log_text: str, error: str, model: str) -> dict:
    """The row written when the model could not produce a usable verdict.

    This replaces `_lazy()`, which detected the model saying "insufficient
    information" and then *fabricated* a narrative from the log fields —
    writing invented analysis into the audit trail as though the model had
    produced it. A security tool must not do that. An honest
    INSUFFICIENT_DATA row is less satisfying and far more useful: it says the
    model failed, which is a fact about the model worth acting on.
    """
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': source_file,
        'critical_summary': f"[PARSE FAILED] The model did not return a usable verdict. {error}",
        'source_data': log_text,
        'verdict': 'INSUFFICIENT_DATA',
        'severity': 'INFO',
        'confidence': 0.0,
        'model': model,
        'payload': None,
    }


async def handle_automation(agent, table, data, api_key, endpoint, model=None):
    log_text = json.dumps(data, indent=2)
    model_name = model or os.getenv("OLLAMA_MODEL", "")

    verdict, raw, error = await asyncio.to_thread(
        analyze_structured, PROMPTS["automation"], log_text, TriageVerdict,
        endpoint=endpoint, agent=agent, model=model, api_key=api_key,
    )

    if error or verdict is None:
        logger.error(f"[!] Automation verdict unusable agent={agent} table={table}: {error}")
        entry = _parse_failure_entry(f"Reviewed_{table}", log_text, error or "no response", model_name)
        try:
            await asyncio.to_thread(save_ai_results, agent, [entry])
        except Exception as e:
            logger.error(f"[!] Automation save FAILED agent={agent}: {e}")
        return

    intel_match = await asyncio.to_thread(get_threat_intel_summary, log_text)

    is_critical = (
        verdict.verdict == 'CRITICAL'
        and verdict.severity in ('CRITICAL', 'HIGH')
        and verdict.confidence >= CRITICAL_CONFIDENCE_THRESHOLD
    )
    is_suspicious = (
        verdict.verdict == 'SUSPICIOUS'
        and verdict.confidence >= SUSPICIOUS_CONFIDENCE_THRESHOLD
    )

    if is_critical or is_suspicious or intel_match:
        summary_line = render_summary(verdict, "AUTO")
        if intel_match:
            summary_line = f"{summary_line}\n[!!] GLOBAL THREAT INTEL MATCH: {intel_match}"
        source_file = f"Realtime_{table}"
        logger.info(f"[!] {verdict.verdict} (Automation) {agent}: {summary_line[:120]}")
    else:
        summary_line = render_summary(verdict, "AUTO REVIEW")
        source_file = f"Reviewed_{table}"
        logger.info(f"[.] Reviewed (Automation) {agent}/{table} "
                    f"v={verdict.verdict} conf={verdict.confidence:.2f}")

    result_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': source_file,
        'critical_summary': summary_line,
        'source_data': log_text,
        'verdict': verdict.verdict,
        'severity': verdict.severity,
        'confidence': verdict.confidence,
        'model': model_name,
        'payload': verdict.model_dump_json(),
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
    except Exception as e:
        logger.error(f"[!] Automation save FAILED agent={agent} table={table}: {e}")

async def handle_manual(agent, table, data, api_key, endpoint, model=None):
    batch_size = len(data) if isinstance(data, list) else 1
    log_text = json.dumps(data, indent=2, default=str)
    model_name = model or os.getenv("OLLAMA_MODEL", "")
    logger.info(f"[*] Manual analysis START agent={agent} table={table} batch={batch_size}")

    verdict, raw, error = await asyncio.to_thread(
        analyze_structured, PROMPTS["manual"], log_text, DeepAnalysis,
        endpoint=endpoint, agent=agent, model=model, api_key=api_key,
    )

    if error or verdict is None:
        logger.error(f"[!] Manual verdict unusable agent={agent} table={table}: {error}")
        entry = _parse_failure_entry(f"Manual_{table}", log_text, error or "no response", model_name)
        try:
            await asyncio.to_thread(save_ai_results, agent, [entry])
        except Exception as e:
            logger.error(f"[!] Manual save FAILED agent={agent}: {e}")
        return

    # The list fields are columns in `payload` now. They are still appended to
    # the display line so the card reads the same, but nothing parses them
    # back out of it.
    summary_line = render_summary(verdict, f"MANUAL x{batch_size}")
    extras = []
    if verdict.techniques:
        extras.append(f"techniques={','.join(verdict.techniques)}")
    if verdict.iocs:
        extras.append(f"iocs={','.join(verdict.iocs)}")
    if verdict.next_steps:
        extras.append("next=" + " | ".join(verdict.next_steps))
    if extras:
        summary_line = f"{summary_line}\n  {' | '.join(extras)}"

    result_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': f"Manual_{table}",
        'critical_summary': summary_line,
        'source_data': log_text,
        'verdict': verdict.verdict,
        'severity': verdict.severity,
        'confidence': verdict.confidence,
        'model': model_name,
        'payload': verdict.model_dump_json(),
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
        logger.info(f"[*] Manual analysis SAVED agent={agent} table={table} batch={batch_size}")
    except Exception as e:
        logger.error(f"[!] Manual save FAILED agent={agent} table={table}: {e}")

AUTONOMOUS_ACTIONS = {
    "BLOCK_IP",
    "KILL_PROCESS",
    "RESTART_SERVICE",
    "ISOLATE_HOST",
    "DISABLE_USER",
    "QUARANTINE_FILE",
    "SUSPEND_PROCESS",
    "LOGOFF_USER",
    "CONTAINER_ISOLATE",
    "CONTAINER_STOP",
    "CONTAINER_KILL",
}

AUTONOMOUS_ACTION_CONFIDENCE = float(os.getenv("AI_AUTO_ACT_CONF", "0.75"))

# Shadow mode: when enabled, the defensive worker stops dispatching real SOAR
# actions and instead writes a "proposal" insight that the operator can
# approve or reject from the SOAR Hub. Lets you test autonomy on production
# data before letting the model actually pull triggers.
SHADOW_MODE = os.getenv("AI_SHADOW_MODE", "0").lower() in ("1", "true", "yes", "on")


async def handle_defensive(agent, table, data, api_key, endpoint, model=None):
    log_text = json.dumps(data, indent=2)
    model_name = model or os.getenv("OLLAMA_MODEL", "")

    decision, raw, error = await asyncio.to_thread(
        analyze_structured, PROMPTS["defensive"], log_text, DefensiveDecision,
        endpoint=endpoint, agent=agent, model=model, api_key=api_key,
    )

    if error or decision is None:
        # Nothing is dispatched on an unusable verdict. That was already true,
        # but it is worth being explicit: this is the path where the platform
        # decides not to touch an endpoint because it could not understand the
        # event, and that decision belongs in the record.
        logger.error(f"[!] Defensive verdict unusable agent={agent} table={table}: {error}")
        entry = _parse_failure_entry("AI_DEFENSIVE_ADVICE", log_text, error or "no response", model_name)
        try:
            await asyncio.to_thread(save_ai_results, agent, [entry])
        except Exception as e:
            logger.error(f"[!] Defensive save FAILED agent={agent}: {e}")
        return

    v = decision.verdict
    conf = decision.confidence
    action = decision.action
    target = decision.target
    reason = decision.reason

    should_act = (
        v == 'ACT'
        and conf >= CRITICAL_CONFIDENCE_THRESHOLD
        and action in AUTONOMOUS_ACTIONS
        and target
        and target != 'none'
    )

    auto_dispatched = False
    shadow_proposed = False
    if should_act and conf >= AUTONOMOUS_ACTION_CONFIDENCE:
        if SHADOW_MODE:
            # Don't actually fire. The proposal will be saved into
            # ai_analysis_results with shadow_status='pending'; the operator
            # approves or rejects from the SOAR Hub.
            shadow_proposed = True
            logger.info(
                f"[~] SHADOW {action} target={target} agent={agent} conf={conf} "
                f"(would have auto-dispatched; queued for operator review)"
            )
        else:
            ok = await asyncio.to_thread(
                queue_soar_action,
                agent,
                action.lower(),
                str(target),
                f"AI auto-action conf={conf:.2f} reason={reason}".strip(),
            )
            auto_dispatched = bool(ok)
            if ok:
                logger.warning(f"[!!] AUTO-ACTION {action} target={target} agent={agent} conf={conf}")

    def _trim(s: str, n: int = 600) -> str:
        s = (s or '').strip()
        return s if len(s) <= n else s[: n - 3] + '...'

    base = render_summary(decision, "AI DEFENSIVE")
    if target and target != 'none':
        base = f"{base} target={target}"

    # `_lazy()` used to live here. It matched the model saying "insufficient
    # information", then rebuilt a narrative out of the log's own fields and
    # stored it as though the model had written it. That is fabricated
    # analysis in an audit trail. The schema now allows INSUFFICIENT_DATA as a
    # real verdict, so the model can say it and we record what it said.
    explanation = _trim(reason)

    proposed_action = None
    proposed_target = None
    shadow_status = None

    if shadow_proposed:
        summary_line = f"{base} | SHADOW-PROPOSED {action} (awaiting operator approval)"
        source_file = "AI_DEFENSIVE_SHADOW"
        proposed_action = action.lower()
        proposed_target = str(target)
        shadow_status = 'pending'
    elif auto_dispatched:
        summary_line = f"{base} | AUTO-DISPATCHED {action}"
        source_file = "AI_DEFENSIVE_AUTO"
    elif should_act:
        summary_line = f"{base} | RECOMMENDED {action} (conf below auto-dispatch threshold)"
        source_file = "AI_DEFENSIVE_ADVICE"
    elif v == 'ACT':
        summary_line = f"{base} | NEEDS-REVIEW (no valid target/action)"
        source_file = "AI_DEFENSIVE_ADVICE"
    else:
        summary_line = f"{base} | {v}"
        source_file = "AI_DEFENSIVE_MONITOR"

    if explanation:
        summary_line = f"{summary_line}\nReason: {explanation}"

    logger.info(f"[?] Defensive ({source_file}) for {agent}: {summary_line[:140]}")
    result_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': source_file,
        'critical_summary': summary_line,
        'source_data': log_text,
        'proposed_action': proposed_action,
        'proposed_target': proposed_target,
        'shadow_status': shadow_status,
        'verdict': decision.verdict,
        'severity': decision.severity,
        'confidence': decision.confidence,
        'model': model_name,
        'payload': decision.model_dump_json(),
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
    except Exception as e:
        logger.error(f"[!] Defensive save FAILED agent={agent} table={table}: {e}")

# How many events this worker will have in flight at once.
#
# Left at 1 by default on purpose. Ollama serialises requests per model unless
# OLLAMA_NUM_PARALLEL is raised, and on CPU inference more parallelism does not
# add throughput — it splits the same compute, making every request slower.
# Raise this together with OLLAMA_NUM_PARALLEL, and only on a GPU box or one
# with cores to spare. The latency line in ai/utils.py tells you whether it
# actually helped.
AI_CONCURRENCY = max(1, int(os.getenv("AI_CONCURRENCY", "1")))

ai_semaphore = asyncio.Semaphore(AI_CONCURRENCY)

# A timeout means the inference did not happen, so the event has not been
# triaged. Redelivering is the right answer; recording a verdict is not.
#
# RabbitMQ only tracks a redelivery count when a dead-letter exchange is
# configured, so the attempt is carried in a header on a republished copy.
MAX_AI_ATTEMPTS = max(1, int(os.getenv("AI_MAX_ATTEMPTS", "4")))
# Backoff between attempts. A model that just timed out will not be faster
# one millisecond later, and hammering it makes the queue worse.
AI_RETRY_BASE_SEC = int(os.getenv("AI_RETRY_BASE_SEC", "30"))

_exchange = None   # set in main(), used to republish retries


async def _requeue_with_backoff(message: aio_pika.IncomingMessage, attempt: int, reason: str):
    """Republish this task for another attempt, or give up loudly."""
    if attempt >= MAX_AI_ATTEMPTS:
        logger.error(
            f"[!] Giving up on {WORKER_TYPE} task after {attempt} attempts: {reason}. "
            f"The event was not triaged — check that Ollama is reachable and "
            f"AI_TIMEOUT_SEC is large enough for this model."
        )
        return

    delay = AI_RETRY_BASE_SEC * attempt
    logger.warning(f"[~] {reason} — retrying in {delay}s (attempt {attempt + 1}/{MAX_AI_ATTEMPTS})")
    await asyncio.sleep(delay)
    try:
        await _exchange.publish(
            aio_pika.Message(
                body=message.body,
                headers={**(message.headers or {}), "x-ai-attempt": attempt + 1},
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            ),
            routing_key=QUEUES.get(WORKER_TYPE, mq_utils.AI_AUTOMATION),
        )
    except Exception as e:
        logger.error(f"[!] Could not requeue task: {e}")


async def process_message(message: aio_pika.IncomingMessage):
    async with message.process():
        async with ai_semaphore:
            attempt = int((message.headers or {}).get("x-ai-attempt", 0) or 0)
            try:
                payload = json.loads(message.body.decode())
                agent = payload.get("agent")
                table = payload.get("table")
                data  = payload.get("data")

                if not agent or not data:
                    return

                logger.info(f"[*] Starting {WORKER_TYPE} task for agent: {agent}, table: {table}"
                            + (f" (attempt {attempt + 1})" if attempt else ""))
                cfg = await load_ai_config(agent) or {}
                api_key = cfg.get('api_key', 'ollama')
                endpoint = cfg.get('endpoint')
                model = cfg.get('model_name') or cfg.get('model')

                started = time.monotonic()
                if WORKER_TYPE == "automation":
                    await handle_automation(agent, table, data, api_key, endpoint, model)
                elif WORKER_TYPE == "manual":
                    await handle_manual(agent, table, data, api_key, endpoint, model)
                elif WORKER_TYPE == "defensive":
                    await handle_defensive(agent, table, data, api_key, endpoint, model)

                logger.info(f"[*] Finished {WORKER_TYPE} task for {agent}/{table} "
                            f"in {time.monotonic() - started:.1f}s")

            except AITransientError as e:
                # Nothing is written. A timeout says the inference did not
                # happen, not that the event is benign, and a wall of "no
                # usable verdict" cards in the UI is worse than none.
                await _requeue_with_backoff(message, attempt, str(e))

            except Exception as e:
                logger.error(f"[!] Error processing message in {WORKER_TYPE}: {e}")

async def main():
    queue_name = QUEUES.get(WORKER_TYPE, mq_utils.AI_AUTOMATION)
    logger.info(f"[*] Starting AI Worker [{WORKER_TYPE.upper()}], queue: {queue_name}")
    
    connection = None
    while not connection:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
        except Exception as e:
            logger.error(f"[!] Connection to {RABBITMQ_URL} failed, retrying in 5s...")
            await asyncio.sleep(5)

    global _exchange
    async with connection:
        channel = await connection.channel()
        _exchange = channel.default_exchange
        # Matched to the semaphore. Prefetching more than we can process just
        # moves the backlog from the broker into this process, where it is
        # invisible and unacked messages sit until the channel closes.
        await channel.set_qos(prefetch_count=AI_CONCURRENCY)
        logger.info(f"[*] Concurrency: {AI_CONCURRENCY}, prefetch: {AI_CONCURRENCY}")
        queue = await channel.declare_queue(queue_name, durable=True)
        await queue.consume(process_message)
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
