import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "Zer0Vuln"))

import asyncio
import json
import re
import logging
import aio_pika
import os
from datetime import datetime
from ai.utils import load_ai_config, analyze_with_ai, save_ai_results, queue_soar_action
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


def _extract_json(text: str):
    """Best-effort extraction of the first JSON object from an LLM response.
    Handles models that wrap JSON in prose or markdown fences."""
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    start = cleaned.find('{')
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(cleaned)):
        c = cleaned[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                blob = cleaned[start:i+1]
                try:
                    return json.loads(blob)
                except Exception:
                    return None
    return None


def _format_insight(verdict: dict, prefix: str) -> str:
    """Render a verdict JSON into a human-readable single-line insight.

    The defensive prompt returns `reason` instead of `summary`, the manual
    prompt returns `summary`, automation returns `summary` + `indicator`.
    We pull whichever fields are present so the rendered line is never an
    empty stub like `[AI DEFENSIVE] [INFO] -> none`.
    """
    sev = (verdict.get('severity') or 'INFO').upper()
    conf = verdict.get('confidence')
    summary = (
        verdict.get('summary')
        or verdict.get('reason')
        or verdict.get('rationale')
        or verdict.get('explanation')
        or ''
    )
    indicator = verdict.get('indicator') or verdict.get('kill_chain_stage') or ''
    action = verdict.get('recommended_action') or verdict.get('action') or ''
    parts = [f"[{prefix}]", f"[{sev}]"]
    if isinstance(conf, (int, float)):
        parts.append(f"conf={conf:.2f}")
    if indicator and indicator != 'none':
        parts.append(f"({indicator})")
    if summary:
        parts.append(summary.strip())
    if action and action not in ('MONITOR', 'none', ''):
        parts.append(f"-> {action}")
    return ' '.join(p for p in parts if p)

QUEUES = {
    "automation": mq_utils.AI_AUTOMATION,
    "manual": mq_utils.AI_MANUAL,
    "defensive": mq_utils.AI_SOAR
}

soar = SOARAutomation(SOARConfig())

async def handle_automation(agent, table, data, api_key, endpoint, model=None):
    log_text = json.dumps(data, indent=2)
    raw = await asyncio.to_thread(
        analyze_with_ai, api_key, log_text, PROMPTS["automation"], endpoint, agent, model,
    )

    verdict = _extract_json(raw) or {}
    v = (verdict.get('verdict') or '').upper()
    sev = (verdict.get('severity') or '').upper()
    try:
        conf = float(verdict.get('confidence') or 0)
    except Exception:
        conf = 0.0

    intel_match = await asyncio.to_thread(get_threat_intel_summary, log_text)

    is_critical = (v == 'CRITICAL' and sev in ('CRITICAL', 'HIGH') and conf >= CRITICAL_CONFIDENCE_THRESHOLD)
    is_suspicious = (v == 'SUSPICIOUS' and conf >= SUSPICIOUS_CONFIDENCE_THRESHOLD)

    if is_critical or is_suspicious or intel_match:
        summary_line = _format_insight(verdict, "AUTO") if verdict else f"[AUTO] {raw[:300]}"
        if intel_match:
            summary_line = f"{summary_line}\n[!!] GLOBAL THREAT INTEL MATCH: {intel_match}"
        source_file = f"Realtime_{table}"
        logger.info(f"[!] CRITICAL (Automation) for {agent}: {summary_line[:120]}")
    else:
        if verdict:
            short_sev = sev or 'INFO'
            summary = verdict.get('summary') or 'No critical indicator detected.'
            summary_line = f"[AUTO REVIEW] [{short_sev}] conf={conf:.2f} {summary}"
        elif raw:
            summary_line = f"[AUTO REVIEW] {raw[:280]}"
        else:
            summary_line = f"[AUTO REVIEW] No response from AI service."
        source_file = f"Reviewed_{table}"
        logger.info(f"[.] Reviewed (Automation) for {agent}/{table} v={v} conf={conf}")

    result_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': source_file,
        'critical_summary': summary_line,
        'source_data': log_text,
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
    except Exception as e:
        logger.error(f"[!] Automation save FAILED agent={agent} table={table}: {e}")

async def handle_manual(agent, table, data, api_key, endpoint, model=None):
    batch_size = len(data) if isinstance(data, list) else 1
    log_text = json.dumps(data, indent=2, default=str)
    logger.info(f"[*] Manual analysis START agent={agent} table={table} batch={batch_size}")

    raw = await asyncio.to_thread(
        analyze_with_ai, api_key, log_text, PROMPTS["manual"], endpoint, agent, model,
    )

    verdict = _extract_json(raw) or {}
    if verdict:
        summary_line = _format_insight(verdict, f"MANUAL x{batch_size}")
        techniques = verdict.get('techniques') or []
        iocs = verdict.get('iocs') or []
        next_steps = verdict.get('next_steps') or []
        extras = []
        if techniques: extras.append(f"techniques={','.join(map(str, techniques))}")
        if iocs:       extras.append(f"iocs={','.join(map(str, iocs))}")
        if next_steps: extras.append("next=" + " | ".join(map(str, next_steps)))
        if extras:
            summary_line = f"{summary_line}\n  {' | '.join(extras)}"
    else:
        summary_line = f"[MANUAL DEEP SCAN x{batch_size}] {raw[:1500] if raw else 'No response from AI service.'}"

    result_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': f"Manual_{table}",
        'critical_summary': summary_line,
        'source_data': log_text,
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
    raw = await asyncio.to_thread(
        analyze_with_ai, api_key, log_text, PROMPTS["defensive"], endpoint, agent, model,
    )

    verdict = _extract_json(raw) or {}
    v = (verdict.get('verdict') or '').upper()
    try:
        conf = float(verdict.get('confidence') or 0)
    except Exception:
        conf = 0.0

    action = (verdict.get('action') or '').upper()
    target = verdict.get('target') or ''
    reason = verdict.get('reason') or ''

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

    # Build a real analyst-friendly explanation. The model frequently returns
    # the structured JSON with `reason` blank — in that case we keep its raw
    # commentary too so the operator actually sees what the AI concluded
    # instead of an empty "MONITOR" badge.
    def _trim(s: str, n: int = 600) -> str:
        s = (s or '').strip()
        return s if len(s) <= n else s[: n - 3] + '...'

    if verdict:
        base = _format_insight(verdict, "AI DEFENSIVE")
        if target and target != 'none':
            base = f"{base} target={target}"

        explanation = (
            verdict.get('reason')
            or verdict.get('summary')
            or verdict.get('rationale')
            or verdict.get('explanation')
            or ''
        ).strip()
        event_name = (verdict.get('event_name') or '').strip()

        # The small llama3.2:3b model loves the lazy "Insufficient information
        # to determine X" non-answer. When we detect that pattern, rebuild a
        # useful note from the actual log content so the operator gets a real
        # description instead of a copy-pasted apology.
        def _lazy(text: str) -> bool:
            t = (text or '').strip().lower()
            if not t:
                return True
            lazy_starts = (
                'insufficient information',
                'insufficient evidence',
                'insufficient data',
                'unclear',
                'cannot determine',
                "can't determine",
                'no information',
                'not enough information',
                'no further action',
            )
            return any(t.startswith(p) for p in lazy_starts)

        if _lazy(explanation):
            try:
                parsed_log = json.loads(log_text) if log_text.strip().startswith('{') else None
            except Exception:
                parsed_log = None
            rec = parsed_log if isinstance(parsed_log, dict) else {}
            src = (rec.get('source') or rec.get('channel') or rec.get('logger') or '').strip()
            sev_lg = (rec.get('severity') or rec.get('level') or '').strip()
            msg = (rec.get('message') or rec.get('msg') or rec.get('details') or '').strip()
            cats = (rec.get('categories') or rec.get('event_type') or '').strip()
            facts = []
            if event_name: facts.append(event_name)
            elif cats: facts.append(cats)
            if src: facts.append(f"source={src}")
            if sev_lg: facts.append(f"severity={sev_lg}")
            head = ' | '.join(facts) if facts else 'Telemetry event'
            tail = msg[:240] if msg else 'no message body'
            verdict_word = v or 'MONITOR'
            explanation = (
                f"{head}. Observed: {tail}. "
                f"No high-confidence indicator of compromise detected, defaulting to {verdict_word}."
            )

        if not explanation and raw:
            # JSON parsed but model gave no narrative — surface raw answer
            cleaned = raw.replace('\n', ' ').strip()
            if cleaned and not cleaned.startswith('{'):
                explanation = cleaned

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
            summary_line = f"{base} | {v or 'MONITOR'}"
            source_file = "AI_DEFENSIVE_MONITOR"

        if explanation:
            summary_line = f"{summary_line}\nReason: {_trim(explanation)}"
    elif raw:
        summary_line = f"[AI DEFENSIVE] {_trim(raw)}"
        source_file = "AI_DEFENSIVE_MONITOR"
        proposed_action = None
        proposed_target = None
        shadow_status = None
    else:
        summary_line = "[AI DEFENSIVE] No response from AI service."
        source_file = "AI_DEFENSIVE_MONITOR"
        proposed_action = None
        proposed_target = None
        shadow_status = None

    logger.info(f"[?] Defensive ({source_file}) for {agent}: {summary_line[:140]}")
    result_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': source_file,
        'critical_summary': summary_line,
        'source_data': log_text,
        'proposed_action': proposed_action,
        'proposed_target': proposed_target,
        'shadow_status': shadow_status,
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
    except Exception as e:
        logger.error(f"[!] Defensive save FAILED agent={agent} table={table}: {e}")

ai_semaphore = asyncio.Semaphore(1)

async def process_message(message: aio_pika.IncomingMessage):
    async with message.process():
        async with ai_semaphore:
            try:
                payload = json.loads(message.body.decode())
                agent = payload.get("agent")
                table = payload.get("table")
                data  = payload.get("data")
                
                if not agent or not data:
                    return

                logger.info(f"[*] Starting {WORKER_TYPE} task for agent: {agent}, table: {table}")
                cfg = await load_ai_config(agent) or {}
                api_key = cfg.get('api_key', 'ollama')
                endpoint = cfg.get('endpoint')
                model = cfg.get('model_name') or cfg.get('model')

                if WORKER_TYPE == "automation":
                    await handle_automation(agent, table, data, api_key, endpoint, model)
                elif WORKER_TYPE == "manual":
                    await handle_manual(agent, table, data, api_key, endpoint, model)
                elif WORKER_TYPE == "defensive":
                    await handle_defensive(agent, table, data, api_key, endpoint, model)

                await asyncio.sleep(0.5)

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

    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=1)
        queue = await channel.declare_queue(queue_name, durable=True)
        await queue.consume(process_message)
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
