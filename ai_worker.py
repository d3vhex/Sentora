import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "Sentora"))

import asyncio
import json
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
from ai.gating import surfaces
from ai.schemas import (
    TriageVerdict, DeepAnalysis, DefensiveDecision, coherence_problem, render_summary,
)
from ai.intel import get_threat_intel_summary
from core import mq as mq_utils

from modules.soar.soar import SOARAutomation, SOARConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AI-Worker")

WORKER_TYPE = os.getenv("WORKER_TYPE", "automation").lower()
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")

CRITICAL_CONFIDENCE_THRESHOLD = float(os.getenv("AI_CRIT_CONF", "0.6"))
SUSPICIOUS_CONFIDENCE_THRESHOLD = float(os.getenv("AI_SUS_CONF", "0.75"))

# Prompt templates live in ai/prompts.py so the eval harness can read them
# without importing this module's RabbitMQ and SOAR dependencies.
from ai.prompts import PROMPTS  # noqa: E402


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

def _split_fingerprint(data):
    """Pull the triage fingerprint out of the event before it becomes a prompt.

    server.py attaches `_ai_fingerprint` so the verdict can be linked back to
    the dedup counter. It must not reach the model — a 64-character hash in
    the log body is pure noise the model will try to interpret, and it would
    also change the prompt for otherwise identical events, defeating the
    response cache.
    """
    if not isinstance(data, dict):
        return data, None
    fp = data.get("_ai_fingerprint")
    if fp is None:
        return data, None
    return {k: v for k, v in data.items() if k != "_ai_fingerprint"}, fp


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
    data, fingerprint = _split_fingerprint(data)
    log_text = json.dumps(data, indent=2)
    model_name = model or os.getenv("OLLAMA_MODEL", "")

    verdict, _, error = await asyncio.to_thread(
        analyze_structured, PROMPTS["automation"], log_text, TriageVerdict,
        endpoint=endpoint, agent=agent, model=model, api_key=api_key,
    )

    if error is None and verdict is not None:
        # Schema-valid and still self-contradictory. See coherence_problem.
        error = coherence_problem(verdict)
        if error:
            verdict = None

    if error or verdict is None:
        logger.error(f"[!] Automation verdict unusable agent={agent} table={table}: {error}")
        entry = _parse_failure_entry(f"Reviewed_{table}", log_text, error or "no response", model_name)
        try:
            await asyncio.to_thread(save_ai_results, agent, [entry])
        except Exception:
            logger.exception(f"[!] Automation save FAILED agent={agent}")
        return

    intel_match = await asyncio.to_thread(get_threat_intel_summary, log_text)

    # ai/gating.surfaces, not a copy of the rule: the eval harness scores the
    # same gate, and while they were separate the harness reported 40%
    # escalation recall on runs where production surfaced nothing at all.
    if surfaces(verdict) or intel_match:
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
        'fingerprint': fingerprint,
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
    except Exception:
        logger.exception(f"[!] Automation save FAILED agent={agent} table={table}")

async def handle_manual(agent, table, data, api_key, endpoint, model=None):
    batch_size = len(data) if isinstance(data, list) else 1
    log_text = json.dumps(data, indent=2, default=str)
    model_name = model or os.getenv("OLLAMA_MODEL", "")
    logger.info(f"[*] Manual analysis START agent={agent} table={table} batch={batch_size}")

    verdict, _, error = await asyncio.to_thread(
        analyze_structured, PROMPTS["manual"], log_text, DeepAnalysis,
        endpoint=endpoint, agent=agent, model=model, api_key=api_key,
    )

    if error is None and verdict is not None:
        # Applied here too, though this class is documented as "operator asked
        # for this, so always produce something". An honest INSUFFICIENT_DATA
        # row is still something; a self-contradictory analysis presented to
        # the person who requested it is not.
        error = coherence_problem(verdict)
        if error:
            verdict = None

    if error or verdict is None:
        logger.error(f"[!] Manual verdict unusable agent={agent} table={table}: {error}")
        entry = _parse_failure_entry(f"Manual_{table}", log_text, error or "no response", model_name)
        try:
            await asyncio.to_thread(save_ai_results, agent, [entry])
        except Exception:
            logger.exception(f"[!] Manual save FAILED agent={agent}")
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
    except Exception:
        logger.exception(f"[!] Manual save FAILED agent={agent} table={table}")

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
    data, fingerprint = _split_fingerprint(data)
    log_text = json.dumps(data, indent=2)
    model_name = model or os.getenv("OLLAMA_MODEL", "")

    decision, _, error = await asyncio.to_thread(
        analyze_structured, PROMPTS["defensive"], log_text, DefensiveDecision,
        endpoint=endpoint, agent=agent, model=model, api_key=api_key,
    )

    if error is None and decision is not None:
        # A self-contradictory decision must not reach the dispatch logic
        # below: `ACT` carrying severity INFO is not an instruction anyone
        # should act on. See coherence_problem.
        error = coherence_problem(decision)
        if error:
            decision = None

    if error or decision is None:
        # Nothing is dispatched on an unusable verdict. That was already true,
        # but it is worth being explicit: this is the path where the platform
        # decides not to touch an endpoint because it could not understand the
        # event, and that decision belongs in the record.
        logger.error(f"[!] Defensive verdict unusable agent={agent} table={table}: {error}")
        entry = _parse_failure_entry("AI_DEFENSIVE_ADVICE", log_text, error or "no response", model_name)
        try:
            await asyncio.to_thread(save_ai_results, agent, [entry])
        except Exception:
            logger.exception(f"[!] Defensive save FAILED agent={agent}")
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
        'fingerprint': fingerprint,
    }
    try:
        await asyncio.to_thread(save_ai_results, agent, [result_entry])
    except Exception:
        logger.exception(f"[!] Defensive save FAILED agent={agent} table={table}")

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
    except Exception:
        logger.exception("[!] Could not requeue task — this event is now lost")


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

            except Exception:
                # exception(), not error(): this is the catch-all for the
                # whole message path, and without a traceback a message like
                # "'NoneType' object has no attribute 'get'" says nothing
                # about which handler raised it.
                logger.exception(f"[!] Error processing message in {WORKER_TYPE}")

async def main():
    queue_name = QUEUES.get(WORKER_TYPE, mq_utils.AI_AUTOMATION)
    logger.info(f"[*] Starting AI Worker [{WORKER_TYPE.upper()}], queue: {queue_name}")
    
    connection = None
    while not connection:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
        except Exception as e:
            # The reason was captured and then dropped, so a broker that was
            # refusing the credentials looked identical to one that was not up
            # yet — both just retried silently every 5s.
            logger.error(f"[!] Connection to {RABBITMQ_URL} failed ({e}), retrying in 5s...")
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
