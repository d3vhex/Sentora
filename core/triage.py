"""Pre-LLM triage: decide which events are worth an inference.

Every SIEM event used to reach the model. On a busy endpoint that is thousands
of inferences a day for telemetry that is overwhelmingly repeats of the same
few lines, and a local 3B model takes ~47s each — so the queue never drains
and genuinely interesting events wait behind routine noise.

Two independent gates, in this order:

1. **Severity floor.** Events below `AI_MIN_SEVERITY` are not analysed.
2. **Deduplication.** An event whose fingerprint has been seen before is
   counted against the existing verdict instead of producing a new one.

The severity gate is the one that can lose a detection, and it is worth being
precise about why: **severity is assigned by the agent's rule file, not by the
model.** A log the rules label INFO is dropped here even if a human would have
called it an intrusion, and the model never gets the chance to disagree. That
is the trade being made — cost against the possibility that the rules are
wrong about something.

Three deliberate limits on that risk:

- An event with a missing or unrecognised severity is **kept**, never dropped.
  Fields go missing in this pipeline (see the `source` handling in
  log_extractor), and "we could not read the severity" must not silently mean
  "below the floor".
- The default floor drops only INFO, the mildest setting that does anything.
- Everything dropped is counted per severity and reported, so the size of the
  blind spot is a number rather than a guess.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os

# Ordered lowest to highest. Position in this list is the comparison.
SEVERITY_LADDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _json_default(o):
    if isinstance(o, _dt.datetime):
        return o.isoformat()
    return str(o)


# Fields excluded from the hash, in two groups.
#
# Volatile: differ between two sightings of the same event, so including them
# would make every repeat look new.
#
# Server-added: columns that exist on the stored row but not on the payload
# the agent sent. This distinction is easy to miss and breaks deduplication
# silently. Ingest fingerprints the incoming payload; the defensive sweep
# fingerprints the row it read back out of MySQL, which has picked up `id`,
# `dup_fp`, `created_at`, `sent` and the `ai_analyzed*` flags along the way.
# Hash those and the two paths can never agree - the sweep would consider
# every alert unseen, and the dedup check would run, pass, and prevent
# nothing.
FINGERPRINT_IGNORE = {
    # volatile
    "timestamp", "@timestamp", "TimeGenerated", "time",
    "PID", "ProcessID", "process_id",
    # server-added
    "id", "sent", "created_at", "dup_fp", "ai_analyzed", "ai_analyzed_at",
}


def compute_ai_fingerprint(table: str, item: dict) -> str:
    """Identify an event for deduplication, ignoring the fields that always vary.

    This lives here, and not next to either caller, because **both paths that
    feed the AI queue have to agree on it.** Ingest computes a fingerprint
    before publishing; the defensive sweep computes one before re-publishing.
    If those two were separate implementations, the sweep's idea of "already
    seen" would not match ingest's, and every alert ingest had already
    analysed would look new to the sweep - which is the exact failure that
    put 4130 duplicate messages on ai_soar_queue.

    `dup_fp` is preferred when the agent supplied one, because **hashing the
    row we received cannot work for encrypted tables.** `source` and `message`
    arrive as `enc::gAAAA...`, and Fernet's random IV makes the ciphertext of
    the same plaintext different every time - so a fingerprint taken over it
    is unique by construction and deduplication matches nothing, which is
    exactly what a night of telemetry showed: 517 fingerprints, all seen once,
    over a handful of alerts repeating hundreds of times.

    The agent computes `dup_fp` over the plaintext before encrypting (see
    enc_db.content_fingerprint) and it is stored in the clear.

    Falling back to hashing the item keeps older agents working. Their events
    still will not deduplicate if the row is encrypted - that cannot be fixed
    from this side - but nothing breaks, and mixed-version fleets behave the
    same as before.
    """
    fp = item.get("dup_fp")
    if isinstance(fp, str) and fp.strip():
        # Re-hashed with the table so the AI namespace stays separate from the
        # agent's own use of dup_fp, and so the value is the same width as the
        # fallback below.
        return hashlib.sha256(table.encode() + b"|AI|dup:" + fp.strip().encode()).hexdigest()

    data = {k: v for k, v in item.items() if k not in FINGERPRINT_IGNORE}
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"),
                      default=_json_default).encode("utf-8")
    return hashlib.sha256(table.encode() + b"|AI|" + blob).hexdigest()

# Events strictly below this are not sent for analysis. "INFO" disables the
# gate entirely, which is the setting to use while you have no measurement of
# what the model would have said about the events being dropped.
MIN_SEVERITY = (os.getenv("AI_MIN_SEVERITY", "LOW") or "LOW").strip().upper()

# Process-local tallies, kept only for the ingest process's own logging.
#
# These are NOT the source of truth and must not be reported as one: ingest
# runs in server.py while the stats endpoint is served by app.py, so a counter
# living in module state reads as zero from the API no matter how many events
# were actually dropped. That is worse than having no counter, because it
# looks like an answer. The durable counts live in the per-agent
# `ai_triage_drops` and `ai_dedup` tables below.
dropped_by_severity: dict[str, int] = {}
suppressed_duplicates = 0


def _rank(severity) -> int | None:
    """Position on the ladder, or None when the value is not one we know."""
    if severity is None:
        return None
    s = str(severity).strip().upper()
    return SEVERITY_LADDER.index(s) if s in SEVERITY_LADDER else None


def _severity_from_body(message):
    """Severity out of the JSON event body, when the column is empty.

    Only used as a fallback. Anything unreadable returns None, which
    passes_severity treats as "keep" — a parse failure must not become a
    silent drop.
    """
    if not isinstance(message, str) or not message.lstrip().startswith("{"):
        return None
    try:
        body = json.loads(message)
    except (ValueError, TypeError):
        return None
    return body.get("severity") if isinstance(body, dict) else None


def passes_severity(item: dict) -> tuple[bool, str]:
    """Return (send_to_model, reason).

    Fails open on anything it cannot read. A dropped event is invisible to the
    whole AI pipeline, so ambiguity has to resolve towards keeping it.
    """
    floor = _rank(MIN_SEVERITY)
    if floor is None or floor == 0:
        # Unparseable config, or the gate is explicitly disabled at INFO.
        return True, "severity gate off"

    raw = item.get("severity") or item.get("level") or item.get("Severity")
    if raw is None:
        # log_extractor puts the enriched event into `message` as JSON and,
        # until recently, left the severity column NULL. Reading only the
        # column made this gate silently inert for every siem_events row —
        # it found nothing to compare and kept everything, which looked
        # exactly like a correctly-configured floor with nothing below it.
        raw = _severity_from_body(item.get("message"))

    rank = _rank(raw)
    if rank is None:
        # Missing or unrecognised. Keep it — see the module docstring.
        return True, f"severity unreadable ({raw!r}), kept"

    if rank < floor:
        label = str(raw).strip().upper()
        dropped_by_severity[label] = dropped_by_severity.get(label, 0) + 1
        return False, f"severity {label} below floor {MIN_SEVERITY}"

    return True, "above floor"


DROPS_DDL = """
CREATE TABLE IF NOT EXISTS ai_triage_drops (
    severity     VARCHAR(16)     NOT NULL PRIMARY KEY,
    dropped      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_dropped TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def record_drop(cursor, severity: str) -> None:
    """Persist the fact that the severity gate discarded an event.

    In the database rather than a counter in memory, for the reason given
    above: the process that drops events is not the process that answers
    /api/ai/triage-stats, so an in-process number would always report zero.

    This is the only evidence that the gate is costing anything. Raising
    AI_MIN_SEVERITY without being able to read it is raising it blind.
    """
    try:
        cursor.execute(DROPS_DDL)
        cursor.execute(
            """INSERT INTO ai_triage_drops (severity, dropped)
               VALUES (%s, 1)
               ON DUPLICATE KEY UPDATE
                   dropped = dropped + 1,
                   last_dropped = NOW()""",
            (str(severity).strip().upper()[:16],),
        )
    except Exception:
        # Never let bookkeeping break ingest. The event is already dropped;
        # losing the tally is bad but losing telemetry would be worse.
        pass


DEDUP_DDL = """
CREATE TABLE IF NOT EXISTS ai_dedup (
    fingerprint  CHAR(64) NOT NULL PRIMARY KEY,
    table_name   VARCHAR(64)  NOT NULL,
    occurrences  INT UNSIGNED NOT NULL DEFAULT 1,
    first_seen   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_dedup_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def claim_for_analysis(cursor, table: str, fingerprint: str) -> bool:
    """Reserve this fingerprint for analysis. True if we are the first to.

    The difference from `record_occurrence` is what it does NOT do: it does
    not increment `occurrences`.

    `record_occurrence` is for ingest, where each call is a real, separate
    sighting of the event and counting it is the point. The defensive sweep is
    not a sighting - it re-reads the same "most recent N" rows every five
    minutes. Using `record_occurrence` there would add one to every recent
    alert on every pass, and `occurrences` would drift from "how often did
    this event happen" to "how many times has the sweep looped", silently
    inflating the `inferences_avoided` figure the AI stats endpoint reports.

    Still a single statement rather than SELECT-then-INSERT, so two callers
    cannot both decide they are first. `last_seen` is touched so the row does
    not look stale, which is also what makes MySQL return rowcount 2 rather
    than 0 for an existing row - only rowcount 1 means we inserted it.
    """
    cursor.execute(
        """INSERT INTO ai_dedup (fingerprint, table_name, occurrences)
           VALUES (%s, %s, 1)
           ON DUPLICATE KEY UPDATE last_seen = NOW()""",
        (fingerprint, table),
    )
    return cursor.rowcount == 1


def record_occurrence(cursor, table: str, fingerprint: str) -> tuple[bool, int]:
    """Count this event and say whether it is the first of its kind.

    Returns `(is_new, occurrences)`. Only a new fingerprint should be sent for
    analysis; repeats attach to the verdict the first one produced.

    The counter lives in the database rather than in a process dict, which the
    previous implementation used. That dict had three problems: it was wiped
    wholesale once it reached 1000 entries — so deduplication stopped working
    exactly when volume made it matter — it was per-Sanic-worker, so it
    divided by the worker count, and it was lost on every restart.

    MySQL reports rowcount 1 for an INSERT and 2 for an ON DUPLICATE KEY
    UPDATE that changed a row, which is what distinguishes the two cases
    atomically. Doing it in one statement matters: two concurrent ingests of
    the same event would otherwise both read "unseen" and both publish.
    """
    global suppressed_duplicates

    cursor.execute(
        """INSERT INTO ai_dedup (fingerprint, table_name, occurrences)
           VALUES (%s, %s, 1)
           ON DUPLICATE KEY UPDATE
               occurrences = occurrences + 1,
               last_seen = NOW()""",
        (fingerprint, table),
    )
    is_new = cursor.rowcount == 1
    if is_new:
        return True, 1

    suppressed_duplicates += 1
    cursor.execute(
        "SELECT occurrences FROM ai_dedup WHERE fingerprint = %s", (fingerprint,)
    )
    row = cursor.fetchone()
    return False, int(row[0]) if row else 2


def config() -> dict:
    """How the funnel is configured. The counts come from the database — see
    the note on `dropped_by_severity` for why they cannot come from here."""
    return {
        "min_severity": MIN_SEVERITY,
        "severity_gate_enabled": (_rank(MIN_SEVERITY) or 0) > 0,
    }
