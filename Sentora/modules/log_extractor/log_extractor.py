#!/usr/bin/env python3
import os
import re
import time
import json
import logging
import threading
import platform
import hashlib
import gzip
from queue import Queue, Empty
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

import modules.enc_db as enc_db
# Encrypted fields are declared once in enc_db.ENCRYPT_FIELDS_MAP. Setting
# them here replaced the map for the whole process, dropping every table other
# modules had registered.
insert_record_enc = enc_db.insert_record_enc
fetch_where_dec   = enc_db.fetch_where_dec

# Sigma is optional at import time. The agent ships with core/ but a partial
# deployment must degrade to the regex rules rather than failing to start:
# an EDR that will not boot is worse than one detecting less.
_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
try:
    from core.sigma import severity_of as sigma_severity
    from core.sigma_loader import match_all as sigma_match
    from core.sigma_loader import windows_event_fields as sigma_fields
    from core.sigma_loader import journal_event_fields as sigma_journal_fields
    from core.sigma_loader import text_event_fields as sigma_text_fields
    from core.correlation import default_engine as _default_correlation
    HAS_SIGMA = True
except ImportError:
    HAS_SIGMA = False

    def sigma_severity(_rule):          # pragma: no cover
        return "MEDIUM"

    def sigma_match(_rules, _fields):   # pragma: no cover
        return []

    def sigma_fields(*_a, **_kw):       # pragma: no cover
        return {}

    def sigma_journal_fields(*_a, **_kw):   # pragma: no cover
        return {}

    def sigma_text_fields(*_a, **_kw):      # pragma: no cover
        return {}

    def _default_correlation(*_a, **_kw):   # pragma: no cover
        return None


IS_WINDOWS = platform.system() == "Windows"

here = os.path.dirname(os.path.abspath(__file__))
default_cfg = os.path.normpath(os.path.join(here, "../../conf/log_paths.yaml"))
RULES_YAML_PATH = os.path.normpath(os.path.join(here, "../../conf/rules.yaml"))
# Sigma rules. `builtin/` ships with the agent; community rulesets go beside
# it, and everything under here is loaded recursively at start.
#
# This directory was empty by design once, on the argument that a detection
# nobody reviewed is no improvement. The argument holds and the outcome did
# not: it meant zero ATT&CK coverage on every install, and "no detections" is
# not a defensible default for a detection agent.
SIGMA_RULES_PATH = os.getenv(
    "SIGMA_RULES_PATH",
    os.path.normpath(os.path.join(here, "../../conf/sigma")))
PATHS_YAML_PATH = default_cfg

try:
    import yaml
except Exception:
    yaml = None
    logging.warning("PyYAML module not found. Rules may not load correctly.")

try:
    from systemd import reader as JournalReader, LOG_INFO
    HAS_JOURNAL = True
    Journal = JournalReader
except Exception:
    try:
        from cysystemd.journal import _Reader as JournalReader, LOG_INFO
        HAS_JOURNAL = True
        Journal = JournalReader
    except Exception:
        HAS_JOURNAL = False

@dataclass
class SIEMConfig:
    keywords: List[str]
    exclude_patterns: List[str]
    log_paths: Dict[str, List[str]]
    windows_log_types: List[str]
    output: Dict[str, str]
    rate_limit: int = 1000
    buffer_size: int = 10000
    log_rotation: bool = True
    max_log_size: int = 100 * 1024 * 1024
    enable_geoip: bool = False
    enable_enrichment: bool = True

@dataclass
class LogEvent:
    timestamp: str
    source_file: str
    raw_message: str
    severity: str = "INFO"
    event_type: str = "UNKNOWN"
    ip_address: Optional[str] = None
    user: Optional[str] = None
    event_hash: Optional[str] = None
    enriched_data: Optional[Dict] = None
    # MITRE ATT&CK technique IDs, from whichever Sigma rules matched. Empty
    # for a regex match: conf/rules.yaml has no ATT&CK mapping and never had
    # one, which is the reason Sigma is worth loading at all.
    techniques: Optional[List[str]] = None
    rule_title: Optional[str] = None

DEFAULT_EXCLUDE_PATTERNS = []

DEFAULT_OUTPUT = {
    'format': 'json',
    'destination': 'db',
    'file_path': './results/siem_events.log'
}

FALLBACK_LOG_PATHS = {
    'debian': [
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/apache2/access.log',
        '/var/log/nginx/error.log',
        '/var/log/syslog',
        '/var/log/auth.log',
    ],
    'rhel': [
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/messages',
        '/var/log/secure',
    ],
    'default': [
        '/var/log/syslog',
        '/var/log/messages',
        '/var/log/auth.log',
        '/var/log/secure',
    ],
}
FALLBACK_WINDOWS_LOG_TYPES = ['Security', 'System', 'Application']

event_queue = Queue()

class RateLimiter:
    def __init__(self, max_events_per_minute: int = 1000):
        self.max_events = max_events_per_minute
        self.events = deque()
        self.lock = threading.Lock()

    def is_allowed(self) -> bool:
        now = time.time()
        with self.lock:
            while self.events and self.events[0] < now - 60:
                self.events.popleft()
            if len(self.events) < self.max_events:
                self.events.append(now)
                return True
            return False

class EventEnricher:
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.user_patterns = [
            re.compile(r'user[:\s]+([a-zA-Z0-9_-]+)', re.I),
            re.compile(r'from\s+([a-zA-Z0-9_-]+)@', re.I)
        ]

    def enrich_event(self, raw_message: str, source_file: str) -> LogEvent:
        now_dt = datetime.now()
        now_ts = now_dt.strftime('%Y-%m-%d %H:%M:%S')

        ip_addresses = self.ip_pattern.findall(raw_message)
        primary_ip = ip_addresses[0] if ip_addresses else None

        username = None
        for pattern in self.user_patterns:
            match = pattern.search(raw_message)
            if match:
                username = match.group(1)
                break

        event_hash = hashlib.md5(
            f"{source_file}:{raw_message[:100]}".encode()
        ).hexdigest()

        enriched_data = {
            'all_ips': ip_addresses,
            'message_length': len(raw_message),
            'hour_of_day': now_dt.hour
        }

        return LogEvent(
            timestamp=now_ts,
            source_file=source_file,
            raw_message=raw_message,
            severity="INFO",
            event_type="LOG",
            ip_address=primary_ip,
            user=username,
            event_hash=event_hash,
            enriched_data=enriched_data
        )

class DuplicateFilter:
    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self.seen_events: Dict[str, float] = {}
        self.lock = threading.Lock()

    def is_duplicate(self, event_hash: str) -> bool:
        now = time.time()
        with self.lock:
            expired = [h for h, t in self.seen_events.items() if now - t > self.window]
            for h in expired:
                del self.seen_events[h]
            if event_hash in self.seen_events:
                return True
            self.seen_events[event_hash] = now
            return False

class LogRotator:
    def __init__(self, max_size: int = 100 * 1024 * 1024):
        self.max_size = max_size

    def should_rotate(self, filepath: str) -> bool:
        try:
            return os.path.getsize(filepath) > self.max_size
        except OSError:
            return False

    def rotate_file(self, filepath: str):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated_name = f"{filepath}.{timestamp}.gz"

        try:
            with open(filepath, 'rb') as f_in:
                with gzip.open(rotated_name, 'wb') as f_out:
                    f_out.writelines(f_in)
            open(filepath, 'w').close()
            logging.info(f"Rotated log file: {filepath} -> {rotated_name}")
        except Exception as e:
            logging.error(f"Failed to rotate {filepath}: {e}")

class MetricsCollector:
    def __init__(self):
        self.metrics = defaultdict(int)
        self.lock = threading.Lock()
        self.start_time = time.time()

    def increment(self, metric_name: str, value: int = 1):
        with self.lock:
            self.metrics[metric_name] += value

    def get_stats(self) -> Dict:
        with self.lock:
            runtime = time.time() - self.start_time
            stats = dict(self.metrics)
            stats['runtime_seconds'] = runtime
            stats['events_per_second'] = stats.get('events_processed', 0) / max(runtime, 1)
            return stats

def detect_distro():
    try:
        data = open('/etc/os-release', encoding='utf-8', errors='ignore').read().lower()
        if 'debian' in data or 'ubuntu' in data: return 'debian'
        if any(x in data for x in ['rhel', 'centos', 'rocky', 'alma']): return 'rhel'
        if 'suse' in data: return 'suse'
        if 'arch' in data: return 'arch'
        if 'fedora' in data: return 'fedora'
        if 'centos' in data: return 'centos'
        if 'amazon' in data: return 'amazon'
        if 'alpine' in data: return 'alpine'
        if 'gentoo' in data: return 'gentoo'
    except Exception:
        pass
    return 'default'

def _to_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if str(x).strip()]
    if isinstance(val, str):
        return [line for line in (v.strip() for v in val.splitlines()) if line]
    return []

def load_paths_from_yaml(path: str):
    if not yaml:
        logging.warning("YAML module missing, paths could not be loaded")
        return None
    if not os.path.isfile(path):
        logging.warning("No yaml file: %s (fallback paths will be used)", path)
        return None

    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}

    cfg = {
        'log_paths': data.get('log_paths'),
        'windows_log_types': _to_list(data.get('windows_log_types')),
    }
    return cfg

def load_rules_from_yaml(path: str):
    """Read rules.yaml and compile its patterns.

    Returns `[{'regex': Pattern, 'category': str, 'severity': str}]`.
    """
    if not yaml:
        logging.warning("YAML module not installed, rules could not be loaded!")
        return []

    if not os.path.exists(path):
        logging.warning(f"Rules file not found: {path}")
        return []

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Error reading rules file: {e}")
        return []

    compiled_rules = []

    categories = data.get('categories', {})
    scope = (os.getenv("RULES_SCOPE", "endpoint") or "endpoint").strip().lower()
    skipped_categories, skipped_patterns = [], 0

    for cat_name, cat_data in categories.items():
        severity = cat_data.get('severity', 'INFO')
        raw_patterns = cat_data.get('patterns', '')

        # `applies_to` scopes a category to the kind of data it can match.
        #
        # 821 of the 1575 patterns here are web-application attacks, and this
        # agent collects event logs, process and network telemetry, Docker and
        # FIM - no HTTP bodies anywhere. They could only produce false
        # positives, and did: one COMMAND INJECTION regex matching the agent's
        # own ` | ` separator flagged 89 of 100 events CRITICAL.
        #
        # Scoped rather than deleted, so they work the moment web logs arrive.
        # Unmarked categories always load: nobody having classified one is not
        # evidence it is irrelevant.
        applies_to = cat_data.get('applies_to')
        if applies_to and scope != "all":
            allowed = {str(s).strip().lower() for s in applies_to}
            if scope not in allowed:
                skipped_categories.append(cat_name)
                skipped_patterns += len([
                    l for l in raw_patterns.splitlines()
                    if l.strip() and not l.strip().startswith('#')
                ])
                continue

        for line in raw_patterns.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                regex = re.compile(line, re.IGNORECASE | re.DOTALL)
                compiled_rules.append({
                    'regex': regex,
                    'category': cat_name,
                    'severity': severity
                })
            except re.error as e:
                logging.warning(f"Rule failed to compile: [{cat_name}] '{line}' -> {e}")

    logging.info("Loaded %d security rules from rules.yaml (scope=%s).",
                 len(compiled_rules), scope)
    if skipped_categories:
        # Named, not silent. "Why did my SQL injection rule not fire" must be
        # answerable from the log rather than by reading this function.
        logging.info(
            "Skipped %d pattern(s) in %d category(ies) that do not apply to "
            "scope '%s': %s. Set RULES_SCOPE=all to load everything.",
            skipped_patterns, len(skipped_categories), scope,
            ", ".join(sorted(skipped_categories)))
    return compiled_rules

def compile_exclude_patterns(patterns):
    compiled = []
    for p in patterns or []:
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            logging.warning("Exclude pattern failed to compile (skipping): %r -> %s", p, e)
    return compiled

def get_log_paths_from_yaml_or_fallback(cfg_log_paths, distro: str):
    if isinstance(cfg_log_paths, list):
        return cfg_log_paths
    if isinstance(cfg_log_paths, dict):
        if distro in cfg_log_paths and cfg_log_paths[distro]:
            return cfg_log_paths[distro]
        if 'default' in cfg_log_paths and cfg_log_paths['default']:
            return cfg_log_paths['default']
    return FALLBACK_LOG_PATHS.get(distro, FALLBACK_LOG_PATHS['default'])

class Classification:
    """What a log line was decided to be, and by what.

    Which layer decided is worth knowing downstream - a Sigma hit matched a
    named field and carries an ATT&CK technique, a regex hit matched text
    somewhere in the line, and they are not equally strong evidence. But it is
    already recorded: `rule_title` is the Sigma rule's name and the regex list
    has nothing to put there. A second field saying the same thing is state
    that can disagree with itself, so `by` reads it rather than storing it.
    """

    __slots__ = ("severity", "category", "rule_title", "techniques")

    def __init__(self, severity, category, rule_title=None, techniques=()):
        self.severity = severity
        self.category = category
        self.rule_title = rule_title
        self.techniques = list(techniques)

    @property
    def by(self) -> str:
        return "sigma" if self.rule_title else "regex"


def classify(text, fields, sigma_rules, rules_list):
    """Sigma first, the regex list as fallback. None if neither fires.

    One implementation for all three collection paths. It existed only on the
    Windows path, so a Linux endpoint got no Sigma and no ATT&CK technique on
    anything.

    `fields` is whatever the path could supply - the journal has real ones, a
    syslog line little more than `Message`. That limit belongs to text logs,
    not to this function.
    """
    if sigma_rules and fields:
        hits = sigma_match(sigma_rules, fields)
        if hits:
            # Every rule that fired, not the first: techniques accumulate and
            # the most severe wins the label.
            best = max(hits, key=lambda r: _SEVERITY_ORDER.get(sigma_severity(r), 0))
            return Classification(
                severity=sigma_severity(best),
                category=best.title,
                rule_title=best.title,
                techniques=sorted({tech for r in hits for tech in r.techniques}),
            )

    for rule in rules_list:
        if rule['regex'].search(text):
            return Classification(severity=rule['severity'],
                                  category=rule['category'])
    return None


def correlated_events(correlator, fields, enricher, source, when=None):
    """Any correlation windows this event closed, as events of their own.

    A statement about a window, not a property of the event that happened to
    complete it - the fifth failed logon is no more interesting than the
    first, and relabelling it would show a routine 4625 marked CRITICAL with
    nothing explaining why.

    Failures are swallowed: this runs on the collection thread, and a
    correlation bug must cost a detection rather than the host's telemetry.
    `when` overrides the clock, for tests that cannot wait five minutes.
    """
    if not correlator or not fields:
        return []
    try:
        found = (correlator.observe(fields) if when is None
                 else correlator.observe(fields, now=when))
    except Exception:
        logging.exception("correlation failed; continuing collection")
        return []

    out = []
    for detection in found:
        event = enricher.enrich_event(detection.summary(), source)
        event.event_type = detection.title
        event.severity = detection.severity
        event.techniques = list(detection.techniques)
        event.rule_title = detection.title
        # The window is the identity, not the text. Without this the same
        # spray re-detected after its cooldown looks like a duplicate and is
        # dropped by the dedup filter that exists for repeated log lines.
        event.event_hash = hashlib.sha256(
            f"{detection.rule}|{detection.group}|{detection.seq}".encode()
        ).hexdigest()
        out.append(event)
    return out


def make_dup_fp_for_event(message: str) -> str:
    msg = (message or "").strip()
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()

def enhanced_follow_file(path: str, rules_list: List[Dict],
                        exclude_patterns: List[re.Pattern], enricher: EventEnricher,
                        metrics: MetricsCollector, rate_limiter: RateLimiter,
                        duplicate_filter: DuplicateFilter, sigma_rules=None,
                        correlator=None):
    last_position = 0
    consecutive_errors = 0
    max_errors = 5

    while consecutive_errors < max_errors:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                if os.path.getsize(path) >= last_position:
                    f.seek(last_position)
                else:
                    f.seek(0)

                consecutive_errors = 0

                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    last_position = f.tell()
                    line = line.strip()
                    if not line:
                        continue

                    if not rate_limiter.is_allowed():
                        metrics.increment('rate_limited_events')
                        continue

                    fields = sigma_text_fields(line, path)
                    for extra in correlated_events(correlator, fields,
                                                   enricher, path):
                        event_queue.put(extra)
                        metrics.increment('events_processed')

                    hit = classify(line, fields, sigma_rules, rules_list)
                    if hit is None:
                        continue

                    if any(p.search(line) for p in exclude_patterns):
                        metrics.increment('excluded_events')
                        continue

                    event = enricher.enrich_event(line, path)
                    event.event_type = hit.category
                    event.severity = hit.severity
                    event.techniques = hit.techniques
                    event.rule_title = hit.rule_title

                    if duplicate_filter.is_duplicate(event.event_hash):
                        metrics.increment('duplicate_events')
                        continue

                    event_queue.put(event)
                    metrics.increment('events_processed')

        except FileNotFoundError:
            logging.warning(f"Log file not found: {path}, waiting...")
            time.sleep(5)
            consecutive_errors += 1
        except PermissionError:
            logging.error(f"Permission denied accessing {path}")
            consecutive_errors += 1
            time.sleep(10)
        except Exception as e:
            logging.error(f"Error following {path}: {e}")
            consecutive_errors += 1
            time.sleep(2)

    logging.error(f"Too many consecutive errors, stopping monitoring of {path}")

def enhanced_follow_journal(rules_list: List[Dict], exclude_patterns, enricher: EventEnricher,
                            metrics: MetricsCollector, rate_limiter: RateLimiter,
                            duplicate_filter: DuplicateFilter, sigma_rules=None,
                            correlator=None):
    try:
        j = Journal(flags=0)
        j.log_level(LOG_INFO)
        j.this_boot()
        j.seek_tail()
        j.get_previous()
    except Exception as e:
        logging.error("Journal initialization failed: %s", e)
        return

    while True:
        try:
            if j.wait(1000):
                for entry in j:
                    msg = entry.get('MESSAGE', '')
                    if not msg: continue
                    msg = str(msg)

                    if not rate_limiter.is_allowed():
                        metrics.increment('rate_limited_events')
                        continue

                    fields = sigma_journal_fields(entry)
                    for extra in correlated_events(correlator, fields,
                                                   enricher, 'journal'):
                        event_queue.put(extra)
                        metrics.increment('events_processed')

                    hit = classify(msg, fields, sigma_rules, rules_list)
                    if hit is None:
                        continue

                    if any(p.search(msg) for p in exclude_patterns):
                        continue

                    event = enricher.enrich_event(msg, 'journal')
                    event.timestamp = datetime.fromtimestamp(entry.get('__REALTIME_TIMESTAMP', time.time())).strftime('%Y-%m-%d %H:%M:%S')
                    event.event_type = hit.category
                    event.severity = hit.severity
                    event.techniques = hit.techniques
                    event.rule_title = hit.rule_title

                    if not duplicate_filter.is_duplicate(event.event_hash):
                        event_queue.put(event)
                        metrics.increment('events_processed')
                    else:
                        metrics.increment('duplicate_events')
        except Exception as e:
            logging.error("Error reading journal: %s", e)
        time.sleep(0.1)

def is_duplicate_event(message: str) -> bool:
    dup_fp = make_dup_fp_for_event(message)
    rows = fetch_where_dec('siem_events', where="dup_fp = %s", params=(dup_fp,), limit=1)
    return bool(rows)

def enhanced_output_worker(output_cfg: Dict, metrics: MetricsCollector,
                           log_rotator: LogRotator):
    fmt = output_cfg.get('format', 'json')
    dest = output_cfg.get('destination', 'db')
    file_path = output_cfg.get('file_path', './results/siem_events.log')

    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    fh = None
    if dest in ['file', 'both']:
        fh = open(file_path, 'a', encoding='utf-8')

    while True:
        try:
            event = event_queue.get(timeout=1)
        except Empty:
            continue

        try:
            if fmt == 'json':
                event_dict = {
                    'timestamp': event.timestamp,
                    'datetime': event.timestamp,
                    'source': event.source_file,
                    'severity': event.severity,
                    'event_type': event.event_type,
                    'message': event.raw_message,
                    'ip_address': event.ip_address,
                    'user': event.user,
                    'hash': event.event_hash,
                    'enriched': event.enriched_data,
                    'techniques': event.techniques or [],
                    'rule': event.rule_title,
                }
                output = json.dumps(event_dict, ensure_ascii=False)
            else:
                output = f"[{event.timestamp}] [{event.severity}] [{event.event_type}] {event.source_file} > {event.raw_message}"

            if dest in ['stdout', 'both']:
                print(output, flush=True)

            if dest in ['file', 'both'] and fh:
                fh.write(output + "\n")
                fh.flush()
                if log_rotator.should_rotate(file_path):
                    fh.close()
                    log_rotator.rotate_file(file_path)
                    fh = open(file_path, 'a', encoding='utf-8')

            if dest in ['db', 'both']:
                dup_fp = make_dup_fp_for_event(output)
                if not is_duplicate_event(output):
                    # `source` and `severity` are real columns and were never
                    # populated: the whole event went into `message` as JSON
                    # and the columns stayed NULL. That is why alerts rendered
                    # "Source: Unknown", why the idx_siem_src index matched
                    # nothing, and why the server-side severity gate saw no
                    # severity to compare and kept every event.
                    #
                    # The JSON body is unchanged, so anything already reading
                    # it keeps working.
                    insert_record_enc('siem_events', {
                        'timestamp': event.timestamp,
                        'source': event.source_file,
                        'severity': event.severity,
                        'message': output,
                        'dup_fp': dup_fp,
                        # A column, not only a field in the JSON body: ATT&CK
                        # coverage is a question you ask across every event
                        # ("which techniques have we ever seen"), and that is
                        # not answerable by parsing a text column.
                        'techniques': ','.join(event.techniques or []) or None,
                    })

            metrics.increment('events_output')

        except Exception as e:
            logging.error(f"Error outputting event: {e}")
            metrics.increment('output_errors')
        finally:
            event_queue.task_done()

    if fh:
        fh.close()

def follow_windows_eventlog(rules_list: List[Dict], exclude_patterns, log_type,
                            enricher: EventEnricher, metrics: MetricsCollector,
                            rate_limiter: RateLimiter, duplicate_filter: DuplicateFilter,
                            sigma_rules=None, correlator=None):
    import win32evtlog
    server = 'localhost'
    
    while True:
        hand = None
        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                for ev in events:
                    if not rate_limiter.is_allowed():
                        metrics.increment('rate_limited_events')
                        continue

                    eid = ev.EventID & 0xFFFF
                    source = ev.SourceName or "Unknown"
                    category = ev.EventCategory or 0
                    timestamp = ev.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                    
                    inserts = ev.StringInserts or []
                    message = ' | '.join(str(i) for i in inserts)
                    
                    event_summary = f"[{source}] EID={eid}, Cat={category}"
                    if eid == 4624: event_summary += " | Successful Logon"
                    elif eid == 4625: event_summary += " | Failed Logon"
                    elif eid == 4648: event_summary += " | Logon explicit credentials"
                    elif eid == 4720: event_summary += " | User account created"
                    elif eid == 4722: event_summary += " | User account enabled"
                    elif eid == 4725: event_summary += " | User account disabled"
                    
                    full_msg = f"{event_summary} | {message}"

                    # Sigma first. It matches on named fields, so it can
                    # tell `Image=vssadmin.exe` from the word "vssadmin"
                    # appearing in a message, and it carries the ATT&CK
                    # technique with it. The regex list is the fallback for
                    # everything Sigma has no rule for.
                    fields = sigma_fields(eid, inserts, message=full_msg,
                                          channel=log_type,
                                          provider=source) if sigma_rules else None
                    for extra in correlated_events(correlator, fields,
                                                   enricher, log_type):
                        event_queue.put(extra)
                        metrics.increment('events_processed')

                    hit = classify(full_msg, fields, sigma_rules, rules_list)
                    if hit is None:
                        continue

                    if any(p.search(full_msg) for p in exclude_patterns):
                        continue

                    # `source` (the event provider, e.g.
                    # Microsoft-Windows-Security-Auditing) was computed above,
                    # used in the message summary, and then dropped — only
                    # `log_type`, the channel name, reached the source column.
                    # Both are worth keeping: the channel says where to look,
                    # the provider says what produced it.
                    origin = f"{log_type}/{source}" if source and source != "Unknown" else log_type
                    event = enricher.enrich_event(full_msg, origin)
                    event.event_type = hit.category
                    event.severity = hit.severity
                    event.techniques = hit.techniques
                    event.rule_title = hit.rule_title

                    if not duplicate_filter.is_duplicate(event.event_hash):
                        event_queue.put(event)
                        metrics.increment('events_processed')
                    else:
                        metrics.increment('duplicate_events')

            if hand:
                win32evtlog.CloseEventLog(hand)
                hand = None
            
            time.sleep(3)
        except Exception as e:
            err_str = str(e)
            if "1314" in err_str:
                logging.warning(f"Insufficient privileges to read Windows event log {log_type} (requires Admin).")
                time.sleep(60)
            else:
                logging.error(f"Error reading Windows event log {log_type}: {e}")
                time.sleep(5)
            if hand:
                try: win32evtlog.CloseEventLog(hand)
                except Exception: pass

def stats_reporter(metrics: MetricsCollector, interval: int = 60):
    """Periodic counters, on one line, and only when they moved.

    This used `json.dumps(indent=2)`, so each report was eight lines. At one
    report a minute that was 6300 lines of agent.log in thirteen hours,
    almost all of it reporting that nothing had happened since the last one.
    """
    last_processed = None
    while True:
        time.sleep(interval)
        stats = metrics.get_stats()
        processed = stats.get('events_processed', 0)
        if processed == last_processed:
            continue        # nothing new since the last report
        last_processed = processed
        logging.info(
            "SIEM stats: processed=%s output=%s duplicates=%s rate_limited=%s "
            "uptime=%.0fs rate=%.2f/s",
            processed, stats.get('events_output', 0),
            stats.get('duplicate_events', 0), stats.get('rate_limited_events', 0),
            stats.get('runtime_seconds', 0), stats.get('events_per_second', 0),
        )

def create_health_check_data(metrics: MetricsCollector) -> Dict:
    stats = metrics.get_stats()
    return {
        'status': 'healthy' if stats.get('events_per_second', 0) >= 0 else 'degraded',
        'uptime': stats.get('runtime_seconds', 0),
        'events_processed': stats.get('events_processed', 0),
        'events_per_second': stats.get('events_per_second', 0),
        'errors': {
            'rate_limited': stats.get('rate_limited_events', 0),
            'duplicates': stats.get('duplicate_events', 0),
            'output_errors': stats.get('output_errors', 0)
        }
    }

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    enricher = EventEnricher()
    rate_limiter = RateLimiter(max_events_per_minute=1000)
    duplicate_filter = DuplicateFilter(window_seconds=300)
    metrics = MetricsCollector()
    log_rotator = LogRotator()

    logging.info(f"Loading rules: {RULES_YAML_PATH}")
    rules_list = load_rules_from_yaml(RULES_YAML_PATH)

    if not rules_list:
        logging.warning("WARNING: No rules loaded. SIEM will be silent.")

    # Sigma rules, if any are installed. They are additive: the regex list
    # still runs for events no Sigma rule addresses, so installing none
    # changes nothing.
    sigma_rules = []
    if HAS_SIGMA:
        from core.sigma_loader import load_dir
        result = load_dir(SIGMA_RULES_PATH)
        sigma_rules = result.rules
        logging.info("%s from %s", result.summary(), SIGMA_RULES_PATH)
        for path, reason in result.rejected:
            # Named, not counted. A rule an operator installed and believes is
            # running, which is not, is the failure this reports.
            logging.warning("Sigma rule rejected: %s - %s", path, reason)

    # One engine shared by every collector thread. Deliberately shared: a
    # spray that arrives partly through the Security channel and partly
    # through a file would be split across two windows and reach neither
    # threshold if each thread counted alone.
    #
    # `observe` is called from several threads. Its work is bounded and it
    # takes no lock, so the worst a race does is miscount by one across a
    # window of five - which is why this is not worth serialising on the
    # collection path.
    correlator = _default_correlation() if HAS_SIGMA else None
    if correlator:
        from core.correlation import techniques_covered
        logging.info("%d correlation rule(s) loaded, %d ATT&CK technique(s)",
                     len(correlator.rules), len(techniques_covered()))


    exclude_patterns = compile_exclude_patterns(DEFAULT_EXCLUDE_PATTERNS)

    y = load_paths_from_yaml(PATHS_YAML_PATH)

    distro = detect_distro()
    paths = get_log_paths_from_yaml_or_fallback(y['log_paths'] if y else None, distro)

    for path in paths:
        if os.path.exists(path):
            threading.Thread(
                target=enhanced_follow_file,
                args=(path, rules_list, exclude_patterns, enricher, metrics,
                        rate_limiter, duplicate_filter, sigma_rules, correlator),
                daemon=True
            ).start()
        else:
            # On Windows the YAML's Linux paths will all miss. That's
            # expected, not a warning — only log it on platforms where
            # the path actually should exist.
            if not IS_WINDOWS:
                logging.warning("Log file not found: %s", path)
            else:
                logging.debug("Skipping non-Windows log path: %s", path)

    if IS_WINDOWS:
        log_types = y['windows_log_types'] if (y and y['windows_log_types']) else FALLBACK_WINDOWS_LOG_TYPES
        for lt in log_types:
            threading.Thread(
                target=follow_windows_eventlog,
                args=(rules_list, exclude_patterns, lt, enricher, metrics,
                      rate_limiter, duplicate_filter, sigma_rules),
                daemon=True
            ).start()
    else:
        if HAS_JOURNAL:
            threading.Thread(
                target=enhanced_follow_journal,
                args=(rules_list, exclude_patterns, enricher, metrics,
                      rate_limiter, duplicate_filter, sigma_rules, correlator),
                daemon=True
            ).start()

    threading.Thread(
        target=enhanced_output_worker,
        args=(DEFAULT_OUTPUT, metrics, log_rotator),
        daemon=True
    ).start()

    threading.Thread(
        target=stats_reporter,
        args=(metrics,),
        daemon=True
    ).start()

    if not IS_WINDOWS and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Run as root to access all logs")

    logging.info("SIEM Log Collector started successfully with YAML rules")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping...")

    logging.info("SIEM Log Collector stopped")
