# Sentora Architecture and Features

This document is a technical breakdown of the Sentora platform: feature
set, container topology, data flow and component-level workflows derived
from the live source.

---

## 1. High-Level System Topography

Sentora operates on a distributed hub-and-spoke model designed for
endpoint visibility, real-time log analysis and automated remediation.

- Cybersecurity Command Center (Frontend). A React 18 plus TypeScript SPA
  served as static assets out of `/app/frontend/dist`. Ships with
  locally-bundled fonts (`@fontsource/inter`, `@fontsource/source-code-pro`)
  so the UI renders identically in air-gapped deployments.
- Management Hub (Control Plane). A high-concurrency Sanic application
  (`app.py`) plus a dedicated TCP ingest service (`server.py`). Per-agent
  MySQL databases keep scan and telemetry data isolated.
- AI Intelligence Multiplexer. RabbitMQ-fronted worker fleet (three
  specialised roles) running locally-hosted LLMs (Ollama `llama3.2:3b`).
- Sentora Agent (Sensor). Cross-platform (Windows and Linux) sensor that
  ships SIEM logs, FIM data, package inventory, Docker events and
  inventory, and accepts SOAR action pushes.

### 1.1 Container Topology (`docker-compose.yaml`)

| Service | Image / Source | Purpose |
| :--- | :--- | :--- |
| `db` | mysql:8.0 | Userdb (RBAC, audit, identities) plus per-agent `<agent>_db` schemas. Tuned `max_connections=500`. |
| `ollama` + `ollama-init` | ollama/ollama:latest | Local LLM runtime; init container pre-pulls `llama3.2:3b`. |
| `app` | Local build | Sanic REST API on `:8000`, also serves the React SPA. |
| `ingest` | Local build (`server.py`) | Async TCP ingest on `:5001`. |
| `rabbitmq` | rabbitmq:3-management | Queues `ai_automation_queue`, `ai_manual_queue`, `ai_soar_queue`. |
| `ai-worker-automation` | Local build | Real-time LLM triage of incoming logs. |
| `ai-worker-manual` | Local build | Operator-initiated deep scans. |
| `ai-worker-defensive` | Local build | Confidence-gated autonomous SOAR action dispatch. Honours `AI_SHADOW_MODE=1` to stage proposals for operator approval (see [§3.3 Shadow Mode](#33-shadow-mode)). |
| `opensearch` + `opensearch-dashboards` | opensearchproject:2.12.0 | Full-text log search, audit index. |

### 1.2 Server-Side Module Layout

After the 2026-04 reorganization the flat utility files at root were
split into intent-based packages:

```
Sentora-Server/
├── app.py                     entry: Sanic API + SPA
├── server.py                  entry: TCP ingest
├── ai_worker.py               entry: AI worker fleet (WORKER_TYPE selects role)
├── ai/
│   ├── utils.py               LLM call helpers, AI cache, SOAR action queueing
│   └── intel.py               AlienVault OTX + VirusTotal per-verdict enrichment
├── core/
│   ├── mq.py                  RabbitMQ publisher
│   ├── opensearch.py          OpenSearch index/search helpers
│   ├── config_validation.py   agent YAML validation (parse, shape, regex)
│   └── threat_feeds.py        abuse.ch indicator feeds
├── security/
│   ├── session.py             server-side session store
│   └── ssrf.py                proxy destination rules
├── scanners/
│   └── vuln.py                Server-side OSV vulnerability scanner
├── scripts/
│   ├── init_secrets.py        generate the secrets .env requires
│   ├── rotate_db_password.py  rotate the MySQL root account safely
│   └── api_smoke_test.py      exercise every route against a live server
├── tests/                     pytest; runs without MySQL or RabbitMQ
├── modules/db.py              (legacy postgres helper, unused)
└── frontend/                  React SPA source
```

Entry-point file names are kept at the root so `docker-compose.yaml`
commands (`python app.py`, `python server.py`, `python ai_worker.py`)
remain unchanged.

`app.py` is still the bulk of the server (~7,500 lines) and is the next
candidate for a Blueprint split. `security/`, `core/config_validation.py` and
`core/threat_feeds.py` were extracted from it because each has logic worth
unit-testing without a running stack.

---

## 2. Server-Side Infrastructure and Features

### 2.1 Management API (`app.py`, port 8000)

- Authentication. Server-side sessions in `userdb.sessions`; the browser
  holds an opaque token in an `HttpOnly` cookie and only its SHA-256 is
  stored. See [§2.5 Authentication](#25-authentication) for the full model —
  this replaced a scheme where the client asserted its own identity in an
  `X-User-ID` header the server trusted verbatim.
- RBAC and IAM. Multi-tier roles, per-permission gating via
  `@require_permission`, optional LDAP/AD fallback with just-in-time user
  provisioning. Bcrypt-hashed credentials.
- Audit Logging. `audit_logs` table records every privileged action
  (who, from, action, resource, details, IP, timestamp). Attribution comes
  from the session, not from a request header — an audit trail an attacker
  can sign with someone else's name is worse than none, because it reads as
  authoritative. Surfaced in the UI with an expandable per-row detail modal.
- Agent Enrollment. One-time `enrollment_tokens` produce a 64-char
  `agent_key` and an `agent_identities` row. Generates pre-baked
  installer payloads (`deploy.sh`, `deploy.ps1`).
- Resilient Server-to-Agent Auth. Outbound calls (`/config/*`,
  `/soar/execute`) try multiple `X-Agent-Key` candidates: first the
  enrolled agent key from `agent_identities`, then the server's master
  `AGENT_SHARED_SECRET`. Each attempt logs a fingerprint
  (`[agent-proxy] ... 401 with key#N (xxxxxx...)`) so mismatches are
  diagnosable.
- Agent Permissive-Auth Fallback. When the agent host has no
  `AGENT_MASTER_SECRET` (or legacy `AGENT_SHARED_SECRET`) env, it accepts any
  non-empty header and warns, instead of hard-failing inbound server
  calls. Strict mode kicks in as soon as either env is set.
- Agent Identity Plumbing. Real `hostname` and primary-NIC `mac_address`
  are appended to `OS_INFO` (`|HOST=...|MAC=...`) at send-time, parsed
  back out by the ingest layer and persisted into the `agent_info`
  schema via idempotent `ALTER TABLE`.
- Visual SOAR Playbooks. Create, validate and execute multi-node
  playbooks. Run rows go into `playbook_runs` with status (`running`,
  `success`, `failed`, `cancelled`) computed from per-node results.
  Schema matches `init.sql` (agent_name and playbook_name required).
- Asset and Inventory. Hardware, software packages, network connections,
  open ports, FIM, Docker container inventory and events.
- AI Pulse and Per-Agent AI Analysis. `/api/ai-insights/all` (cross-agent
  feed) and `/<agent>/ai_insights` (per-agent tab). Insights are stored
  with raw `source_data` so the UI's View Source modal can show the
  exact log the AI inspected.

### 2.2 Ingestion Engine (`server.py`, port 5001)

- Async TCP. Streams from sensors, multi-frame protocol:
  `agent_name | public_ip | os_info | filename | data`.
- Dynamic Provisioning. Unknown agents trigger
  `create_agent_db_if_not_exists` and table bootstrap.
- Multiplexing. After persisting a row, ships SIEM logs and alerts into
  RabbitMQ for AI triage and indexes them in OpenSearch.
- Identity Tail Parsing. `_parse_os_info_tail` recovers `hostname` and
  `mac_address` from the `OS_INFO` field without touching the wire
  format.

### 2.3 Server-Side Vulnerability Scanner (`scanners/vuln.py`)

The OSV scan workload was lifted off the agent to keep endpoints quiet.

```
agent.packages (encrypted)
       |
       v
Fernet decrypt --> OSV batch /v1/querybatch
                          |
                          v  (per CVE id, cached in-process)
                   GET /v1/vulns/<id>  --> summary + reference URL
                          |
                          v
       INSERT plaintext into <agent>_db.vulnerabilities_report
```

Key behaviours:

- Endpoint resolution at boot via `resolve_osv_endpoint()`. Modes via
  `OSV_MODE` env:
  - `auto`: probe `OSV_PUBLIC_URL` (default `https://api.osv.dev`); fall
    back to `OSV_MIRROR_URL` if the public host is unreachable. The
    air-gap-friendly default.
  - `online`: force public.
  - `mirror`: force mirror (fail-closed if unset).
- Ecosystem detection maps OS strings to OSV ecosystems (`Debian`,
  `RPM`, `Alpine`, `Windows` to `NuGet`). Generic `Linux` (including
  WSL) is fingerprinted from package version patterns and defaults to
  Debian.
- Hydration. OSV batch only returns CVE IDs; a follow-up
  `/v1/vulns/<id>` per unique CVE fills `summary` and `details_url`. A
  process-level cache prevents re-fetching across agents or scans.
- Backfill. Each scan runs `_backfill_missing_summaries` first to repair
  any rows from earlier deployments that were inserted before hydration
  existed.
- Cadence. `periodic_vuln_scan` runs every `VULN_SCAN_INTERVAL` (default
  1800 s). Manual `POST /<agent>/vulns/scan` from the UI's Scan Now
  button.

### 2.4 Remote Desktop / Screen Streaming

The original TCP-VNC plus TightVNC dependency was replaced with a
self-contained JPEG frame stream:

```
Browser <--ws--> /vnc-proxy/<agent>  (server)
                  | websockets.connect(...)
                  v
            agent /screen/ws  --> mss screen capture, Pillow JPEG, binary frame
```

- Agent endpoint `/screen/ws`. Auth via `X-Agent-Key` header or `?key=`
  query (browsers cannot set custom headers on WS upgrade). Tunable
  params: `?fps=10&q=60&w=1280` (5-30 fps, 20-95 quality, 320-2560 px).
- Server proxy `/vnc-proxy/<agent>`. Picks the agent's enrolled key from
  `agent_identities`, forwards browser query params and pipes both
  directions over `websockets`.
- Frontend `VncViewer.tsx`. Plain `WebSocket` plus Blob to `<img>`
  rendering. Live FPS display, on-the-fly FPS / quality dropdowns,
  `URL.revokeObjectURL` keeps memory bounded.
- No TightVNC install or VNC client required.

### 2.5 Authentication

Identity comes from a server-side session, never from a client-supplied
value.

```
POST /login  ──►  bcrypt / LDAP bind
                      │
                      ▼
              userdb.sessions row          Set-Cookie: sentora_session=<token>
              (stores SHA-256 only)  ◄──   HttpOnly; SameSite=Lax; Path=/
                      │
                      ▼
        @app.on_request authenticate  ──►  request.ctx.user
```

**Storage.** Only `sha256(token)` is persisted, so a dump of the `sessions`
table yields nothing presentable. Two expiry clocks are enforced in SQL
rather than in Python, so an expired session cannot be returned even if a
caller forgets to check: `SESSION_IDLE_MINUTES` (sliding, default 60) and
`SESSION_ABSOLUTE_HOURS` (hard ceiling, default 12). `last_seen_at` is only
rewritten once a minute so a polling dashboard does not become one UPDATE
per request.

**Deny-by-default.** The `authenticate` middleware runs after routing, so
`request.route` names the handler. Everything is rejected without a session
except an explicit set: the login endpoint, the SPA shell, static assets, and
the agent-facing endpoints (which carry `X-Agent-Key` or an enrolment token).

**`X-User-ID`.** Still sent by the frontend, but no longer identity — the
server validates it against the session and a mismatch is a hard 401. Since
browsers cannot attach custom headers to cross-site requests without a CORS
preflight, requiring it on state-changing requests backs up `SameSite` as a
second CSRF control.

**Permission enforcement.** `@require_permission(...)` records its
requirement in a registry keyed by the handler's `__qualname__`, which
`@wraps` preserves. The middleware enforces from that registry, so protection
applies regardless of which side of `@app.route` the decorator sits on.

> This matters because `app.route` registers the *bare* handler at decoration
> time. When `@require_permission` sat above it, the wrapper it returned was
> built and never called — 85 routes looked guarded in the source and were
> not, with no runtime symptom. The registry removes the failure mode rather
> than the individual instances.

A boot-time self-check prints the tally, because the original bug was
invisible precisely because nothing ever inspected the result:

```
[Auth] Routes: <n> permission-gated, <n> session-only, <n> public.
```

**Revocation.** Sessions are killed on password change, admin password reset,
role change and account deletion. Without that, an admin can revoke access
and still leave the browser tab working until the idle timeout.

**LDAP.** A successful bind provisions a local `users` row on the fly, so
sessions, RBAC and audit attribution all key off the same integer id as local
accounts.

### 2.6 Agent Config Validation (`core/config_validation.py`)

`POST /<agent>/config/<cfg_type>` forwarded the request body to the sensor
unread. A typo therefore reached the agent, where the only symptom was the
agent quietly not detecting things any more.

Three layers, cheapest first:

| Layer | Catches |
| :--- | :--- |
| Parse | YAML syntax, with the line and column YAML itself reports |
| Shape | A `log_paths` file that lost its root key — valid YAML, useless |
| **Regex compilation** | The layer that matters |

An invalid regex is perfectly valid YAML and silently disables the category
containing it, so a syntax-only check would push it straight to the endpoint.
Per-pattern line numbers come from `yaml.compose()`, which keeps the source
marks `safe_load()` discards. Comments inside block scalars are literal
content, not YAML comments, and are skipped the way the agent skips them.

Errors block the push and are audit-logged; warnings (unknown regex flags,
relative paths) are surfaced but do not block. `POST
/<agent>/config/<cfg_type>/validate` lints without pushing, which is what the
editor calls as you type — the rules are not duplicated in the browser,
because two implementations drift and the browser's copy is the one operators
would trust.

### 2.7 Threat Intel Feeds (`core/threat_feeds.py`)

Populates `sentora_hub.threat_intel` hourly from abuse.ch: Feodo Tracker
(botnet C2 addresses), ThreatFox (mixed IoCs with a confidence score) and
URLhaus (malware-distributing URLs).

Parsing is separated from the HTTP call so feed shapes are testable without a
network. Every parser is defensive: a feed that changes its schema yields
fewer indicators, never an exception that kills the refresh loop.

- **Staleness.** Indicators carry `last_seen` and are pruned after
  `THREAT_INTEL_STALE_DAYS` (30). An address that hosted a C2 last quarter
  usually belongs to someone else now.
- **Ports stripped** from ThreatFox IP indicators — `1.2.3.4:443` would never
  equal an observed address.
- **Offline URLhaus entries skipped.** History, not live indicators.
- **Per-feed cap** (`THREAT_INTEL_MAX_PER_FEED`, 2000) because the table is
  read on the alert path.
- **One failing feed does not stop the others**; the failure is reported.
- **`THREAT_INTEL_MODE=off`** makes no outbound request at all, and every feed
  URL is overridable for an internal mirror — the same shape as `OSV_MODE`.

> This replaced a function that inserted three hardcoded rows every hour and
> said so in its own docstring. One of them was the SHA-256 of the empty
> string, marked CRITICAL malware: had anything matched against this table,
> every empty file on every endpoint would have been flagged. Those rows are
> purged from existing databases at startup, matched on `source` as well as
> value so an operator who added one of those addresses by hand keeps it.

### 2.8 Fleet Exposure (`/api/exposure/report`)

Counts unpatched packages and file-integrity events across agent databases,
per agent, worst first. FIM is split into `changed` / `new` / `deleted`
rather than summed — twelve files changed and twelve files deleted are very
different mornings.

Coverage is explicit: `complete: false` when an agent could not be read, and
the dashboard panel labels the figure partial. A total over half the fleet is
not a fleet total.

There is deliberately no score. This was `/api/compliance/report` (still
routed, for compatibility) and returned `100 - vulns*2 - fim*5`. That maps to
no framework so it cannot be shown to an auditor, does not scale with fleet
size, and pins to zero at fifty vulnerabilities — an ordinary state. Severity
grading is absent for the same reason: `vulnerabilities_report` has no
severity column and its fields are encrypted at rest, so any grade would have
to be invented here.

---

## 3. AI Intelligence Pipeline

### 3.1 Triple-Worker Fleet (`ai_worker.py`)

The same image runs in three roles, selected by `WORKER_TYPE` env:

| Worker | Queue | Role |
| :--- | :--- | :--- |
| Automation | `ai_automation_queue` | Continuous triage of incoming logs. Strict JSON verdict prompt (`CRITICAL`, `SUSPICIOUS`, `NOT_CRITICAL`). Every verdict is saved; what varies is whether it is shown to an analyst or filed quietly — see 3.1.1. |
| Manual | `ai_manual_queue` | Operator-initiated deep scans. Always saves something (user explicitly requested). Output includes MITRE techniques, IOCs, next steps. |
| Defensive | `ai_soar_queue` | Recommends a SOAR action and autonomously dispatches it when verdict is `ACT`, confidence is at or above `AI_AUTO_ACT_CONF` (default 0.75), and the action is on the safe-list. |

### 3.1.1 What Reaches an Analyst (`ai/gating.py`, `ai/criteria.py`)

The automation worker files every verdict. `Realtime_<table>` is shown;
`Reviewed_<table>` is kept and quiet. One function decides — `gating.surfaces`
— and both the worker and the eval harness call it, because when they were
separate copies the harness reported 40% escalation recall on runs where
production surfaced nothing at all.

**The rule: severity CRITICAL or HIGH, and a criterion the log was checked
against and found to support. Model confidence is not consulted.**

That is not a stylistic preference. Two rounds of measurement removed it:

- Six CRITICAL verdicts were held at confidence 0.50 — an LSASS dump, a SAM
  hive export, shadow copies being deleted — and a seventh at 0.00. Every
  benign case also came back at 0.50, so the number separated nothing.
- Moving the floor changes nothing between 0.60 and 0.90; the model emits 0.50
  or 0.90 and almost nothing between.
- Over 29 cases, every attack that surfaced already had a verified criterion.
  Both false alarms that reached an analyst got there on confidence alone —
  SUSPICIOUS / CRITICAL / 0.80 on this platform's own containers restarting.

`AI_CRIT_CONF` and `AI_SUS_CONF` are still read, only so that a non-default
value logs a warning saying it no longer applies.

**`ai/criteria.py` is what makes this possible.** The model proposes a
criterion; the code decides whether the log supports it, by looking for that
criterion's literal markers. It works in both directions — it refuses a
claimed criterion the log does not contain, corrects one the model filed
under the wrong letter, and finds one the model missed entirely. Base64 on a
command line is decoded (UTF-16LE and UTF-8) before searching, because
`-EncodedCommand` is exactly where a payload goes to stop being searchable,
and the question worth asking is what it does rather than that it was
encoded.

**On the model's SUSPICIOUS label:** precision 0.00, recall 0.00 over that
corpus. It uses the top of the scale and not the middle. Since a supported
criterion is promoted to CRITICAL, a SUSPICIOUS verdict never carries verified
evidence and never surfaces. The middle of the scale is real and comes from
layers that can be checked — a Sigma rule at MEDIUM, or a correlation window
(4.1.2) — not from asking a 3B model to feel uncertain.

Threat-intel matches surface regardless, and are handled by the caller.

### 3.2 Defensive Auto-Action Allow-List

Only these actions are auto-dispatched without human review:

```
BLOCK_IP, KILL_PROCESS, RESTART_SERVICE, ISOLATE_HOST, DISABLE_USER,
QUARANTINE_FILE, SUSPEND_PROCESS, LOGOFF_USER,
CONTAINER_ISOLATE, CONTAINER_STOP, CONTAINER_KILL
```

Anything else (for example `DELETE_FILE` or arbitrary command exec) is
downgraded to an advisory insight only. Auto-dispatched insights are
tagged with the `[AI DEFENSIVE ADVICE] | AUTO-DISPATCHED <action>` marker
so the SOAR Hub shows a red AUTO badge.

Dispatch path: `ai/utils.queue_soar_action` inserts a `pending` row into
the agent's `automations` table; the agent picks it up on the next poll.
If the agent inbound port is unreachable the polling fallback still
delivers it.

### 3.3 Shadow Mode

Set `AI_SHADOW_MODE=1` on the `ai-worker-defensive` container (or in the
shared `.env`) to suspend autonomous dispatch. When a verdict satisfies
all the conditions that would normally trigger `queue_soar_action`
(`verdict=ACT`, `confidence >= AI_AUTO_ACT_CONF`, action on the
allow-list, valid target), the worker writes a **proposal** instead:

- `source_file = 'AI_DEFENSIVE_SHADOW'`
- `shadow_status = 'pending'`
- `proposed_action`, `proposed_target` populated with what would have
  fired
- `critical_summary` carries a `SHADOW-PROPOSED <ACTION>` marker

The proposal is then routed to the SOAR Hub > Shadow Queue tab. The
operator either:

| Decision | Endpoint | Side-effects |
| :--- | :--- | :--- |
| Approve | `POST /<agent>/shadow/<id>/approve` (perm: `manage_soar`) | Calls `call_agent_soar(action, target)`. Updates row to `shadow_status='approved'` with `shadow_decided_at`, `shadow_decided_by`. |
| Reject | `POST /<agent>/shadow/<id>/reject` (perm: `manage_soar`) | Updates row to `shadow_status='rejected'`. Optional `note` recorded in `critical_summary`. |

Listing endpoints (perm: `read_telemetry`):

- `GET /<agent>/shadow/pending`
- `GET /shadow/pending` (cross-agent aggregator)

Proposals have **no expiry**. They sit in the pending list until the
operator decides. This is intentional: with autonomy paused, the model
must not silently "lose" decisions because nobody noticed in time.

Other defensive verdicts (advice, monitor) are unaffected by shadow mode
and still produce `AI_DEFENSIVE_ADVICE` / `AI_DEFENSIVE_MONITOR`
insights as usual. Only the auto-dispatchable subset gets staged.

Typical lifecycle:

```
events_alert  →  ai_soar_queue  →  defensive worker
                                       │
                       AI_SHADOW_MODE=1 ↓
                                  proposal row (pending)
                                       │
                            operator approves
                                       ↓
                       call_agent_soar  →  automations table  →  agent poll  →  executed
```

### 3.4 Insight Storage Schema

`ai_analysis_results` columns:

- `id`, `timestamp`, `created_at`
- `source_file`. Worker tag (`Realtime_<table>`, `Manual_<table>`,
  `AI_DEFENSIVE_AUTO`, `AI_DEFENSIVE_ADVICE`, `AI_DEFENSIVE_MONITOR`,
  `AI_DEFENSIVE_SHADOW`).
- `critical_summary`. One-line tagged summary used by the UI.
- `source_data` LONGTEXT. Raw log JSON the AI actually saw. Surfaced by
  the View Source modal in the per-agent AI Analysis tab. Idempotent
  `ALTER TABLE` adds the column on legacy DBs.
- `proposed_action`, `proposed_target`. Populated for shadow proposals
  (Section 3.3); NULL otherwise.
- `shadow_status`. `'pending' | 'approved' | 'rejected' | NULL`.
- `shadow_decided_at`, `shadow_decided_by`. Audit trail of who approved
  or rejected a shadow proposal and when.

### 3.5 Threat-Intel Enrichment (`ai/intel.py`)

Optional enrichment of LLM verdicts using public reputation services:

- AlienVault OTX: IPv4 reputation (requires `OTX_API_KEY`).
- VirusTotal: file-hash reputation (requires `VT_API_KEY`).

Both are no-ops when their API key is unset, so the agent ships
air-gap-friendly out of the box. A confirmed external indicator hit can
override a low-confidence `NOT_CRITICAL` LLM verdict.

Not to be confused with the indicator feeds in
[§2.7](#27-threat-intel-feeds-corethreat_feedspy): this module enriches a
single verdict on demand by querying an external API, while the feeds
maintain a local table of known-bad indicators. Different mechanisms, both
optional, and either can run without the other.

---

## 4. Agent Architecture

### 4.1 Sensor Capabilities

- SIEM Engine. Hooks Windows Event Log / Linux syslog / journald.
  Every collection path runs Sigma first and falls back to the
  `rules.yaml` regex list for events no Sigma rule addresses. See 4.1.1.
- FIM (watchdog). In-memory hash comparison for sensitive paths.
- Docker Monitor. Container inventory snapshots (60 s) plus live event
  stream (`docker_containers` and `siem_events` filtered by
  `DockerMonitor` source).
- Inventory. `psutil`-based hardware, software, network, process and
  disk telemetry.
- Screen Streaming. `mss` plus `Pillow` JPEG WebSocket (see 2.4). The
  agent no longer runs the OSV vuln scan locally; that was moved
  server-side.

### 4.1.1 Sigma Detection (`core/sigma.py`, `core/sigma_loader.py`)

Sigma rules are compiled in process to a predicate over an event dict. Not
via pysigma: that compiles Sigma to *query languages* — Splunk SPL,
Elasticsearch DSL — and has no backend answering "does this dict match",
which is the only question an agent has. It also brings a large dependency
tree to something running on every endpoint.

**An unsupported construct raises rather than compiling to false.** A rule
that silently never fires is worse than one that fails to load: the second is
visible on the next start, the first is discovered after an intrusion.
Rejected rules are named with their reason and contribute no ATT&CK coverage.

Supported modifiers: `contains`, `startswith`, `endswith`, `all`, `re`,
`cidr`, `windash`, `base64`, `base64offset`, and the encoding modifiers
`utf16le` / `utf16be` / `utf16` / `wide`. Conditions support `and` / `or` /
`not`, parentheses, `1 of x*` and `all of them`.

The encoding modifiers matter more than they look. PowerShell's
`-EncodedCommand` takes UTF-16LE, so a needle encoded as UTF-8 and base64'd
cannot appear in that payload at all — without them the detection compiles,
reports as covered, and matches nothing. `base64offset` emits the needle at
each of the three byte alignments, trimmed at *both* ends, because base64
packs three bytes into four characters and the first and last groups are
shared with whatever surrounds the needle.

**Field mapping.** Sigma addresses `CommandLine`, `Image`, `TargetObject`.
Windows supplies `StringInserts`, a positional array whose meaning depends on
the event ID, so `WINDOWS_FIELDS` names them for the IDs this agent collects
(4688, 4624, 4625, 4648, 4672, 4698, 4699, 4720, 4657, 4104, 7045, 1102).
`SYSMON_FIELDS` is a separate table selected by channel: Sysmon's IDs are
small numbers — 1, 11, 13 — that mean something entirely different on the
System and Application channels, and reading a System event through Sysmon's
layout would put arbitrary text into `Image` and invent evidence for whichever
rule then matched.

An unmapped event ID is not dropped; its inserts stay reachable and the
assembled text is available as `Message`. `unmapped_event_ids()` reports which
IDs are arriving without a mapping rather than leaving the gap silent.

**Per-platform capability.** The three collection paths are not equal, and the
difference is a property of the logs rather than of the rules:

| Path | Fields available | Field-matching rules |
| --- | --- | --- |
| Windows Event Log | full, via `WINDOWS_FIELDS` | yes |
| systemd journal | process, command line, unit | yes |
| plain log files | parsed from the line — see below | partially |

`text_event_fields` returned `Message` and nothing else at first, on the
reasoning that parsing every log format is not worth it. That was half right:
parsing *every* format is not worth it, and parsing the handful carrying
authentication and command execution is — it decides whether a host on rsyslog
gets field rules and correlation, or neither.

sshd, sudo, PAM, cron and auditd each write in a fixed shape, so
`SYSLOG_PATTERNS` pulls `TargetUserName`, `IpAddress`, `CommandLine` and
`Image` out of them, plus a synthesised `AuthResult` — Linux has no
equivalent of EventID 4624/4625, and correlation needs something stabler to
key on than "does this text contain the word failed".

Fields the line does not contain stay absent rather than being guessed at. A
wrong `Image` is worse than a missing one: it matches rules the event has
nothing to do with.

**ATT&CK coverage** is read from the loaded rules' own `tags`, so there is no
mapping table to keep current, and a rule that failed to load cannot claim
coverage it is not providing.

### 4.1.2 Correlation (`core/correlation.py`)

Sigma matches a rule against one event dict. It cannot express "count
distinct users where the source is the same, within a window", so an entire
class of detection was invisible: password spray, brute force, and the one
that matters most — repeated failures followed by a success.

Not Sigma's own `correlation:` spec, which arrived in 2024 and would mean a
stateful rule engine buffering events per rule and resolving references
between them. That is a lot of machinery on something running on every
endpoint, for four shapes that are few and specific enough to write directly.

Three properties are load-bearing:

- **Fires once per window, not once per event.** A sustained spray produces
  one detection, then silence for the cooldown. The same bug class had the
  defensive sweep re-queueing 4,919 duplicate alerts: a condition that stays
  true keeps producing work unless something says "already told you".
- **Bounded memory.** Group keys are attacker-supplied — a username, a source
  address. Timestamps outside the window are dropped on every observation and
  the number of tracked groups is capped with least-recently-seen eviction.
- **One predicate per platform-independent concept.** `_is_failed_logon` is
  EventID 4625 *or* the `AuthResult` field synthesised from Linux auth lines.
  A spray is the same shape wherever it happens; two rule sets is how the
  thresholds drift apart.

A window that fires becomes an **event of its own** rather than relabelling
the event that completed it — the fifth failed logon is no more interesting
than the first, and marking it CRITICAL would show an analyst a routine 4625
with nothing explaining why.

**Two engines, because two vantage points see different attacks.**

`default_engine()` runs on the agent, where an attack against one machine is
visible in full. It is per host, and that leaves a gap: one account sprayed
across fifty machines, once each, is invisible to every agent, because none of
them sees more than one event. That is the *more* competent attack — wide and
shallow stays under both per-account lockout and per-host thresholds.

`fleet_engine()` runs in `server.py`'s ingest path, where every agent's events
pass through one process, and counts distinct **hosts** instead of distinct
accounts. Its windows are wider (30 minutes rather than 5): walking an estate
takes longer than walking a user list, and being slow is the point of the
technique.

The server only has the agent's flattened message, so
`sigma_loader.agent_event_fields` puts the named fields back. That is
reversible because the flattening is a positional join in our own format on
both ends — `' | '.join(StringInserts)` — rather than a guess at somebody
else's.

A fired fleet window is written as an `events_alert` row **and explicitly
published to the AI queue**. Rows written from inside the ingest loop are not
items that loop iterates, so without that publish a correlation finding landed
in the database, appeared in the alerts view, and never became an AI insight.

`ai_worker` surfaces a correlated finding regardless of the model's verdict,
the same way a threat-intel match does — and it has to, because the gate asks
whether the log contains a criterion's markers and the summary of a fired
window contains none by construction.

**Known wart:** a cross-host finding is stored in the database of whichever
agent's event completed the window, which is arbitrary. It is the right
finding filed in a slightly wrong place; an analyst looking at a different
host in that same spray will not see it there.

### 4.2 Tables Synced From Agent to Server

```python
TABLES = [
  'critical_files', 'portscan_result', 'resource_usage', 'packages',
  'vulnerabilities_report', 'siem_events', 'events_alert', 'soar_actions',
  'disk_usage', 'fim_data', 'registry_logs', 'network_connections',
  'process_events', 'hardware_inventory', 'security_audit',
  'docker_containers',
]
```

### 4.3 SOAR Enforcement

Agents poll `/automations/pending` (returns empty list gracefully if the
table does not exist yet) and execute compiled actions:

- Network: `block_ip`, `unblock_ip`, `disable_interface`, `flush_dns`
- Process: `kill_process`, `dump_process`, `restart_service`,
  `suspend_process`
- System / User: `disable_user`, `enable_user`, `lock_machine`,
  `logoff_user`, `clear_temp`
- File: `quarantine_file`, `tail_log`
- Container: `container_kill`, `container_stop`, `container_isolate`

Results are reported back via `/automations/<task_id>/report`.

### 4.4 End-to-End Incident Workflow

1. Detection. Agent matches a SIEM rule on a brute-force pattern.
   Inserts into local `siem_events` and `events_alert`; sync ships rows
   to `<agent>_db`.
2. Ingestion. `server.py` persists to MySQL, indexes into OpenSearch and
   publishes to RabbitMQ.
3. Triage. Automation worker classifies as `CRITICAL` or `SUSPICIOUS`.
   Threat-intel cross-check on extracted IPs and hashes.
4. Defensive Decision. Defensive worker proposes
   `BLOCK_IP <attacker_ip>`. Confidence at or above 0.75 plus a
   safe-list match triggers autonomous dispatch.
5. Action Dispatch. `queue_soar_action` writes a `pending` row in
   `<agent>_db.automations`. The server's direct-push attempt to
   `/soar/execute` runs in parallel; either path delivers.
6. Enforcement. Agent applies `iptables -A INPUT -s <ip> -j DROP` (or
   platform equivalent), records the result in `soar_actions`.
7. UI Update. SOAR Hub stat cards, AI Pulse, and the per-agent AI
   Analysis tab all refresh on the same `/api/ai-insights/all` cycle
   (30 s).

---

## 5. Air-Gap Deployment

| Surface | Behaviour |
| :--- | :--- |
| Frontend fonts | Bundled locally via `@fontsource/*`. No CDN call. |
| OSV scanner | `OSV_MODE=auto` probes public, falls back to `OSV_MIRROR_URL` (or no-ops if neither is reachable). `OSV_MODE=mirror` forces internal-only. |
| Ollama | Runs in the same Compose stack on `:11434`. No external API. |
| Threat intel enrichment (OTX / VT) | No-op when `OTX_API_KEY` / `VT_API_KEY` are unset. |
| Threat intel feeds | `THREAT_INTEL_MODE=off` makes no request at all. Each feed URL is overridable (`THREAT_INTEL_FEODO_URL` etc.) to serve them from an internal mirror. |
| Outbound HTTP proxy | Disabled unless `PROXY_ALLOWED_HOSTS` names destinations. |
| Build | Image artifacts can be `docker save`d on a connected box and `docker load`ed on the air-gap host. |

---

## 6. Operational Notes

- `DB_PASSWORD`, `RABBITMQ_PASSWORD` and `FERNET_KEY` are required — compose
  refuses to start without the first two, the app without the third.
  `scripts/init_secrets.py` generates what it can; it never overwrites an
  existing value, because `FERNET_KEY` has no rotation path and a second run
  that regenerated it would make every encrypted column unreadable.
- Only `app` (:8000) and `ingest` (:5001) listen on all interfaces. The rest
  bind to `BIND_ADDR` (default loopback) because none of them authenticate:
  OpenSearch runs with `DISABLE_SECURITY_PLUGIN` and Dashboards is an
  unauthenticated view of every collected log.
- The app container runs as a non-root user (uid 10001). `/app/data` is the
  only path written at runtime and is backed by the `sentora_data` volume —
  without it, the agent Fernet key was regenerated on every recreate,
  silently orphaning previously encrypted telemetry.
- The MySQL pool caps per-DB at 10 concurrent connections; total fleet
  is bounded by `_POOL_MAXSIZE` times the number of agent DBs.
- Sanic worker count is set by `WORKERS` env (compose default `1`).
  Background tasks (`periodic_vuln_scan`, `periodic_threat_intel_update`,
  `periodic_critical_alerts_check`, `periodic_soar_automation_check`,
  `periodic_session_purge`) only run on worker `0-0` to avoid duplication.
- All UI strings and operator-facing log lines are English-only as of
  2026-04-30. Internal docstrings and comments may still be Turkish in
  legacy modules.

---

## 7. Verification

```bash
pytest -ra                                   # no MySQL or RabbitMQ needed
python -m compileall -q app.py core security
cd frontend && npx tsc --noEmit && npm run build && cd ..
```

### 7.1 Measuring the Model (`scripts/run_eval.py`)

```bash
python scripts/build_attack_corpus.py
python scripts/run_eval.py --corpus evals/corpus_attacks.jsonl --save evals/runs/x.json
python scripts/run_eval.py --corpus evals/corpus_attacks.jsonl --no-cache
```

The report is deliberately noisy about what it does **not** prove, because
every number here has been misread at least once:

| Line | What it means |
| :--- | :--- |
| Escalation recall | Of events that should escalate, how many the model flagged |
| Escalation precision | Of its escalations, how many deserved it — scores the *verdict* |
| Reaches an analyst | Of those, how many production would actually show — scores the *product* |
| False alarms shown | Benign events that get past the gate — the ones that cost attention |
| Positives | How many were hand-written, and how many are real |
| Resolution | How much one case flipping moves recall |

**Recall is an upper bound.** Every positive is written from documented
technique behaviour — nobody has run mimikatz on this estate — so these are
the loud versions of each technique and a real intruder is quieter. A miss is
real evidence; a hit is weak evidence. The report prints this on every run
rather than leaving it in a README.

**Precision and "false alarms shown" are different claims,** in the same way
recall and "reaches an analyst" are. On one 29-case run the model raised 12
unwarranted escalations and 2 of them surfaced. Quoting 43% precision and
stopping there describes a console nobody has.

**Read every figure with the resolution.** Two runs of the identical corpus at
temperature 0 returned 50% and 60%: llama.cpp on CPU reduces across threads in
a non-deterministic order and a near-tie flips. A difference smaller than
twice the resolution is noise.

**The replay cache** stores the raw reply keyed on the model *and the prompt
text*. Keying on the prompt is what makes it safe — `ai.utils` has a
production cache keyed on the log alone, which the harness deliberately never
uses, because a reply from an older prompt would make a rewritten one look
identical to the one it replaced. What is cached is the reply before
`criteria.apply` and before the gate, so criterion and gating changes are
scored fresh: re-scoring drops from ~20 minutes to ~2 seconds. A fully cached
run says so instead of passing as a fresh measurement; `--no-cache` asks the
model again.

**Real positives** need telemetry a machine produced.
`scripts/generate_telemetry.py` performs the harmless action that emits the
same event as a technique — `vssadmin list shadows` rather than deleting them,
a scheduled task created and removed, a real `-EncodedCommand` whose payload
prints the date. It marks which entries exercise a rule end to end and which
only exercise collection, and refuses the ones with no harmless version (an
actual LSASS dump, actually clearing the Security log), naming them as the gap
rather than omitting them. Collect the results with
`build_eval_corpus.py` + `label_eval_corpus.py`; the labelled rows carry
`constructed=false`.

With the stack up, `scripts/api_smoke_test.py` enumerates every route from
`app.py` via AST — so the list cannot drift from the code — and exercises it
twice:

1. **Unauthenticated, every route and verb.** Safe for all of them because
   the middleware rejects before the handler runs. A protected route
   answering 2xx here is an auth bypass and fails the run.
2. **Authenticated, read-only verbs** plus a small allow list of write
   endpoints that validate before acting. A live session is never used to
   send a write that would act, so the test cannot be the thing that
   dispatches a SOAR action or drops a database.

The write list is an allow list on purpose: with a deny list, one missing
entry is `DELETE /databases/userdb`.

**Pass 3: authenticated with no permissions.** A temporary account holding a
role with an empty permission set calls every write route and must be refused.
This closes the half of the gap that can be closed safely: pass 1 proves a
route refuses an anonymous caller, which does **not** prove the permission it
demands is the right one — a SOAR dispatch gated on `read_telemetry` passes
pass 1 exactly like one gated on `manage_soar`. That is privilege escalation
between roles, and nothing was testing for it.

Safe to run where pass 2 is not, because a 403 comes from the permission
middleware *before the handler executes* — nothing is dispatched, deleted or
truncated. Two further guards: the payloads name agents and ids that do not
exist, so a wrongly-permissive route acts on nothing; and anything answering
2xx is reported as a bypass and fails the run. The account and role are
removed in a `finally`, including on early return.

**Known gap.** Roughly 60 write-verb routes — SOAR dispatch, playbook
execution, agent restart, user deletion, table truncation — are checked
anonymously and, since pass 3, with an unprivileged session — but never with a
session that *should* succeed. Widening the allow list is not the fix. Closing
it properly needs a disposable database and a fake agent endpoint that absorbs
SOAR calls, so `block_ip` can be exercised for real without touching a
machine. The summary output names what remains rather than folding it into a
count.

---

Document version: 5.0. Last revised against source HEAD on 2026-08-21.
