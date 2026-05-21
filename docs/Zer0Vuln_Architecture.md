# Zer0Vuln Architecture and Features

This document is a technical breakdown of the Zer0Vuln platform: feature
set, container topology, data flow and component-level workflows derived
from the live source.

---

## 1. High-Level System Topography

Zer0Vuln operates on a distributed hub-and-spoke model designed for
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
- Zer0Vuln Agent (Sensor). Cross-platform (Windows and Linux) sensor that
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
Zer0Vuln-Server/
├── app.py            entry: Sanic API + SPA
├── server.py         entry: TCP ingest
├── ai_worker.py      entry: AI worker fleet (WORKER_TYPE env selects role)
├── ai/
│   ├── utils.py      LLM call helpers, AI cache, SOAR action queueing
│   └── intel.py      AlienVault OTX + VirusTotal indicator enrichment
├── core/
│   ├── mq.py         RabbitMQ publisher
│   └── opensearch.py OpenSearch index/search helpers
├── scanners/
│   └── vuln.py       Server-side OSV vulnerability scanner
├── modules/db.py     (legacy postgres helper, unused, kept for back-compat)
└── frontend/         React SPA source
```

Entry-point file names are kept at the root so `docker-compose.yaml`
commands (`python app.py`, `python server.py`, `python ai_worker.py`)
remain unchanged.

---

## 2. Server-Side Infrastructure and Features

### 2.1 Management API (`app.py`, port 8000)

- RBAC and IAM. Multi-tier roles, per-permission gating via
  `@require_permission`, optional LDAP/AD fallback. Bcrypt-hashed
  credentials.
- Audit Logging. `audit_logs` table records every privileged action
  (who, from, action, resource, details, IP, timestamp). Surfaced in the
  UI with an expandable per-row detail modal.
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

---

## 3. AI Intelligence Pipeline

### 3.1 Triple-Worker Fleet (`ai_worker.py`)

The same image runs in three roles, selected by `WORKER_TYPE` env:

| Worker | Queue | Role |
| :--- | :--- | :--- |
| Automation | `ai_automation_queue` | Continuous triage of incoming logs. Strict JSON verdict prompt (`CRITICAL`, `SUSPICIOUS`, `NOT_CRITICAL` plus confidence). Saves only high-confidence findings or threat-intel-confirmed hits. |
| Manual | `ai_manual_queue` | Operator-initiated deep scans. Always saves something (user explicitly requested). Output includes MITRE techniques, IOCs, next steps. |
| Defensive | `ai_soar_queue` | Recommends a SOAR action and autonomously dispatches it when verdict is `ACT`, confidence is at or above `AI_AUTO_ACT_CONF` (default 0.75), and the action is on the safe-list. |

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

---

## 4. Agent Architecture

### 4.1 Sensor Capabilities

- SIEM Engine. Hooks Windows Event Log / Linux syslog / journald.
  `rules.yaml` controls regex categorization and severity tagging.
- FIM (watchdog). In-memory hash comparison for sensitive paths.
- Docker Monitor. Container inventory snapshots (60 s) plus live event
  stream (`docker_containers` and `siem_events` filtered by
  `DockerMonitor` source).
- Inventory. `psutil`-based hardware, software, network, process and
  disk telemetry.
- Screen Streaming. `mss` plus `Pillow` JPEG WebSocket (see 2.4). The
  agent no longer runs the OSV vuln scan locally; that was moved
  server-side.

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
| Threat intel (OTX / VT) | No-op when `OTX_API_KEY` or `VT_API_KEY` is unset. |
| Periodic threat-intel feed | Currently mock data, no external call. |
| Build | Image artifacts can be `docker save`d on a connected box and `docker load`ed on the air-gap host. |

---

## 6. Operational Notes

- Default credentials ship in `.env.example` and must be rotated before
  production.
- The MySQL pool caps per-DB at 10 concurrent connections; total fleet
  is bounded by `_POOL_MAXSIZE` times the number of agent DBs.
- Sanic worker count is set by `WORKERS` env (compose default `1`).
  Background tasks (`periodic_vuln_scan`,
  `periodic_threat_intel_update`, `periodic_critical_alerts_check`,
  `periodic_soar_automation_check`) only run on worker `0-0` to avoid
  duplication.
- All UI strings and operator-facing log lines are English-only as of
  2026-04-30. Internal docstrings and comments may still be Turkish in
  legacy modules.

---

Document version: 4.0. Last revised against source HEAD on 2026-05-02.
