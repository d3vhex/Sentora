# Sentora Progress Report

This document summarises the technical work and security improvements
made to the Sentora platform, newest first.

---

## 2026-08 — Authentication, endpoint audit, honest metrics

### Authentication rebuilt

The UI had no real authentication. Login returned a plain user object, the
frontend stored `userId` in `localStorage`, and every request asserted
identity in an `X-User-ID` header the server trusted verbatim:

```bash
curl -H "X-User-ID: 1" http://server:8000/users   # full admin, no login
```

On a platform that can `ISOLATE_HOST`, `BLOCK_IP` and `KILL_PROCESS` on every
enrolled endpoint, that was unauthenticated remote command execution across
the fleet.

Replaced with server-side sessions (`userdb.sessions`, SHA-256 of the token
only, idle + absolute expiry enforced in SQL). `X-User-ID` is retained but
validated against the session, which also backs up `SameSite` as a CSRF
control. Every route is deny-by-default. Sessions are revoked on password
change, admin reset, role change and account deletion.

### RBAC was decorative

The claim in the older section below — "more than 40 API routes are now
guarded by `@require_permission`" — was not true in practice. The decorator
sat **above** `@app.route` on 85 routes. `app.route` registers the bare
handler at decoration time, so the wrapper `require_permission` returned was
built and never called. The routes looked guarded in the source and were not,
with no runtime symptom.

Fixed by having the decorator record its requirement in a registry keyed by
`__qualname__` and enforcing from middleware, which removes the failure mode
rather than the 85 instances. A boot-time self-check now prints the tally so a
regression is visible in the first lines of the container log.

### Endpoint audit

`scripts/api_smoke_test.py` enumerates every route from `app.py` via AST and
calls it twice — anonymously across all verbs, then authenticated across
read-only verbs. First run found seven endpoints returning 500:

| Endpoint | Cause |
| :--- | :--- |
| `GET /ldap` | Queried `ldap_config ORDER BY updated_at`; the table is `ldap_conf`, the column `created_at`. Settings saved but never loaded. |
| `/<agent>/notifications/templates` | `email_templates` was never created by `init_userdb.sql`, so `send_email()` had been failing at its SELECT — alert mail was silently dead. |
| `/threat-intel` | No exception handler and no `CustomEncoder`; 500'd on the `datetime` in `created_at`. Worked only while the table was empty. |
| `/api/compliance/report` | Queried `sentora_hub` for two tables that only exist per-agent. |
| `/databases/*` (×3) | Returned 500 for a missing database or table; both are 404s. |

Current state: 135 route/method pairs, 0 auth bypasses, 0 server errors.

### Metrics that were not computed

- Dashboard `Alert Coverage: 100%` and `DB Integrity: Verified` were literal
  strings in the JSX. They read nothing and would have kept saying the same
  with the database down.
- `/api/compliance/report` returned `100 - vulns*2 - fim*5` as a "compliance
  score" — no framework, no fleet-size scaling, pinned to zero on any real
  fleet. Now `/api/exposure/report`, reporting measured counts with explicit
  coverage and no score.
- `periodic_threat_intel_update()` inserted three hardcoded IoCs hourly, one
  of them the SHA-256 of the empty string marked CRITICAL malware. Replaced
  with abuse.ch feeds; the mock rows are purged from existing databases.

### Validation before anything leaves the server

- **Agent configs.** `POST /<agent>/config/<type>` forwarded the body to the
  sensor unread. Now parsed, shape-checked, and — the layer that matters —
  regex-compiled, since an invalid regex is valid YAML and silently disables
  the rule containing it.
- **Outbound proxy.** `/_proxy/http` was unauthenticated SSRF. Now behind
  `manage_system` plus a host allowlist, with loopback and link-local refused
  even for allowlisted names, no redirect following, and `Set-Cookie` never
  relayed back.
- **Playbook steps.** Per-action parameter validation in the editor;
  irreversible actions flagged before save.

### Deployment hardening

Supporting services bind to `BIND_ADDR` (loopback by default) since none of
them authenticate. The whole-host bind mount (`/:/host_disk:ro`) is gone. The
container runs as non-root. `.env` and `data/` are excluded from the image.
RabbitMQ no longer runs on guest/guest. `data/` is now a named volume — it
had none, so every recreate orphaned encrypted telemetry.

### Test coverage

125+ tests, none requiring MySQL or RabbitMQ. The ones that pull weight:
session storage invariants, an AST guard that fails if a handler reads
`X-User-ID` directly again, SSRF rules including the DNS-rebinding case,
config validation (chiefly that a broken regex is caught although the YAML is
valid), and threat-feed parsers under malformed input.

**Known gap.** ~60 write-verb routes are checked anonymously but never with a
session. Closing that needs a disposable database and a fake agent endpoint,
not a wider allow list.

---

## Earlier work

## Security and IAM

- Bcrypt password hashing. All user passwords were migrated from
  plain-text to bcrypt hashes in the database.
- Stricter RBAC:
  - More than 40 API routes are now guarded by the `@require_permission`
    decorator.
  - Granular permissions: `read_telemetry`, `manage_agent`,
    `manage_soar`, `manage_system`, `manage_db`.
  - The frontend hides buttons that the current user does not have
    permission for (frontend-backend sync).
- Audit logging:
  - New `audit_logs` table.
  - Sensitive operations (agent download, user creation, DB drop, role
    update) are recorded with who, from where, IP and timestamp.
- Pydantic input validation. All critical entry points (login, create
  user, change password) are validated against Pydantic models for type
  and format, blocking SQL injection and malformed-data attacks.

## Agent and deployment

- One-line install:
  - Linux: `curl | bash` runs a dependency check and installs to
    `/opt/sentora-agent`.
  - Windows: PowerShell `irm | iex` self-elevates to Administrator and
    installs.
- Windows Scheduled Task support. To work around Windows services not
  running Python scripts directly, the agent is registered as a startup
  scheduled task when installed.
- Dynamic packaging. The server embeds the current IP address and
  enrollment key into the agent package on every download request
  (ZIP/TAR).

## Monitoring and SIEM

- Docker security monitor. A new module connects to the local Docker
  socket and watches `exec_start`, `kill`, `oom` and similar events in
  real time.
- New alert rules. Docker and container security detection patterns
  added to `rules.yaml`.
- SOAR Hub. A central page (modeled on Splunk SOAR) that shows all
  automations and successful responses.
- Container response actions: `container_kill`, `container_stop`,
  `container_isolate` (network isolation).

## UI / UX

- Modern Zinc theme with subtle glassmorphism.
- Responsive layout. Sidebar, tables and dashboard cards work on phone,
  tablet and desktop.
- Improved visual feedback. Copy buttons, loading animations and error
  messages updated to current standards.

## System architecture and performance

- DB connection pooling. Switched single connections for an `aiomysql`
  connection pool.
- Multi-worker Sanic. Server scales to available CPU cores by default.
- Global error handling. Server crashes return a clean JSON error to
  the user; technical details stay in the logs.
- Environment management. All secrets (DB passwords, API keys) moved to
  `.env`.

---

## Sprint Update, 2026-04 to 2026-05

The platform was hardened around three themes: air-gap readiness,
server-side scanning and end-to-end UX consistency. Highlights below are
grouped by surface area.

### Code organization

- Module reorg. Flat utility files (`ai_utils.py`, `intel_utils.py`,
  `mq_utils.py`, `modules/opensearch_utils.py`,
  `modules/vuln_scanner.py`) moved into intent-based packages:
  `ai/utils.py`, `ai/intel.py`, `core/mq.py`, `core/opensearch.py`,
  `scanners/vuln.py`. Entry-point file names (`app.py`, `server.py`,
  `ai_worker.py`) stayed at root so `docker-compose` commands remain
  unchanged.
- English-only UI and backend. Every Turkish user-facing string (UI
  labels, response messages, operator log lines) was translated.
  Source-file comments in legacy modules may still be Turkish; runtime
  output is uniformly English.

### Vulnerability scanning (moved server-side)

- `scanners/vuln.py`. New OSV-based scanner reads each agent's
  encrypted `packages` table, decrypts via Fernet, queries OSV in
  batches and writes plaintext findings to
  `<agent>_db.vulnerabilities_report`. The agent's old per-host
  `find_vuln` thread was disabled, so endpoints no longer burn CPU on a
  5-minute scan loop.
- CVE detail hydration. `/v1/querybatch` only returns CVE IDs, leaving
  the UI's Summary column empty. Each unique CVE is now hydrated via
  `/v1/vulns/<id>` (process-level cached) so summaries and reference
  URLs are populated. Older empty rows are repaired by
  `_backfill_missing_summaries` at the start of every scan.
- Ecosystem detection improved to handle WSL Ubuntu (generic
  `Linux-...-WSL2-...` platform string). Unknown Linux variants now
  fingerprint via package version patterns (`-Nubuntu`, `.elN`) and
  default to Debian.
- Manual trigger. `POST /<agent>/vulns/scan` and a Scan Now button on
  the per-agent Vulns tab. Returns
  `{ok, ecosystem, packages, hits, inserted, skipped_reason?}`.

### Air-gap support

- OSV mirror auto-fallback. New `OSV_MODE` env (`auto`, `online`,
  `mirror`). Auto probes public OSV at boot; if unreachable and
  `OSV_MIRROR_URL` is set, the in-network mirror is used for the rest
  of the process lifetime. Logged on startup so operators can confirm
  which side is active.
- Local fonts. `frontend/src/index.css` no longer pulls Google Fonts
  via remote `@import`. Inter and Source Code Pro now ship through
  `@fontsource/*` packages and are inlined into Vite's build output.
- Documented internet dependencies. OTX and VirusTotal are no-ops
  without API keys; the periodic threat-intel feed is mock data.

### AI pipeline and SOAR autonomy

- Defensive worker autonomously dispatches actions. When the verdict
  is `ACT`, confidence is at or above `AI_AUTO_ACT_CONF` (default
  0.75), and the recommended action is on the safe-list (BLOCK_IP,
  KILL_PROCESS, ISOLATE_HOST, DISABLE_USER, QUARANTINE_FILE, etc.), the
  worker queues a `pending` row directly into `<agent>_db.automations`
  via `ai/utils.queue_soar_action`. Auto-dispatched insights are tagged
  `| AUTO-DISPATCHED <action>` and surface in SOAR Hub with a red AUTO
  badge.
- `source_data` column on `ai_analysis_results`. The raw log text fed
  to the LLM is now stored alongside each insight so the per-agent AI
  Analysis tab's View Source modal can show exactly what was analyzed.
  Idempotent `ALTER TABLE` migrates legacy schemas.
- Strict-JSON verdict prompts. All three workers (automation, manual,
  defensive) require the LLM to return a single JSON object with
  `verdict`, `severity`, `confidence`, `indicator`, `summary`, etc.
  Aggressive parsing (`_extract_json` brace-counter plus regex
  fallback) keeps even malformed output usable.
- Per-agent AI Analysis tab. Insights moved from the agent overview
  into a dedicated tab with structured rendering: severity chips,
  confidence %, MITRE techniques as chips, IOC chips, next-steps list,
  intel-match banner, raw-toggle. Source filter dropdown shows friendly
  labels (`Logs (Auto)`, `Alerts (Manual)`, `AI Auto-Action`,
  `AI Advisory`) instead of raw table names.

### Server-to-agent auth resilience

- Multiple-key probing. The server's outbound proxy (`_get_agent_keys`
  plus `_try_agent_request`) tries the per-agent enrollment key from
  `agent_identities` first, then the master `AGENT_SHARED_SECRET`. Each attempt
  logs a key fingerprint (`[agent-proxy] ... 401 with key#N
  (xxxxxx...)`) so mismatches are diagnosable.
- Agent permissive-auth fallback. When the agent host has no
  `AGENT_MASTER_SECRET` (or legacy `AGENT_SHARED_SECRET`) env, the agent
  accepts any non-empty `X-Agent-Key` and warns. Strict mode kicks
  in as soon as either env is set.
- Helper `_check_auth_header` and `_ws_authorized` unify all three
  agent endpoints (`/soar/execute`, `/config/<type>` GET and POST) and
  the new `/screen/ws`. Either a header or a `?key=` query string is
  accepted (browsers cannot set custom headers on a WebSocket upgrade).

### Remote desktop (replaces TightVNC)

- Pure JPEG WebSocket streaming. The agent's new `/screen/ws` captures
  the primary monitor with `mss`, JPEG-encodes via `Pillow` and writes
  binary frames at a configurable cadence (`?fps=10&q=60&w=1280`). The
  server's `/vnc-proxy/<agent>` is a websocket-to-websocket proxy using
  the `websockets` library.
- `VncViewer` rewritten. noVNC is gone; the component opens a raw
  WebSocket, paints incoming Blob frames into an `<img>`, exposes live
  FPS / quality dropdowns and revokes the previous frame's object URL
  to keep memory bounded.

### Agent identity and telemetry

- Real hostname and MAC propagated. The agent now embeds
  `|HOST=<gethostname>|MAC=<uuid.getnode()>` into the `OS_INFO` field
  at send-time. The server splits the tail back out via
  `_parse_os_info_tail` and persists into the `agent_info` schema
  (extended with `hostname` and `mac_address` columns via idempotent
  `ALTER TABLE`). System tab Hostname / MAC fields are no longer empty
  or wrong.
- Docker container inventory now reaches the server. `docker_containers`
  was missing from the agent's `TABLES` sync list and was added.
  Agent's `state` field is truncated to 64 chars to fit the server
  schema.
- Disk monitor logs visible. `disks.py` now prints `[DiskMonitor]
  cycle: persisted=X skipped=Y` per scan and surfaces "table missing"
  and upsert failures explicitly so empty Disk Inventory tabs are
  diagnosable instead of silently failing.

### Playbooks

- `run_playbook` hardening. Every node call is wrapped in `try/except`
  so a single failed action no longer 500s the entire run. Errors are
  recorded in the `timeline` and the run row is marked `failed` with a
  `last_error` blurb. Schema mismatch fixed: `playbook_runs` INSERT
  now includes `agent_name` (NOT NULL in `init.sql`); status uses
  `success` (matches the ENUM) instead of the rejected `completed`.
- Real status reporting. Run completion no longer hard-codes `success`:
  it computes the overall outcome from each node's `result.ok`,
  including queued-but-direct-push-failed cases. The UI's Recent
  Executions table now shows accurate `success` and `failed` badges.

### Audit logs UI

- Expandable detail modal. Each row's Details column is now a button
  that opens a modal showing every field of the `audit_logs` row
  (User, User ID, Action, Resource, IP, Details, Timestamp, plus any
  extra columns added later). Resource cells longer than 32 chars are
  truncated but click through to the same modal.
- Robust timestamp parsing. Reads either MySQL's `timestamp` or
  OpenSearch's `@timestamp`; epoch seconds vs ms vs ISO / SQL strings
  are all handled.
- Pending tasks endpoint resilience. `/<agent>/automations/pending` now
  returns `{tasks: []}` when the agent's local `automations` table does
  not exist yet, instead of 500-spamming agent logs.

### Quality of life

- `/api/ai-insights/all` no longer empties out. The endpoint now uses
  `sync_mysql_conn` (root) for `SHOW DATABASES` instead of
  `userdb_conn` (which could not see `*_db`s) and lazily ALTERs
  `ai_analysis_results` to add `source_data` on the fly.
- `getAgents()` shape mismatch fixed. `SoarHub` was passing the full
  `{name, status, ...}` agent object as a URL segment; switched to
  extracting `.name`. Stat cards (Mitigated Threats, Active IP Blocks,
  Pending Tasks, Failed Responses) and the Recent Automation Events
  feed now populate correctly.
- Frontend timestamp display. Dashboard, SoarHub and AI Analysis tabs
  all normalise Unix-seconds-or-ms-or-ISO into `toLocaleString()`.

---

## Paid tier roadmap (open core)

Decision (2026-05-02): the platform splits into a free Community Edition
(AGPL-3.0) and paid Pro / Enterprise tiers. Local-AI triage and core
SIEM / SOAR / agent capability stay free; that is the differentiator and
locking it would kill adoption. Paid tiers unlock features only
enterprises need.

The full task tree lives in `TODO.md` (kept private). Build order below.

### Build order

1. Paid-tier feature flag system (foundation, must land first)
   - `userdb.tier` (`community`, `pro`, `enterprise`)
   - `core/tier.py` with `current_tier()`, `require_tier()`, feature flags
   - `@require_tier("pro")` decorator
   - Signed tier entitlement file (verified at boot against a public key
     bundled with the build) so offline operation stays possible
   - UI tier badge and paywall modal component
   - Soft agent-count gate (Community = 10)
   - Telemetry on every paywall hit so we can size demand

2. Multi-tenancy / MSSP mode (flagship Enterprise feature)
   - `tenants` table plus `tenant_id` FK on `users`,
     `agent_identities`, `audit_logs`
   - Tenant-scoped sessions; every `@require_permission` route filters
     by the caller's tenant
   - `sentora-ops` admin tenant for impersonation
   - Sidebar tenant switcher (Enterprise tier only)
   - Migration plan for existing single-tenant deployments

3. SSO / SAML / SCIM
   - SAML 2.0 ACS endpoint via `python3-saml`
   - OIDC option (Okta, Azure AD, Google Workspace)
   - SCIM 2.0 user / group provisioning (Pro+)
   - IdP-group to Sentora-role mapping

4. Compliance module
   - PCI-DSS / ISO 27001 / HIPAA dashboard templates
   - Tier-based audit retention (Community 30 d, Pro 1 y, Enterprise
     unlimited plus WORM)
   - WORM enforcement: append-only audit table, hash-chained signatures
   - Scheduled compliance report PDF export

5. High availability / clustering
   - OpenSearch cluster mode toggle
   - MySQL read-replica config (Pro), full HA helper (Enterprise)
   - Liveness and readiness `/healthz` endpoints

6. Air-gap update bundles (subscription, signed)
   - `sentora-bundle` CLI: snapshot OSV plus threat-intel feeds plus
     Ollama models
   - `sentora-bundle apply <file>` on the air-gap host
   - Bundles are signed; the server verifies the signature against the
     customer's enterprise tier entitlement

7. SOAR approval workflow (4-eyes)
   - `automations.requires_approval` flag
   - Pending-approval queue UI; a second operator must approve before
     the agent receives the action
   - Auto-applied to destructive actions at Enterprise tier
   - Audit row per approval / rejection

8. Premium integrations
   - Splunk HEC forwarder
   - Microsoft Sentinel forwarder
   - ServiceNow ITSM ticket on CRITICAL alert
   - Jira ticket creation
   - Slack / Teams webhook templates

9. Hosted / SaaS edition (later)
   - Per-tenant Compose stack in the customer's cloud (BYOC)
   - Stripe billing
   - Self-service tenant creation portal

### Tier feature matrix (target state)

| Feature | Community | Pro | Enterprise |
| :--- | :---: | :---: | :---: |
| Local-AI triage (Ollama) | yes | yes | yes |
| Core SIEM + SOAR + agent | yes | yes | yes |
| OSV vuln scanning (public) | yes | yes | yes |
| Basic playbooks | yes | yes | yes |
| LDAP login | yes | yes | yes |
| Audit retention | 30 d | 1 y | Unlimited + WORM |
| Agent count | 10 | 100 | Unlimited |
| SAML / OIDC SSO | no | yes | yes |
| SCIM provisioning | no | yes | yes |
| Multi-tenancy | no | no | yes |
| Compliance dashboards | no | no | yes |
| HA / cluster mode | no | Read replica | Full HA |
| Air-gap update bundles | no | no | yes |
| SOAR approval workflow | no | no | yes |
| Splunk / Sentinel forwarders | no | yes | yes |
| ServiceNow / Jira ticketing | no | no | yes |
| Priority support / SLA | Community | Email 24 h | Phone + SLA |

Pricing model intent: per-agent, predictable. The marketing strategy
doc pitches this as the antidote to the per-GB SIEM model.
