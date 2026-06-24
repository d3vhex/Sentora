# Sentora Community Edition

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Built with Sanic](https://img.shields.io/badge/built%20with-Sanic-FF7600)](https://sanic.dev/)

Self-hosted security stack for small/mid teams that don't have a dedicated
SOC. Drop an agent on each endpoint, point them at the server, and you get
SIEM logs, file integrity, package vulnerabilities, an OpenSearch-powered
log explorer, autonomous AI triage and a SOAR playbook engine, all in one
`docker compose up`.

The "AI" part is a locally-running Ollama model (default `llama3.2:3b`).
Logs never leave the box; there's no OpenAI key, no Anthropic key, no
phone-home. If you want a smarter model and have the RAM, swap it in `.env`.

![Dashboard](docs/pics/dashboard.jpg)

---

## What it actually does

- **Collects telemetry** from Windows and Linux agents over a single TCP
  channel. SIEM events, alerts, FIM, packages, network connections,
  open ports, Docker activity, screen frames.
- **Triages every event with a local LLM.** Three workers run in parallel:
  one watches every incoming event in real time, one runs operator-driven
  deep scans, and one decides whether to take a defensive action
  (`BLOCK_IP`, `ISOLATE_HOST`, `KILL_PROCESS`, etc.).
- **Shadow mode for the defensive worker.** Flip `AI_SHADOW_MODE=1` and
  every autonomous verdict is staged for human approval in the SOAR Hub
  instead of being dispatched. Useful for tuning the model on real
  traffic before letting it act on its own.
- **Indexes everything in OpenSearch** so you can grep your fleet with
  fuzzy / exact / starts-with queries from one place.
- **Runs SOAR playbooks** built in a small visual editor with multi-step,
  per-node result tracking, can be triggered manually or by AI verdict.
- **Vulnerability scans** every agent's installed packages against OSV
  (online or via an internal mirror).
- **Built-in remote desktop** via WebSocket JPEG streaming, no separate
  VNC install needed on the endpoint.

## What it looks like

The sidebar groups everything into three sections: telemetry (dashboard,
agents, alerts, assets, FIM, logs, AI), automation response
(defensive actions, playbooks, automation rules), and administration.

<p align="center">
  <img src="docs/pics/sidebar.jpg" alt="Sidebar navigation" width="240"/>
</p>

### Per-agent view

Each enrolled agent has its own page with twelve tabs. The overview
shows live resource meters, the most recent SIEM logs, agent metadata
and a threat summary:

![Agent overview](docs/pics/agent-overview.jpg)

Alerts are everything the agent's own correlation rules already flagged.
Severity-coloured, filterable, searchable:

![Agent alerts](docs/pics/agent-alerts.jpg)

The AI Analysis tab is the operator-facing side of the local LLM. Manual
and automatic scans both land here. Each insight carries a verdict chip,
confidence, MITRE indicators (when the model returns them), IOCs, next
steps, and a *View Source* button that opens the exact log row the AI
looked at:

![AI analysis](docs/pics/agent-ai-analysis.jpg)

### Asset inventory

Hardware, software, and network sockets per agent. Hardware tab lists
every PnP device, software lists installed packages, network lists every
TCP/UDP socket with its owning process:

![Asset inventory: hardware](docs/pics/asset-inventory-hardware.jpg)

![Asset inventory: network](docs/pics/asset-inventory-network.jpg)

### Log Explorer

Cross-agent search backed by OpenSearch. Pick an agent, pick a dataset
(SIEM events, security alerts, process events, network, FIM, audit
logs), and search. There's also a button to open OpenSearch Dashboards
(Kibana fork) for power users:

![Log Explorer](docs/pics/log-explorer.jpg)

### Audit logs

Every login attempt against the platform itself, both local and LDAP,
with result, source IP, and timestamp. Useful when someone is in the
"who-logged-in-when" mood:

![Audit logs](docs/pics/audit-logs.jpg)

---

## Quick start

You'll need Docker 24+ with Compose v2 and Python 3.10+ on the host (only
for the one-time agent build step). The full stack wants ~16 GB RAM,
see [System requirements](#system-requirements) below.

```bash
git clone https://github.com/0giv/Sentora-Community-Edition.git
cd Sentora-Community-Edition

# .env holds your local secrets. Never commit it.
cp .env.example .env
# Edit .env: at minimum change DB_PASSWORD.

# Build the agent binary once. The server serves it via
# /api/agent/download/{linux,windows}; skipping this means agents can't be
# deployed because the download endpoint returns 404.
cd Sentora
./build_agent.sh                 # on Linux/macOS/WSL
# .\build_agent.ps1              # on Windows
cd ..

docker compose up --build -d
```

Open <http://localhost:8000>. Default login is `admin` / `admin123`.
Change it immediately under **Users & Roles**.

Ollama auto-pulls `llama3.2:3b` on first boot. Verify with:

```bash
docker exec sentora-ollama ollama list
```

Deploying an agent: from the **Deploy Agent** page, copy the one-liner
for the OS you want. On the target machine (admin shell), paste it. The
installer downloads the binary, drops a config, enrols with the server,
and registers itself as a scheduled task / systemd unit.

---

## Services in the compose

| Service | Port | Purpose |
| :--- | :--- | :--- |
| `app` | `:8000` | REST API + React UI |
| `ingest` | `:5001` | TCP log collector (the agent sends here) |
| `db` | `:3307` | MySQL 8.0 (host port; 3306 inside the network) |
| `rabbitmq` | `:5672` / `:15672` | Job queue + management UI |
| `ollama` | `:11434` | Local LLM runtime |
| `opensearch` | `:9200` | Full-text log search |
| `opensearch-dashboards` | `:5601` | Optional Kibana-style explorer |
| `ai-worker-{automation,manual,defensive}` |   | LLM analysis workers |

---

## System requirements

| Profile | CPU | RAM | Disk | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Lab (≤ 5 agents) | 4 cores | 12 GB | 40 GB SSD | `llama3.2:3b`, OpenSearch heap at 1 GB |
| Small team (10–50 agents) | 8 cores | 16 GB | 100 GB SSD | Compose defaults are fine |
| Production (50+ agents) | 16+ cores | 32 GB+ | 250 GB+ NVMe | Move OpenSearch and Ollama onto their own hosts |

Idle footprint:

- Ollama (`llama3.2:3b`): ~3 GB, more under inference
- OpenSearch: ~2 GB default heap, disk grows with retention
- MySQL: 500 MB – 1 GB
- RabbitMQ: ~300 MB
- Sanic + ingest + 3 AI workers: ~1 GB combined

If you're tight on RAM, swap to `qwen2.5:1.5b` or another small Ollama
model and shrink the OpenSearch heap. A GPU isn't required but Ollama
will use it automatically if present.

---

## Defensive AI auto-actions

When the defensive worker's verdict is `ACT` with confidence ≥
`AI_AUTO_ACT_CONF` (default `0.75`) and the recommended action is on the
safe-list below, the worker queues the action straight into the agent's
`automations` table:

```
BLOCK_IP        KILL_PROCESS      RESTART_SERVICE   ISOLATE_HOST
DISABLE_USER    QUARANTINE_FILE   SUSPEND_PROCESS   LOGOFF_USER
CONTAINER_ISOLATE   CONTAINER_STOP   CONTAINER_KILL
```

Anything outside that list (arbitrary `RUN_CMD`, `DELETE_FILE`, etc.)
gets downgraded to an advisory insight. The operator has to dispatch
it manually from the SOAR Hub. Auto-dispatched actions show a red AUTO
chip in the UI.

To disable autonomy entirely, set `AI_AUTO_ACT_CONF=1.0` in `.env`. To
disable the periodic defensive sweep, set `AI_DEFENSIVE_SWEEP_ENABLED=0`.

### Shadow mode

Set `AI_SHADOW_MODE=1` in `.env` and the defensive worker stops firing
real actions. Verdicts that would have triggered an autonomous response
are saved as **proposals** instead, with `source_file = AI_DEFENSIVE_SHADOW`
and `shadow_status = pending`. The operator reviews each one from
**SOAR Hub > Shadow Queue** and either:

- **Approve** > the real SOAR action (`call_agent_soar`) fires and the
  proposal is marked `approved` (with timestamp + operator name).
- **Reject** > the proposal is marked `rejected` with an optional note.
  No action is taken.

Proposals never expire; nothing decides for you. Useful for letting the
model run on production telemetry while you build confidence in its
verdicts before unleashing real `BLOCK_IP` / `ISOLATE_HOST` etc.

---

## Security notes

### Default secrets

`.env.example` ships with placeholders. The real `.env` is git-ignored.
Rotate these before exposing the platform to anything beyond `localhost`:

- `DB_PASSWORD`
- The `admin / admin123` UI login
- `AGENT_SHARED_SECRET` (agent auth fallback). Auto-generated on first
  boot if unset.

### Self-signed certs

`certs/` ships with self-signed dev certs so the stack works on
`localhost` out of the box. They are public and grant zero trust. For
anything that isn't your laptop, regenerate:

```bash
cd certs && python generate_certs.py
```

Or supply your own organisational CA.

### Local Fernet keys

The server uses two Fernet keys, both auto-generated on first boot:

| Key | Location | Protects |
| :--- | :--- | :--- |
| Agent key | `data/fernet.key` (or `FERNET_KEY_PATH`) | Agent telemetry; handed out via `/api/agents/bootstrap` |
| Server key | `.env` `FERNET_KEY` | Server-internal at-rest fields (e.g. password column) |

`chmod 600` both. Back them up. Losing either makes the corresponding
encrypted data unreadable. There is no in-place rotation yet.

### Threat intel keys

`OTX_API_KEY` and `VT_API_KEY` are optional. Unset → enrichment becomes
a no-op, no external API calls. Keeps the stack air-gap-friendly.

### Air-gap mode

```ini
OSV_MODE=mirror
OSV_MIRROR_URL=http://osv.internal
```

Bundled fonts, local Ollama, no external CDN. Works fully offline.

---

## Architecture overview

```
 Agent (Win / Linux)
    │  TCP frames + REST polling
    ▼
 ingest (:5001) ──► RabbitMQ ──► AI worker fleet (3 modes)
    │                                  │
    ▼                                  ▼
 MySQL (per-agent <name>_db)    ai_analysis_results
    │
    ▼
 app (Sanic :8000)  ──► React UI + REST + WebSocket screen proxy
```

The deeper version (per-module layout, schema, AI pipeline, SOAR
autonomy, air-gap surfaces) lives in
[docs/Sentora_Architecture.md](docs/Sentora_Architecture.md).

---

## Development setup

```bash
# 1. Database
mysql -u root -p < init_userdb.sql
mysql -u root -p < init.sql

# 2. Backend
pip install -r requirements.txt
python app.py

# 3. Ingest (separate terminal)
python server.py

# 4. Frontend dev server
cd frontend
npm install
npm run dev
```

### AI workers manually

Same script, three roles:

```bash
WORKER_TYPE=automation python ai_worker.py
WORKER_TYPE=manual     python ai_worker.py
WORKER_TYPE=defensive  python ai_worker.py
```

Production: let `docker-compose.yaml` do it.

---

## Contributing

PRs welcome. Before opening:

1. Fork → branch → PR against `main`.
2. `npx tsc --noEmit` in `frontend/` and `python -m py_compile app.py`.
3. New endpoints must be wrapped in `@require_permission(...)`.

For anything bigger than a fix, open an issue first so we can align on
the approach.

---

## Project layout

```
.
├── app.py                # Sanic API + React SPA host
├── server.py             # TCP ingest
├── ai_worker.py          # AI worker fleet (3 modes)
├── ai/
│   ├── utils.py          # LLM helpers, AI cache, SOAR queueing
│   └── intel.py          # OTX / VT enrichment (opt-in)
├── core/
│   ├── mq.py             # RabbitMQ publisher
│   └── opensearch.py     # OpenSearch index/search
├── scanners/
│   └── vuln.py           # Server-side OSV scanner
├── frontend/             # React 18 + TS SPA
├── Sentora/             # Cross-platform agent
├── certs/                # Self-signed dev certs
├── docs/                 # Architecture + screenshots
└── docker-compose.yaml
```

---

## License

AGPL-3.0. See [LICENSE](LICENSE).

Use, modify, redistribute. The thing AGPL adds on top of regular GPL:
if you run a modified version on a network server where other users
interact with it, you must publish the modifications under AGPL too.

- Self-hosting for internal use → no source-disclosure obligation.
- Public-facing SaaS on top of a modified Sentora → you must publish
  the modifications.
- Want to ship a closed-source derivative or skip the network-copyleft
  clause? A commercial licence waiver is available. Contact the author.

The "Sentora" name and logo are trademarks of the project authors and
are not covered by AGPL. Fork freely, but rename if you redistribute as
your own product.

---

## What's not in Community Edition

Community Edition has zero artificial caps: no agent limit, no
retention limit, no feature gating on the core. Run it as wide as your
hardware allows.

The paid Pro / Enterprise distribution adds enterprise-glue features
(SAML/SCIM SSO, multi-tenancy, compliance reports, HA, WORM audit,
signed air-gap update bundles, 4-eyes SOAR approvals, premium
ticketing/SIEM forwarders). The core detection capability never gets
moved behind that wall.

If any of that matters for your deployment,
[reach out](mailto:oguzhanbayarslan@gmail.com).
