# Sentora Agent

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](#)

Cross-platform endpoint agent for the [Sentora](../README.md) SIEM/SOAR/EDR
platform. Collects telemetry, performs local detections, executes SOAR
playbook actions and ships everything back to the central server over an
authenticated, Fernet-encrypted channel.

The agent runs as a single PyInstaller-bundled binary. No Python runtime
is required on the endpoint.

---

## What the agent does

Each agent runs a fleet of independent worker threads on a fixed schedule:

| Domain | Module | Default cadence |
| :--- | :--- | :--- |
| SIEM ingestion | Live `log_extractor` follower (journald / Event Log) | continuous |
| FIM | Realtime `fim` watchdog plus scheduled `edr_enforcer` baseline | continuous + 5 min |
| Endpoint inventory | `inventory` (CPU/RAM/disk/software/hardware) | 30 min |
| Vulnerability discovery | `find_vulns` (installed packages, queried against OSV) | 30 min |
| Permission audit | `check_permissions` (suid / world-writable / non-root configs) | 15 min |
| Network surface | `portscanner` (local TCP banner grab) | 30 min |
| Threat hunting | `lateral_movement`, `persistence_hunter` | 5-10 min |
| Resource health | `resource_checker` + `disks` | 1 min |
| Container telemetry | `docker_monitor` (when Docker socket reachable) | 1 min |
| Detection | `alert` (YAML rules against `events_alert`) | 5 min |
| Response | `soar` (consumes server-issued automation tasks) | 30 s |

All findings go to the local DB first; a background shipper flushes new
rows to the server's TCP ingest socket and marks them sent on ack.

---

## Enrolment and key bootstrap

The agent does not ship with credentials. Every install starts from a
one-time enrolment token issued by the server's *Agent Deployment* page:

```
1. Server admin generates a token in the UI            (one-time, scoped)
2. Installer POSTs the token to /api/agents/register   (returns 64-char agent_key)
3. Agent GETs /api/agents/bootstrap with X-Agent-Key   (returns Fernet key)
4. config.json is written with mode 0600
5. Sensitive columns (paths, hashes, cmdlines, addrs)  are encrypted at rest
```

The agent_key is the only long-lived secret on the endpoint. The Fernet
key is fetched on every start and refreshed every `FERNET_REFRESH_SEC`
seconds (default 600), so rotating it on the server propagates without
reinstall.

> The agent only supports enrolment-based bootstrap — there is no
> standalone CLI auth mode. Run the server installer to register the
> host, then point the agent at the generated `config.json`.

---

## Deploy

### Linux (one-liner, recommended)

```bash
curl -fsSL "https://your-server.example.com/api/agent/deploy/linux?token=ENROL_TOKEN" \
    | sudo bash
```

This downloads `deploy.sh`, registers with the server, drops the binary
in `/opt/sentora-agent/`, writes a 0600 `config.json` and installs a
`sentora-agent.service` systemd unit (auto-restart on failure,
`User=root` required for raw socket and firewall actions).

Manual form:

```bash
sudo ./deploy.sh \
    --token  ENROL_TOKEN \
    --server https://your-server.example.com \
    --name   prod-web-01            # optional, defaults to $(hostname)
```

### Windows (PowerShell, one-liner)

```powershell
iwr -UseBasicParsing "https://your-server.example.com/api/agent/deploy/windows?token=ENROL_TOKEN" `
    | iex
```

Equivalent to running `deploy.ps1` with `-Token` and `-Server`. Installs
into `C:\Program Files\Sentora\Agent\` and registers a Windows service
that starts at boot.

### Verify it's running

```bash
# Linux
systemctl status sentora-agent
journalctl -u sentora-agent -f

# Windows
Get-Service SentoraAgent
Get-Content "C:\Program Files\Sentora\Agent\agent.log" -Tail 50 -Wait
```

The agent log path is always `<install-dir>/agent.log`. The agent
detects PyInstaller's frozen mode and writes alongside the executable,
not into the ephemeral `_MEIxxxx` extract dir.

---

## Build from source

The server ships pre-built `main` (Linux) and `main.exe` (Windows)
binaries that the installer downloads from
`/api/agent/download/{linux,windows}`. To rebuild them after editing the
agent:

### Linux

```bash
cd Sentora/
./build_agent.sh
# produces Sentora/main (PyInstaller --onefile)
```

### Windows

```powershell
cd Sentora\
.\build_agent.ps1
# produces Sentora\main.exe
```

Both scripts run `pip install -r requirements.lock`, then invoke
PyInstaller with `--onefile`, embedding `conf/` and `modules/` via
`--add-data`. After rebuilding, restart the server container so the new
binary is served on the next download request.

---

## Configuration files

YAML files in `conf/` are bundled into the binary at build time. Override
them by dropping a file with the same name into the agent's working
directory. The loader prefers on-disk copies over the embedded ones.

| File | Purpose |
| :--- | :--- |
| `conf/rules.yaml` | YAML detection rules for the `alert` module |
| `conf/log_paths.yaml` | Per-OS log sources the `log_extractor` follows |
| `conf/file_scan.yaml` | Paths and extensions for the FIM baseline scan |

`config.json` (written by the installer) holds runtime identity and is
not in `conf/`. It lives in the install directory:

```json
{
  "agent_name": "prod-web-01",
  "agent_key":  "kK7H...64 chars...",
  "server_url": "https://your-server.example.com",
  "server_ip":  "10.0.0.42"
}
```

---

## Manual / development run

Skip the installer for local dev:

```bash
# 1. Install deps
pip install -r requirements.lock

# 2. Hand the agent an enrolment config (or pass flags directly)
python main.py --config /path/to/config.json

# Or use individual flags:
python main.py \
    --server https://localhost:8000 \
    --agent  dev-laptop \
    --key    YOUR_AGENT_KEY
```

Useful flags:

| Flag | Default | Effect |
| :--- | :--- | :--- |
| `--config / -c` | (none) | Path to enrolment JSON |
| `--server / -s` | (none) | Server base URL (overrides config) |
| `--agent / -a` | hostname | Agent name reported to server |
| `--api / -p` | (none) | API base URL (rarely needs to differ from `--server`) |
| `--ingest-port` | 5001 | TCP ingest port on the server |
| `--automations-mode` | `server` | `server` polls tasks; `local` is the legacy local-only mode |

---

## Modules

Full per-module reference: [docs/MODULES.md](docs/MODULES.md).

```
modules/
├── alert/                  YAML-rule SIEM matcher
├── check_permissions/      Critical-file ownership audit
├── docker_monitor/         Container lifecycle tracking
├── edr_enforcer.py         Scheduled hash-baseline FIM
├── enc_db.py               Fernet field-level encryption layer
├── fim.py                  Realtime filesystem watcher (watchdog)
├── find_vulns/             Installed-package vulnerability scan via OSV
├── inventory.py            Hardware + installed-software snapshot
├── lateral_movement.py     Suspicious port / process detector
├── log_extractor/          journald + Windows Event Log follower
├── persistence_hunter.py   Registry Run keys / cron / systemd hunt
├── portscanner/            Local TCP scan + banner grab
├── resource_checker/       CPU / memory / disk telemetry
└── soar/                   Action executor (firewall, processes, VNC, etc.)
```

---

## Local storage and encryption

The agent keeps a local relational store managed by `modules/db.py`. Two
schema bundles ship in `db/`: [`init.sql`](db/init.sql) for PostgreSQL
(default. Connection params come from `DB_HOST` / `DB_PORT` / `DB_USER` /
`DB_PASSWORD` / `DB_NAME` env vars) and
[`init_sqlite.sql`](db/init_sqlite.sql) for the embedded-SQLite path used
in minimal or offline deployments. Every detection row carries a `sent`
flag. The shipper sweeps unsent rows, batches them onto the ingest
socket and marks them sent on ack.

Sensitive fields are encrypted via `modules/enc_db.py` using the
per-tenant Fernet key bootstrapped from the server. Encrypted-by-default
columns:

| Table | Encrypted fields |
| :--- | :--- |
| `fim_data` | `path`, `hash_sha256` |
| `registry_logs` | `hive`, `key_path`, `value_name`, `value_data` |
| `network_connections` | `process_name`, `local_addr`, `remote_addr` |
| `process_events` | `name`, `cmdline`, `username` |
| `hardware_inventory` | `name`, `serial_number` |
| `security_audit` | `finding`, `details` |

If the server's Fernet key is rotated, the agent re-fetches it on the
next refresh tick. Old encrypted rows remain readable because the server
stores the active key indefinitely until a manual purge.

---

## Logs and troubleshooting

| Symptom | Where to look |
| :--- | :--- |
| Service won't start | `journalctl -u sentora-agent` (Linux), Event Viewer (Windows) |
| Auth failures | `agent.log`. Look for `Agent key rejected by server`, then re-enrol |
| FIM not firing | `watchdog` requires the agent user to read the monitored paths |
| SOAR action no-ops | Most actions need root or Administrator. Check the service user |
| Bootstrap loop | Server unreachable. Agent retries every 30 s, then falls through to the cached Fernet key after the first successful bootstrap |

The agent forwards `print()` calls from inside `modules/` into the file
logger automatically, so module-side `print(...)` lines land in
`agent.log` under a `[MODULE]` prefix without console noise.

---

## Security notes

- `config.json` is mode 0600 (Administrators-only on Windows). It holds
  the agent_key. Treat it as a secret.
- The agent runs as root or Administrator by design. Permission audits,
  realtime FIM, firewall rules and many SOAR actions require it. Run it
  on endpoints where you would be comfortable running an EDR.
- Outbound only. The agent never opens a listening port on the endpoint.
  The embedded Sanic instance binds to `127.0.0.1` for local control
  endpoints used by the SOAR `start_vnc` action; nothing accepts
  external connections.
- No external API calls without an opt-in. OSV is the only network
  dependency for vulnerability checks, and the server can proxy it via
  the air-gap mirror. The agent itself talks to one host: your server.

---

## License

AGPL-3.0, the same as the rest of
[Sentora Community Edition](../LICENSE).

If you ship a modified agent to endpoints you don't own (managed-service,
SaaS, MSSP) you must publish your modifications under AGPL-3.0. A
commercial waiver is available for closed-source derivatives. See the
[main README](../README.md#license).
