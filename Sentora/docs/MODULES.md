# Module Reference

Every module is launched from `main.py` via `periodic_wrapped(...)` (or
a dedicated thread for continuous watchers). Findings are written to
the agent's local DB and shipped to the server by a background flusher.

Convention: tables marked (enc) have sensitive fields encrypted at rest
by `modules/enc_db.py` using the per-tenant Fernet key. See the
[agent README](../README.md#local-storage-and-encryption) for the field
map.

---

## SIEM ingestion

### `log_extractor`
- Path: `modules/log_extractor/log_extractor.py`
- Platforms: Linux (journald and arbitrary file paths) / Windows (Event
  Log via `pywin32`)
- Behavior: Continuous follower. Tails sources listed in
  `conf/log_paths.yaml`, normalizes each entry to a JSON record and
  writes it to `siem_events` (enc). Filters by keyword set so the local
  store does not fill with noise.
- Output table: `siem_events` (encrypted `message`)

### `alert`
- Path: `modules/alert/alert.py`
- Behavior: Loads detection rules from `conf/rules.yaml` and matches
  them against unprocessed rows in `siem_events`. Matches are written
  to `events_alert` with severity and rule id. This is the agent-side
  detection engine; the server's AI workers run additional triage on top.
- Output table: `events_alert`

---

## File integrity

### `fim` (realtime watcher)
- Path: `modules/fim.py`
- Backed by: [watchdog](https://pypi.org/project/watchdog/)
- Behavior: Subscribes to filesystem events under `/etc`, `/root/.ssh`,
  `C:\Windows\System32\drivers\etc` and `C:\Users`. Only emits when the
  changed file matches the critical list (`passwd`, `shadow`, `hosts`,
  `authorized_keys`, `sshd_config`, `.env`, etc.) or the extension list
  (`.php`, `.py`, `.sh`, `.exe`, `.dll`). On every match it recomputes
  the SHA-256 and writes a `fim_data` row tagged `created`, `modified`
  or `deleted`.
- Output table: `fim_data` (enc) for `path` and `hash_sha256`

### `edr_enforcer` (periodic baseline)
- Path: `modules/edr_enforcer.py`
- Behavior: Scheduled hash-baseline scan of a small high-value file set
  (`/etc/passwd`, `/etc/shadow`, SAM hive path, `hosts`, `sshd_config`).
  First run establishes the baseline; subsequent runs flag any mismatch
  as a `security_audit` finding. Complements the realtime `fim` watcher,
  since the baseline scan catches changes that occurred while the agent
  was offline.
- Output table: `security_audit` (enc)

---

## Inventory and vulnerability

### `inventory`
- Path: `modules/inventory.py`
- Behavior: Hardware snapshot (CPU model, RAM, disk topology) plus
  installed-software enumeration (`dpkg-query`, then `rpm -qa`, then a
  Windows registry walk under `Uninstall`). Writes one
  `hardware_inventory` row and N `installed_software` rows per sweep.
- Output tables: `hardware_inventory` (enc) for `name` and
  `serial_number`; `installed_software`

### `find_vulns`
- Path: `modules/find_vulns/` (`info_collector.py` and `find_vuln.py`)
- Behavior:
  - `info_collector` produces the package list (same logic as
    `inventory` but emits to the OSV-input format).
  - `find_vuln` queries `https://api.osv.dev` (or the server-proxied
    air-gap mirror) for known vulnerabilities and writes
    `vulnerabilities_report` rows.
- Output table: `vulnerabilities_report`

---

## Threat hunting

### `lateral_movement`
- Path: `modules/lateral_movement.py`
- Behavior: Two-pronged.
  1. Walks `psutil.net_connections()` and flags ESTABLISHED sessions on
     RDP (3389), SSH (22), VNC (5900), SMB (445 / 139).
  2. Walks `psutil.process_iter()` for known dual-use tooling: `psexec`,
     `winrs`, `wsmprovhost`, `nmap`, `masscan`, `nc` / `ncat` / `netcat`,
     `socat`, `chisel`, `mimikatz`, `rdesktop`.
- Output table: `security_audit` (enc) with `type=LATERAL_MOVEMENT`

### `persistence_hunter`
- Path: `modules/persistence_hunter.py`
- Behavior:
  - Windows: walks `HKLM\Software\...\CurrentVersion\Run` and
    `HKCU\...\Run` for values pointing into `%TEMP%`, `%APPDATA%`, or
    running `.vbs` / `.ps1`. Inspects the per-user Startup folder.
  - Linux: `/etc/crontab`, `/etc/cron.d/`, user crontabs and suspicious
    systemd unit files.
- Output table: `security_audit` (enc) with `type=PERSISTENCE`

### `check_permissions`
- Path: `modules/check_permissions/check_permissions.py`
- Behavior: Walks common config and backup directories (Linux: `/etc`,
  `/var/backups`, `/srv`; Windows: `Program Files`, `ProgramData`) and
  flags files not owned by `root` (Linux) or by the
  `SYSTEM`/`Administrators` SID (Windows). Catches operator missteps
  that leave critical configs world-writable.
- Output table: `critical_files`

---

## Network and system

### `portscanner`
- Path: `modules/portscanner/portscanner.py`
- Behavior: Scans local TCP ports, grabs service banners, classifies
  the service when a fingerprint matches. Used both for surface mapping
  and to detect new listeners that appear between sweeps.
- Output table: `portscan_result`

### `resource_checker`
- Path: `modules/resource_checker/resource_checker.py` (plus `disks.py`)
- Behavior: Per-tick CPU and memory snapshot into `resource_log`. The
  `disks.py` companion writes per-partition usage to `disk_info` and
  flags any partition over the soft or hard threshold.
- Output tables: `resource_log`, `disk_info`

### `docker_monitor`
- Path: `modules/docker_monitor/docker_monitor.py`
- Behavior: When `/var/run/docker.sock` is reachable, enumerates running
  containers (id, name, image, state, created_at) into
  `docker_containers`. SOAR actions (`CONTAINER_STOP`, `CONTAINER_KILL`,
  `CONTAINER_ISOLATE`) target this inventory. No-op on hosts without
  Docker.
- Output table: `docker_containers`
- Dependency: [`docker`](https://pypi.org/project/docker/) Python SDK

---

## Response

### `soar`
- Path: `modules/soar/soar.py`
- Behavior: Polls the server every 30 s for `automations` rows assigned
  to this agent, executes them and reports the result back via
  `/api/agents/<name>/automations/<id>/result`. Each action carries an
  optional `expires_at`. When a block expires the agent unblocks the IP
  or re-enables the user automatically and emits a `RESOLVED` status.
- Supported actions (`ActionType`):
  `BLOCK_IP`, `UNBLOCK_IP`, `DISABLE_USER`, `ENABLE_USER`, `RUN_CMD`,
  `KILL_PROCESS`, `RESTART_SERVICE`, `LOCK_MACHINE`, `ISOLATE_HOST`,
  `QUARANTINE_FILE`, `DELETE_FILE`, `TAIL_LOG`, `CONTAINER_KILL`,
  `CONTAINER_STOP`, `CONTAINER_ISOLATE`, `FLUSH_DNS`,
  `DISABLE_INTERFACE`, `LOGOFF_USER`, `CLEAR_TEMP`, `DUMP_PROCESS`,
  `SUSPEND_PROCESS`, `DELETE_REGISTRY_KEY`, `PROTECT_SHADOWS`,
  `START_VNC`, `STOP_VNC`
- Auto-action allow-list: the server's defensive AI worker can
  auto-dispatch a subset of these without operator approval. See
  [Defensive AI Auto-Actions](../../README.md#defensive-ai-auto-actions)
  in the server README. Everything not on that list still requires a
  human click.
- Output table: `soar_actions`

---

## Internal helpers (not findings producers)

### `db.py`
Thin DB wrapper used by every module: `insert_record`, `fetch_where`,
`fetch_unsent`, `mark_sent`. Defaults to PostgreSQL via `psycopg2`
(connection params from env: `DB_HOST`, `DB_PORT`, `DB_USER`,
`DB_PASSWORD`, `DB_NAME`). Schema lives in [`db/init.sql`](../db/init.sql);
an equivalent SQLite schema is shipped at
[`db/init_sqlite.sql`](../db/init_sqlite.sql) for offline or minimal
deployments.

### `enc_db.py`
Fernet-backed transparent encryption layer over `db.py`. Pulls the
active key from `/api/agents/bootstrap` and refreshes it every
`FERNET_REFRESH_SEC` (default 600 s). Modules call
`insert_record_enc(...)` and `fetch_one_dec(...)`. Encryption is
invisible to module code, driven entirely by the table-to-field map at
the top of `enc_db.py`.
