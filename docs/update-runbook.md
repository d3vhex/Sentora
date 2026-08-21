# Update / Upgrade Runbook

How new Sentora releases land in a production deployment: server stack
upgrades, agent binary rollout, DB migrations, and rollback.

> Audience: SecOps lead + DevOps engineer running the upgrade window.

See also [production-deployment.md](production-deployment.md) for sizing,
backup and monitoring.

---

## 1. Versioning Policy

Semantic versioning: `vMAJOR.MINOR.PATCH`.

| Tier | Means | Compatibility | Operator impact |
| :--- | :--- | :--- | :--- |
| PATCH | Bug fixes, UI tweaks, telemetry corrections | Full | Restart server containers. Agents untouched. |
| MINOR | New features, additive endpoints, optional DB columns | Backward compatible | Restart server. Optional agent rollout. |
| MAJOR | Breaking API/DB/agent-protocol changes | Not guaranteed | Maintenance window, coordinated agent rollout. |

Every release ships with a `CHANGELOG.md` entry under **Breaking** / **Added**
/ **Fixed**, a git tag, and — for MAJOR — a `docs/upgrade-X.Y.md` with
bespoke steps.

### 1.1 Agent-side changes need a rebuild

This catches people out. A release that changes anything under `Sentora/` has
**no effect on your fleet until the binary is rebuilt and redeployed**.
Restarting the server does nothing for it. Section 3 covers the rollout.

Recent examples where the fix lives entirely in the agent: the boot-time
restart failure, the at-rest encryption map, the Windows event source field.

---

## 2. Server Stack Upgrade

### 2.1 Standard upgrade (PATCH / MINOR)

Pre-flight (15 minutes):

```bash
# 1. Fresh backup before touching anything
/opt/sentora/backup.sh                    # production-deployment.md §4.2

# 2. Note the current version
git -C /opt/sentora describe --tags --always

# 3. Confirm health BEFORE upgrading
curl -fsS http://localhost:8000/health
docker compose ps                          # all "running (healthy)"

# 4. Record a baseline to compare against afterwards
python scripts/api_smoke_test.py | tail -20
```

Upgrade (5 to 10 minutes of app/worker downtime; DB stays up):

```bash
cd /opt/sentora

git fetch --tags
git checkout v1.4.0
less CHANGELOG.md

# New settings? .env is not updated for you.
diff <(grep -oP '^[A-Z_]+(?==)' .env.example | sort) \
     <(grep -oP '^[A-Z_]+(?==)' .env | sort)

# Rebuild only the services that ship code
docker compose build --no-cache \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive
```

Post-flight:

```bash
curl -fsS http://localhost:8000/health

# RBAC actually enforced? A zero here is an outage, not a warning.
docker logs sentora-server | grep '\[Auth\] Routes'

# Threat feeds still refreshing?
docker logs sentora-server | grep ThreatIntel | tail -5

# No auth bypasses, no 5xx
python scripts/api_smoke_test.py

docker logs --tail 50 sentora-ai-worker-defensive
```

Expected: all containers healthy, agents continue pushing telemetry, AI
workers resume within 30 seconds, smoke test reports 0 bypasses and 0 5xx.

### 2.2 Database migrations

There is no separate migration tool. Schema changes are applied lazily by
idempotent `ALTER TABLE ... ADD COLUMN` calls inside the relevant
ensure-table functions:

- `init_hub_db()` / `init_enrollment_tables()` / `init_session_table()` /
  `init_email_templates_table()` in `app.py`, at `main_process_start`.
- `save_ai_results` in `ai/utils.py` backfills `ai_analysis_results`.
- `set_ai_cache` in `ai/utils.py` widens the `ai_cache` key column.
- `_ensure_playbook_runs_table` in `app.py` backfills `playbook_runs`.

Practical consequence: a fresh container picks up the new code and the first
INSERT or SELECT triggers the ALTER. No manual step for PATCH / MINOR.

**One caveat worth knowing.** A migration that only runs on a *successful*
code path never runs on a deployment where that path is failing. The
`threat_intel.last_seen` column was added by the feed refresher's own ALTER,
which only executed after a feed returned data — so on a deployment whose
feeds were blocked, the column never appeared and anything querying it broke.
Migrations now live in the `init_*` functions that run unconditionally at
startup. Apply the same rule to anything you add.

For MAJOR releases needing bulk transforms, the release ships
`scripts/migrate-X.Y-to-X.Z.py` and the upgrade doc says so explicitly.

### 2.3 MAJOR upgrade

Additional pre-flight:

- Maintenance window, 30 to 60 minutes.
- Host snapshot (VM disk or LVM snapshot of `/var/lib/docker`).
- Re-read the version-specific upgrade doc.

```bash
# 1. Stop code containers, keep DB/OpenSearch/RabbitMQ up
docker compose stop app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 2. Bespoke migration, only when the CHANGELOG says so
docker run --rm --network sentora-community-edition_default \
    -v $(pwd):/work -w /work \
    python:3.10-slim python scripts/migrate-1.x-to-2.0.py

# 3. New code
git checkout v2.0.0
docker compose build --no-cache

# 4. Back up
docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

curl -fsS http://localhost:8000/health
```

Agents on the previous major can keep streaming telemetry for a grace period
defined per release (typically one minor version).

---

## 3. Agent Rollout

### 3.1 Build

```powershell
# Windows build host
cd C:\path\to\Sentora\Sentora
.\build_agent.ps1
```

```bash
# Linux build host
cd /opt/sentora/Sentora
./build_agent.sh
```

Outputs `main.exe` / `main` next to the script, and prints a SHA-256. Record
it — it is what you verify against after publishing.

### 3.2 Publish

The server serves the binary from `/api/agent/download/{linux,windows}`.
Restart the app container so the on-disk binary is picked up:

```bash
docker compose restart app
```

Verify:

```bash
curl -fsS -H "X-Agent-Key: <enrolled-key>" \
    http://localhost:8000/api/agent/download/windows -o agent.zip
unzip -p agent.zip main.exe | sha256sum
```

### 3.3 Canary

```powershell
# Admin PowerShell on the canary endpoint
Stop-ScheduledTask -TaskName SentoraAgent -EA SilentlyContinue
Get-Process main -EA SilentlyContinue | Stop-Process -Force
iwr -useb 'https://soc.example.com/api/agent/deploy/windows?token=<TOKEN>' | iex
```

The installer detects the existing install, stops the task, waits for the
binary lock to release, extracts in place preserving `config.json` (identity
unchanged), and re-registers the scheduled task.

**Verify more than "it started."** The agent now takes a single-instance lock
and retries its server bootstrap rather than exiting, so a running process is
no longer proof that it connected:

```powershell
Get-ScheduledTaskInfo -TaskName SentoraAgent, SentoraAgentWatchdog |
    Select TaskName, LastRunTime, LastTaskResult

Get-Content "C:\Program Files\Sentora-Agent\agent.log" -Tail 30
```

Look for `Agent bootstrap OK`. If you see `Agent bootstrap attempt N failed …
retrying`, it is alive but cannot reach the server — check network and
`FERNET_KEY`. In the UI, `last_seen` should update within 60 seconds.

**Then reboot the canary.** That is the only way to test the boot path, and it
is where the agent used to die permanently.

### 3.4 Phased rollout

| Phase | Population | Duration | Exit criteria |
| :--- | :--- | :--- | :--- |
| 1. Canary | 3 to 5 friendly endpoints | 24 h + one reboot | No crashes, telemetry steady, agent survives reboot |
| 2. Wave 1 | 10% of fleet | 3 to 7 days | RAM/CPU baseline drift under 20% |
| 3. Wave 2 | 50% | 1 week | OpenSearch index rate stable, no spike in failed automations |
| 4. Full | 100% | within 1 week | All `last_seen` under 2 minutes |

Any MDM can run the deploy one-liner (Intune, JAMF, Ansible).

### 3.5 Linux

```bash
ssh canary.host
sudo systemctl stop sentora-agent
sudo curl -fsSL "https://soc.example.com/api/agent/deploy/linux?token=<TOKEN>" | sudo bash
sudo systemctl status sentora-agent
sudo journalctl -u sentora-agent -n 30
```

---

## 4. Rollback

### 4.1 Server (PATCH / MINOR)

```bash
cd /opt/sentora
docker compose stop app ingest ai-worker-automation ai-worker-manual ai-worker-defensive
git checkout v1.3.5
docker compose build --no-cache \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive
docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive
curl -fsS http://localhost:8000/health
```

DB rollback is usually unnecessary: schema changes are additive
`ADD COLUMN`, which the older binary ignores.

**Check whether the target version needs fewer `.env` values than the current
one.** Compose refuses to start when a required variable is missing, but a
rolled-back image that does not know about a variable simply ignores it —
which is harmless. The dangerous direction is rolling *forward* without the
new values.

### 4.2 Server (MAJOR)

```bash
virsh snapshot-revert sentora-host pre-v2.0-upgrade
docker compose up -d
```

Without a snapshot, restore from the pre-flight backup:

```bash
docker compose stop app ingest ai-worker-automation ai-worker-manual ai-worker-defensive
docker compose down
docker volume rm sentora-community-edition_mysql_data \
                 sentora-community-edition_opensearch_data

docker compose up -d db
docker exec -i sentora-db mysql -uroot -p"$DB_PASSWORD" < /var/backups/sentora/latest/mysql.sql

git checkout v1.x.y
docker compose up -d
```

**Do not delete the `sentora_data` volume**, and restore `.env` from the same
backup. Those hold the two Fernet keys; restoring a database with mismatched
keys leaves every encrypted column unreadable. The UI will show
`<decryption failed — key mismatch>`, which is the symptom to watch for after
any restore.

Allow time for OpenSearch to re-index from MySQL telemetry.

### 4.3 Agent

```powershell
Stop-ScheduledTask -TaskName SentoraAgent
Copy-Item C:\Backups\main.exe.previous "C:\Program Files\Sentora-Agent\main.exe" -Force
Start-ScheduledTask -TaskName SentoraAgent
```

Or roll the server back — it then serves the older binary — and re-run the
deploy one-liner.

Agent identity (`config.json`: `agent_name`, `agent_key`) survives rollback.
No re-enrolment.

---

## 5. Breaking Change Policy

Breaking changes are announced two minor versions ahead where possible.
Release notes call out removed endpoints or renamed fields, schema changes
needing manual migration, and agent protocol bumps.

| Version | Behaviour of removed `X` |
| :--- | :--- |
| v1.5 | Works, warning logged |
| v1.6 | Works, warning logged, replacement `Y` documented |
| v2.0 | Removed |

Subscribe to the release feed and read `CHANGELOG.md` before every upgrade.

---

## 6. Upgrade Window Checklist

**T minus 1 day**

- [ ] Backup taken and restore-tested on staging, including Fernet keys.
- [ ] CHANGELOG read; version-specific runbook reviewed.
- [ ] `.env` diffed against `.env.example` for new required values.
- [ ] Maintenance window communicated.
- [ ] Host snapshot taken (MAJOR only).

**T zero**

- [ ] Stack upgraded per Section 2.
- [ ] `/health` green; all containers healthy.
- [ ] Boot log shows a non-zero `permission-gated` route count.
- [ ] `api_smoke_test.py`: 0 auth bypasses, 0 5xx.
- [ ] AI workers consuming; threat feeds refreshing.
- [ ] Agents heart-beating.
- [ ] Canary agent upgraded, observed 10 minutes, **and rebooted**.

**T plus 1 day**

- [ ] No spike in `automations.status='failed'`.
- [ ] AI insight rate matches baseline.
- [ ] No tickets attributable to the upgrade.
- [ ] Wave 1 rollout started.

**T plus 1 week**

- [ ] Full fleet rolled out; all `last_seen` under 2 minutes.
- [ ] Old binaries archived from the MDM image library.
- [ ] Lessons learned filed.

---

## 7. Signed Update Bundles (Enterprise)

Community releases ship as plain Docker images plus PyInstaller binaries.
Verification is the operator's job — compare the SHA-256 against the release
page.

Enterprise ships signed bundles: one tarball with server images, agent
binaries and the model snapshot, signed by the project release key and
verified before install. This is the recommended path for air-gap
environments where supply-chain risk matters. Signing infrastructure, key
rotation and bundle format are covered in the Enterprise onboarding pack.
