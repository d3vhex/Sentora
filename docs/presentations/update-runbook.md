# Update / Upgrade Runbook

Companion technical document for the DTCloud pitch deck. Covers how new
Sentora releases land in a production deployment: server stack
upgrades, agent binary rollout, DB migrations, and rollback procedures.

> Audience: SecOps lead + DevOps engineer responsible for the upgrade
> window.

---

## 1. Versioning Policy

Semantic versioning: `vMAJOR.MINOR.PATCH`.

| Tier | What it means | Backward compatibility | Operator impact |
| :--- | :--- | :--- | :--- |
| PATCH (vX.Y.Z → vX.Y.Z+1) | Bug fixes, UI tweaks, telemetry corrections | Full | Restart server containers. Agents untouched. |
| MINOR (vX.Y → vX.Y+1) | New features, additive endpoints, optional DB columns | Backward compatible | Restart server. Optional agent rollout. |
| MAJOR (vX → vX+1) | Breaking API/DB/agent-protocol changes | Not guaranteed | Maintenance window, agent rollout coordinated. |

Every release ships with:

- `CHANGELOG.md` entry under three sections: **Breaking** / **Added** / **Fixed**.
- Git tag (`vX.Y.Z`) and signed release notes.
- Optional `docs/upgrade-X.Y.md` for MAJOR releases with bespoke steps.

---

## 2. Server Stack Upgrade

### 2.1 Standard upgrade (PATCH / MINOR)

Pre-flight (15 minutes):

```bash
# 1. Take a fresh backup before touching anything
/opt/sentora/backup.sh                          # see production-deployment.md §4.2

# 2. Note the current version
docker exec sentora-server grep -m1 'VERSION' /app/VERSION 2>/dev/null || \
    git -C /opt/sentora describe --tags --always

# 3. Verify health is green BEFORE upgrade
curl -fsS http://localhost:8000/health
docker compose ps    # all containers should be "running (healthy)"
```

Upgrade (5 to 10 minutes downtime for app/workers; DB stays up):

```bash
cd /opt/sentora

# 4. Fetch the new release
git fetch --tags
git checkout v1.4.0       # adjust to the actual target

# 5. Review the changelog
less CHANGELOG.md

# 6. Rebuild only the services that ship code
docker compose build --no-cache \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 7. Rolling restart of code containers (DB, RabbitMQ, OpenSearch, Ollama untouched)
docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 8. Smoke checks
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/devices | head -c 200
docker logs --tail 50 sentora-ai-worker-defensive
```

Expected outcome: all `running (healthy)`, agents continue to push
telemetry, AI workers resume processing within 30 seconds.

### 2.2 Database migrations

Sentora does not ship a separate migration tool. Schema changes are
applied lazily by idempotent `ALTER TABLE ... ADD COLUMN ...` calls
inside the relevant ensure-table functions:

- `save_ai_results` in `ai/utils.py` backfills `ai_analysis_results`
  columns (`source_data`, `proposed_action`, `proposed_target`,
  `shadow_status`, `shadow_decided_*`).
- `_ensure_playbook_runs_table` in `app.py` backfills `playbook_runs`.
- `_sanitize_db_name` keeps DB naming consistent for hostnames
  containing hyphens.

Practical consequence: a fresh container picks up the new code, the
first INSERT or SELECT triggers the ALTER. No manual `migrate up`
step is required for PATCH / MINOR.

For MAJOR releases that need bulk transforms, the release ships a
dedicated `scripts/migrate-X.Y-to-X.Z.py` and the upgrade docs call it
out explicitly.

### 2.3 MAJOR upgrade

Additional pre-flight:

- Schedule a maintenance window (30 to 60 minutes).
- Snapshot the host (VM disk snapshot or LVM snapshot of `/var/lib/docker`).
- Re-read the version-specific upgrade doc.

Execution:

```bash
# 1. Stop ingest and workers, keep DB/OpenSearch/RabbitMQ up
docker compose stop app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 2. Run the bespoke migration script (only when CHANGELOG says so)
docker run --rm --network sentora-community-edition_default \
    -v $(pwd):/work -w /work \
    python:3.10-slim python scripts/migrate-1.x-to-2.0.py

# 3. Pull the new code and rebuild
git checkout v2.0.0
docker compose build --no-cache

# 4. Bring code containers back
docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 5. Verify and unblock agents
curl -fsS http://localhost:8000/health
```

After the server is healthy on v2.0.0, the agent rollout (Section 3)
begins. Agents on v1.x can keep streaming telemetry for a grace period
defined per release (typically one minor version).

---

## 3. Agent Rollout

### 3.1 Build a new agent binary

```powershell
# On the Windows build host
cd C:\Users\pc\Desktop\Sentora-Community-Edition\Sentora
.\build_agent.ps1

# On a Linux build host
cd /opt/sentora/Sentora
./build_agent.sh
```

Outputs `main.exe` and `main` next to the script. Note the SHA-256
emitted at the end:

```
[+] Built main.exe  (38.4 MB)
    sha256: 9a8b7c...
```

### 3.2 Publish to the server

The server serves the binary via
`/api/agent/download/{linux,windows}`. After building, restart the
server container so the on-disk binary is picked up:

```bash
docker compose restart app
```

Verify the hash matches:

```bash
curl -fsS -H "X-Agent-Key: <some-enrolled-key>" \
    http://localhost:8000/api/agent/download/windows \
    -o agent.zip
unzip -p agent.zip main.exe | sha256sum
```

### 3.3 Deploy to one endpoint (canary)

```powershell
# Admin PowerShell on a canary endpoint
Stop-ScheduledTask -TaskName SentoraAgent -EA SilentlyContinue
Get-Process main -EA SilentlyContinue | Stop-Process -Force
iwr -useb 'https://soc.example.com/api/agent/deploy/windows?token=<TOKEN>' | iex
```

The deploy script:

1. Detects the existing install at `C:\Program Files\Sentora-Agent`.
2. Stops the scheduled task and waits for the binary lock to release.
3. Downloads the new agent zip with the per-agent key.
4. Extracts in place, preserving `config.json` (agent identity unchanged).
5. Re-registers the scheduled task and starts it.

Verify in the UI: agent's `last_seen` updates within 60 seconds, AI
Analysis tab keeps producing insights, no errors in `agent.log`.

### 3.4 Phased rollout

| Phase | Population | Duration | Exit criteria |
| :--- | :--- | :--- | :--- |
| 1. Canary | 3 to 5 known-friendly endpoints | 24 h | No crashes, telemetry steady, no operator complaints |
| 2. Wave 1 | 10% of fleet | 3 to 7 days | RAM/CPU baseline drift under 20% |
| 3. Wave 2 | 50% of fleet | 1 week | OpenSearch index rate stable, no spike in failed automations |
| 4. Full | 100% | within 1 week | All `last_seen` under 2 minutes |

Rollout tooling: integrate with your existing MDM (Intune, JAMF, Ansible).
The deploy one-liner is a single PowerShell or bash command, so any
fleet management tool can run it.

### 3.5 Linux agent rollout

```bash
# Build artefacts already in place via build_agent.sh
ssh canary.host
sudo systemctl stop sentora-agent
sudo curl -fsSL "https://soc.example.com/api/agent/deploy/linux?token=<TOKEN>" | sudo bash
# Installer drops main, writes config.json, registers systemd unit, starts it.
```

---

## 4. Rollback

### 4.1 Server rollback (PATCH / MINOR)

```bash
cd /opt/sentora

# 1. Stop code containers
docker compose stop app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 2. Check out the previous tag
git checkout v1.3.5

# 3. Rebuild and bring back up
docker compose build --no-cache \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive
docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 4. Smoke check
curl -fsS http://localhost:8000/health
```

DB rollback usually not needed for PATCH / MINOR: schema changes are
additive `ALTER TABLE ... ADD COLUMN` which the older binary ignores.

### 4.2 Server rollback (MAJOR)

```bash
# Restore the pre-upgrade snapshot
virsh snapshot-revert sentora-host pre-v2.0-upgrade
# or the equivalent LVM/disk snapshot operation
docker compose up -d
```

If a snapshot wasn't taken, restore from the backup taken in Section 2.1
pre-flight:

```bash
# 1. Stop app and workers
docker compose stop app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 2. Wipe MySQL and OpenSearch volumes
docker compose down
docker volume rm sentora-community-edition_mysql_data sentora-community-edition_opensearch_data

# 3. Bring DB up and restore
docker compose up -d db
docker exec -i sentora-db mysql -uroot -p"$DB_PASSWORD" < /var/backups/sentora/latest/mysql.sql

# 4. Check out old version and bring back up
git checkout v1.x.y
docker compose up -d
```

Allow extra time for OpenSearch to re-index from the MySQL telemetry
(or accept that historical full-text search loses some recent data
until reindex completes).

### 4.3 Agent rollback

```powershell
# Admin PowerShell on the affected endpoint
Stop-ScheduledTask -TaskName SentoraAgent
# If your MDM keeps the previous binary:
Copy-Item C:\Backups\main.exe.previous "C:\Program Files\Sentora-Agent\main.exe" -Force
Start-ScheduledTask -TaskName SentoraAgent
```

Or re-deploy the previous server release: roll back the server (it now
serves the older binary), then re-run the deploy one-liner on the
endpoints.

Agent identity (`config.json` with `agent_name` and `agent_key`) is
preserved across rollbacks. No re-enrolment.

---

## 5. Breaking Change Policy

Breaking changes are announced **two minor versions in advance** when
possible. The release notes will explicitly call out:

- Removed endpoints or renamed fields.
- DB schema changes that require manual migration.
- Agent protocol bumps.

Deprecation pattern (example):

| Version | Behaviour of removed `X` |
| :--- | :--- |
| v1.5 | `X` still works, warning logged |
| v1.6 | `X` still works, warning logged, replacement `Y` documented |
| v2.0 | `X` removed entirely |

Operators should subscribe to the release feed (GitHub Releases / RSS)
and review `CHANGELOG.md` before every upgrade.

---

## 6. Upgrade Window Checklist

Hand this to whoever runs the change request.

**T minus 1 day**

- [ ] Backup taken and validated (restore-test on staging).
- [ ] CHANGELOG read; any version-specific runbook reviewed.
- [ ] Maintenance window communicated to operators.
- [ ] Snapshot of the host taken (for MAJOR upgrades).

**T zero**

- [ ] Stack upgraded per Section 2.
- [ ] Health checks green.
- [ ] AI workers consuming queue.
- [ ] Agents heart-beating.
- [ ] Canary endpoint upgraded and observed for 10 minutes.

**T plus 1 day**

- [ ] No spike in `automations.status='failed'`.
- [ ] AI insight emit rate matches baseline.
- [ ] No support tickets attributable to the upgrade.
- [ ] Wave 1 agent rollout started.

**T plus 1 week**

- [ ] Full fleet rolled out.
- [ ] Old binaries archived from MDM image library.
- [ ] Lessons learned filed.

---

## 7. Signed Update Bundles (Enterprise)

Community releases ship as plain Docker images plus PyInstaller binaries.
Verification is up to the operator (compare SHA-256 from the release page).

Enterprise tier ships **signed update bundles**: a single tarball
containing the server images, the agent binaries, and the LLM model
snapshot, signed by the project's release key. The Sentora updater
verifies the signature before installing. This is the recommended path
for air-gap environments where supply-chain risk is a concern.

The signing infrastructure, key rotation policy and bundle format are
covered in the Enterprise customer onboarding pack.
