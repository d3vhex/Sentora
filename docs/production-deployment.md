# Production Deployment Guide

Hardware sizing, network topology, TLS handling, persistence, monitoring and
the air-gap path.

> Audience: SecOps lead + DevOps engineer standing up a production instance.

See also [update-runbook.md](update-runbook.md) for upgrades and rollback, and
[Sentora_Architecture.md](Sentora_Architecture.md) for how the pieces fit.

---

## 1. Hardware Sizing

### 1.1 Per-tier reference

| Tier | CPU | RAM | Disk | Concurrent agents | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Lab / POC | 4 cores | 12 GB | 40 GB SSD | up to 5 | OpenSearch heap pinned to 1 GB |
| Small team | 8 cores | 16 GB | 100 GB SSD | 10 to 50 | Compose defaults work |
| Mid (default production) | 16 cores | 32 GB | 250 GB NVMe | 50 to 300 | Move OpenSearch to its own node |
| Large | 32+ cores | 64 GB+ | 1 TB+ NVMe | 300 to 1000 | OpenSearch cluster, separate RabbitMQ host |

### 1.2 Per-service idle footprint

| Service | RAM idle | CPU idle | Disk growth |
| :--- | :--- | :--- | :--- |
| `ollama` (llama3.2:3b) | ~3 GB | low | ~2 GB model snapshot once |
| `opensearch` | ~2 GB | low | grows with retention |
| `mysql` | 500 MB to 1 GB | low | grows with retention |
| `rabbitmq` | ~300 MB | low | negligible |
| `app` + `ingest` + 3 AI workers | ~1 GB combined | low | logs only |

Peak load (large LLM inference): Ollama can spike to 5 to 7 GB. Keep headroom.

### 1.3 GPU and model notes

A GPU is **not required**. `llama3.2:3b` runs on CPU at 20 to 60 s per
inference. Ollama auto-detects CUDA / Metal / ROCm; with a GPU, average
latency drops under 3 s.

Smaller and faster:

```ini
OLLAMA_MODEL=qwen2.5:1.5b   # faster, weaker analysis
OLLAMA_MODEL=phi3:mini
```

Larger, with a GPU:

```ini
OLLAMA_MODEL=llama3.1:8b
```

**On concurrency.** `AI_CONCURRENCY` defaults to 1 and should usually stay
there. Ollama serialises requests per model unless `OLLAMA_NUM_PARALLEL` is
raised, and on CPU inference more parallelism splits the same compute rather
than adding throughput. Raise both together, on a GPU box, and check the
result — every inference logs its latency:

```bash
docker logs sentora-ai-worker-automation | grep '\[ai\]'
```

`AI_TIMEOUT_SEC` (default 120) bounds a single inference. It was 600, which
is a hang rather than a timeout: one stuck request held the worker's only slot
while the queue backed up behind it.

---

## 2. Network Topology

### 2.1 Recommended layout

```
                Internet
                   │
                   │  (only if remote endpoints push telemetry)
                   ▼
          ┌──────────────────┐
          │  reverse proxy   │   nginx / Traefik / Caddy
          │  TLS terminate   │   - 443 → app :8000
          │                  │   - 5001 (or tunnelled) → ingest :5001
          └──────────────────┘
                   │ internal network
                   ▼
          ┌──────────────────┐
          │  Sentora host    │
          │  docker compose  │
          └──────────────────┘
                   │ internal LAN
                   ▼
          Endpoint fleet (agents)
```

### 2.2 Ports

| Direction | Port | Protocol | Required when |
| :--- | :--- | :--- | :--- |
| Agent → server | 5011/tcp | length-framed binary inside TLS | `TLS_ENABLED=1` (the target state) |
| Agent → server | 5001/tcp | length-framed binary, **in the clear** | until every agent is rebuilt |
| Agent → server | 8000/tcp | HTTP(S) REST + WS | always — the agent's own channel (`/agent-link`) |
| Operator → server | 8000/tcp | HTTP(S) | UI access |

**Nothing connects to an agent.** There is no inbound port on a monitored
host: config push, SOAR execute, the console and the screen stream all travel
back down the websocket the agent opens. A firewall rule allowing the server
to reach endpoints is not needed and should be removed if one exists.

`5001` and `5011` carry the same protocol; `5011` wraps it in TLS. Both listen
by default because a fleet does not migrate in one step, and closing `5001`
before the agents are rebuilt stops their telemetry with no symptom on either
side — a host that went quiet is indistinguishable from a host with nothing to
report. The ingest log names each agent still arriving in the clear, once
each:

```
[!] web-01 is sending telemetry in the clear on port 5001. ...
```

When that stops appearing, set `INGEST_TLS_REQUIRED=1` and stop publishing
`5001`. An un-migrated agent is then refused, which is a symptom somebody can
see.

Only `app` and `ingest` publish on all interfaces. Everything else binds to
`BIND_ADDR`, which defaults to `127.0.0.1`:

| Service | Port | Bound to |
| :--- | :--- | :--- |
| `db` | 3307 | `BIND_ADDR` |
| `rabbitmq` | 5672, 15672 | `BIND_ADDR` |
| `opensearch` | 9200, 9600 | `BIND_ADDR` |
| `opensearch-dashboards` | 5601 | `BIND_ADDR` |
| `ollama` | 11434 | `BIND_ADDR` |

**Do not widen `BIND_ADDR` to expose one of them.** None of these
authenticate in the default configuration: OpenSearch runs with
`DISABLE_SECURITY_PLUGIN` and Dashboards is an unauthenticated view of every
log the platform has collected. Publish through the same reverse proxy and
auth as `app` instead.

The "Open Dashboards" button in Log Explorer links to port 5601 on the
server's hostname, so it works from the host itself; remote operators need
that proxy.

### 2.3 Reverse proxy template (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name soc.example.com;

    ssl_certificate     /etc/letsencrypt/live/soc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 100m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 86400;
    }
}

# Ingest is binary TCP, not HTTP — nginx `stream`, or expose 5001 directly.
stream {
    upstream sentora_ingest { server 127.0.0.1:5001; }
    server {
        listen 5001;
        proxy_pass sentora_ingest;
        proxy_timeout 60s;
    }
}
```

`X-Forwarded-For` matters: the audit log and login-attempt records read it to
attribute the source IP.

---

## 3. TLS / Certificate Handling

> **These settings did nothing until recently.** `TLS_ENABLED`, `TLS_CERT` and
> `TLS_KEY` were described in this guide, in `.env.example`, and in the
> instructions `certs/generate_certs.py` prints when it finishes — and read by
> no line of code. Setting `TLS_ENABLED=1` produced a console that came up
> cleanly on plain HTTP while its operator had every reason to believe it was
> HTTPS, with the login form and the session cookie crossing the network in
> clear text. If you are upgrading from a build before this section changed,
> **assume the console was never encrypted** and rotate any credential that was
> typed into it.

### 3.1 Three patterns

1. **Reverse proxy terminates TLS (recommended).** App listens on plain HTTP
   at `:8000`, ingest plain TCP at `:5001`. Rotation is a proxy reload. Set
   `SESSION_COOKIE_SECURE=1` by hand — TLS terminating at a proxy is invisible
   from inside the app, so nothing can infer it for you.
2. **App container terminates TLS.** Cert at `certs/server.crt` + `.key`, and
   in `.env`:
   ```ini
   TLS_ENABLED=1
   TLS_CERT=/app/certs/server.crt
   TLS_KEY=/app/certs/server.key
   ```
   Rotation requires `docker compose restart app ingest`. Both read the same
   pair; `app` is the only writer.
3. **Self-signed, lab only.** With `TLS_ENABLED=1` and no certificate
   present, the app generates one on first boot into the `sentora_certs`
   volume; `python certs/generate_certs.py --force` replaces it. Each
   deployment gets its own key, and the key never leaves the machine that made
   it — nothing is bundled any more, because a committed private key gave
   every install the same published TLS identity. Browsers will warn: the CA
   is self-signed and trusts nothing. Use a real certificate for anything
   reachable beyond your own network.

**A certificate that cannot be loaded stops the server.** `TLS_ENABLED=1` with
a missing, unreadable or mismatched pair exits with a message naming the file,
rather than falling back to plain HTTP. Falling back is how the original
problem would come back wearing an error nobody reads in a container log.

### 3.1.1 What the agent has to trust

Against a self-signed server the agent verifies and therefore fails, which is
correct — an unverified TLS connection is encrypted to whoever answered. Give
it the CA:

```jsonc
// config.json, beside agent_name / agent_key / server_url
{
  "server_url": "https://soc.example.com:8000",
  "server_ca": "C:\Sentora\rootCA.crt"
}
```

`SENTORA_CA_CERT` and `--ca` do the same thing. Copy `certs/rootCA.crt` from
the server — the certificate, never `rootCA.key`.

The transport is derived from `server_url`, not configured separately: an
`https://` console means telemetry goes to `5011` inside TLS and the channel
goes to `wss://`. Two settings that had to agree, with nothing making them
agree, would be wrong in exactly the deployment that believed it was
encrypted. `--ingest-port` still overrides the port for a bastion setup.

With a real certificate from a public CA, `server_ca` is unnecessary — the
system trust store already has it.

### 3.2 Session cookies require this

Whichever pattern you choose, **set `SESSION_COOKIE_SECURE=1` once TLS is
terminating anywhere in front of the UI.** The session cookie is what
authenticates the operator; without `Secure` it can travel over plain HTTP.

The inverse is also a trap: setting it to `1` while serving plain HTTP means
the browser silently drops the cookie and nobody can log in.

Unset, it now follows `TLS_ENABLED` rather than defaulting to `0`. The two had
to agree and nothing made them, so turning on TLS and leaving this alone gave
an HTTPS console whose session cookie was still allowed onto plain HTTP. An
explicit value still wins — which is what pattern 1 above needs, because a
proxy terminating TLS is invisible from inside this process.

`SESSION_COOKIE_SAMESITE` defaults to `Lax`, which blocks the cross-site
POST/XHR that CSRF needs. Only a split-origin deployment needs `None`, and
that requires `SESSION_COOKIE_SECURE=1`.

### 3.3 Rotation

Reverse proxy:

```bash
nginx -t && nginx -s reload      # no downtime
```

App-terminated:

```bash
docker compose cp new.crt app:/app/certs/server.crt
docker compose cp new.key app:/app/certs/server.key
docker compose restart app ingest
```

`ingest` reads the same volume read-only, so it has to be restarted too — a
console on the new certificate and telemetry still presenting the old one is
the kind of half-migration that shows up as a few hosts going quiet.

**Agent trust:** agents verify against the system trust store, plus `server_ca`
if one is configured. Rotating a certificate issued by a public CA is
server-side only. Rotating the *self-signed CA* — which `--force` does — is
not: every agent holding the old `rootCA.crt` will refuse the new server and
stop sending. Replace the file on the endpoints first, or re-enrol them.

### 3.4 Why not mTLS, and what it would take

Client certificates were considered for agent authentication and deliberately
not implemented. The reasoning, so it does not have to be reconstructed later:

**What authenticates an agent today.** Every agent route checks `X-Agent-Key`
against a per-agent secret issued at enrolment. The control channel refuses
the fleet-wide key outright, because it carries `/self_destruct` among other
things and a leaked master key should not be able to open one against every
endpoint at once. Ingest is the weaker half — it identifies an agent by the
name in the frame, and TLS gives it a private channel but not a proof of who
is on the other end.

**What mTLS would add.** A key that cannot be replayed from a captured log or
a config file, and revocation that does not depend on the server remembering
to reject a secret.

**Why it is not in yet.** A client certificate needs an enrolment flow that
issues one, an agent that stores it as securely as it stores the key it
already has, a CA whose private key lives on the server that signs them, and a
revocation path — a CRL or a short lifetime with renewal. Every one of those
is a way for an agent to lose the ability to report, and an agent that cannot
report is invisible in precisely the way this platform exists to prevent. The
enrolment flow is the part to build first, and it is not a smaller change than
the transport work above.

**The honest summary:** TLS here protects the telemetry in transit and proves
the *server's* identity to the agent. It does not prove the agent's identity
to the server beyond a bearer secret. If your threat model includes an
attacker who can read an endpoint's config file, that secret is what they get,
and mTLS is the thing that would help.

---

## 4. Data Persistence and Backup

### 4.1 What to back up

| Path | Contains | Priority | Restore |
| :--- | :--- | :--- | :--- |
| Volume `mysql_data` | All telemetry, agents, AI insights, automations, sessions | High | `mysqldump --all-databases` daily |
| Volume `sentora_data` | `data/fernet.key` — the **agent** telemetry key | **Critical** | Encrypted vault |
| Volume `sentora_certs` | The deployment's TLS certificate and self-signed CA | High | Encrypted vault (it holds `server.key`) |
| File `.env` | `FERNET_KEY` (server key), DB and broker passwords, agent shared secret | **Critical** | Encrypted vault |
| Volume `opensearch_data` | Log search index | Medium | Rebuildable from MySQL |
| Volume `ollama` | Model weights | Low | Re-pull, or restore for air-gap |
| `Sentora/main*` | Built agent binaries | Low | Rebuild via `build_agent.sh/ps1` |

**Losing either Fernet key makes the corresponding encrypted data unreadable,
and there is no in-place rotation.** The agent key lives in the `sentora_data`
volume; before that volume existed it was regenerated on every
`docker compose down && up`, silently orphaning previously encrypted
telemetry. If you are restoring a deployment from before that change, expect
some historical rows to be undecryptable — the UI marks them
`<decryption failed — key mismatch>` rather than showing ciphertext.

Losing `sentora_certs` is recoverable but not free: a new certificate and a
new CA are generated, and every agent holding the old `rootCA.crt` refuses the
new server and stops sending until the file is replaced on the endpoint. The
backup script tars every volume `docker-compose.yaml` declares, so this one is
picked up without anybody having to remember it.

### 4.2 Backup script

`scripts/backup_state.py` does all of this, cross-platform, and its restore
path is exercised by tests:

```bash
python scripts/backup_state.py                       # dated backup
python scripts/backup_state.py --list
docker compose down                                  # required before restore
python scripts/backup_state.py --restore backups/2026-08-25T1401
```

It takes both a `mysqldump --all-databases` and a tar of every volume compose
declares — read from `docker-compose.yaml`, so a volume added later is not
silently missing from every backup after. It deliberately does **not** copy
`.env`; that belongs in a secret store, not in a directory people tar up and
move around, and the script says so at the end of every run.

Two things this got wrong before they were tested, both worth knowing if you
write your own:

- `docker -v` reads a **relative** path as a named volume rather than a host
  directory, and the error names the drive letter as an invalid character,
  which looks like a quoting bug.
- the restore printed success on a run where every archive had failed. A
  restore that reports success it did not have is worse than one that fails —
  the failure is noticed now, the false success the next time you need the
  data.

The hand-written equivalent, if you would rather run it from cron on a Linux
host:

```bash
#!/usr/bin/env bash
# /opt/sentora/backup.sh
set -euo pipefail
TS=$(date +%F-%H%M)
DEST=/var/backups/sentora/$TS
mkdir -p "$DEST"

# MySQL — includes every agent database plus userdb
docker exec sentora-db mysqldump --all-databases --single-transaction \
    -uroot -p"$(awk -F= '/^DB_PASSWORD=/{print $2}' /opt/sentora/.env)" \
    > "$DEST/mysql.sql"

# Agent Fernet key, which now lives in a named volume
docker run --rm -v sentora_data:/src -v "$DEST":/dst alpine \
    sh -c 'cp -a /src/. /dst/sentora_data/'

# Server secrets
cp /opt/sentora/.env "$DEST/"

tar czf /var/backups/sentora-$TS.tgz -C /var/backups/sentora "$TS"
aws s3 cp /var/backups/sentora-$TS.tgz s3://my-backups/sentora/
```

Daily via systemd timer or cron. 30 days hot, 1 year cold.

### 4.3 Restore test

Quarterly:

1. Spin up a sandbox host.
2. Restore the latest backup, including both Fernet keys.
3. Confirm the UI logs in, dashboards populate, an agent re-enrols, **and
   that historical alerts decrypt** — that last one is what proves the key
   restore worked.
4. Document any deviation.

Not optional, and not theoretical. On the development machine Docker Desktop
was reset and every named volume went with it: `mysql_data` — all telemetry,
every agent database, users, sessions — plus `opensearch_data` and
`sentora_data`. Nothing had asked for them to be removed and nothing warned.
There was no backup, so there was no recovery.

What that clarified, and what the table above already said but is easy to read
past: **there are two Fernet keys.** The server key is `FERNET_KEY` in `.env`,
on the host filesystem, and it survived. The agent key is `data/fernet.key`
inside the `sentora_data` volume, and it did not — it was regenerated on the
next boot, which permanently orphans any agent telemetry encrypted under the
old one. Backing up `.env` and not the volume protects the half that was never
at risk.

---

## 5. Monitoring & Observability

### 5.1 Built-in surfaces

| Endpoint | Exposes |
| :--- | :--- |
| `GET /health` | Liveness ping |
| `GET /db-status` | MySQL reachability + version |
| `GET /devices` | Fleet with real `Online`/`Offline` per agent (90 s threshold) |
| `GET /api/exposure/report` | Vulnerability and FIM counts per agent, with coverage |
| `GET /threat-intel` | Indicator counts and per-feed freshness |
| `GET /api/ai-insights/all` | AI worker output |
| `:15672` | RabbitMQ queue depth, throughput, dead letters |

### 5.2 Boot-time assertions worth alerting on

The server prints these at startup. They are cheap to scrape and each one
represents a failure mode that is otherwise invisible:

```
[Auth] Routes: <n> permission-gated, <n> session-only, <n> public.
```

**If this reports `0 permission-gated`, RBAC is not being enforced.** Treat it
as an outage, not a warning.

```
[ThreatIntel] N indicator(s) from 3 feed(s); M row(s) written.
[ThreatIntel] feed error — feodo: 403 — this feed now requires a key...
```

A feed erroring here means indicators go stale and eventually get pruned. The
Threat Intelligence page shows per-source last-refresh for the same reason.

### 5.3 Prometheus sidecars

```yaml
  rabbitmq-exporter:
    image: kbudde/rabbitmq-exporter:latest
    environment:
      RABBIT_URL: http://rabbitmq:15672
      RABBIT_USER: ${RABBITMQ_USER:-sentora}
      RABBIT_PASSWORD: ${RABBITMQ_PASSWORD}
    ports: [ "127.0.0.1:9419:9419" ]
    depends_on: [ rabbitmq ]

  mysqld-exporter:
    image: prom/mysqld-exporter:v0.15.1
    command:
      - "--mysqld.username=root:${DB_PASSWORD}@(db:3306)/"
    ports: [ "127.0.0.1:9104:9104" ]
    depends_on: [ db ]
```

The broker no longer runs on `guest/guest`; the exporter needs the real
credentials. Bind exporters to loopback and let Prometheus scrape over the
internal network.

### 5.4 Alerts worth wiring

| Alert | Threshold | Why |
| :--- | :--- | :--- |
| RBAC not enforced | boot log shows `0 permission-gated` | Every route is session-only |
| Worker queue depth growing | `ai_*_queue` > 200 for 5 min | Worker stuck on Ollama or DB |
| Agent silent | `last_seen` > 5 min while flagged online | Compromise, crash, or a boot-time failure |
| AI insight rate zero | no `ai_analysis_results` inserts for 10 min while alerts continue | Worker stopped consuming |
| Threat feed stale | `/threat-intel` `stats.newest` older than 26 h | Feed failing, indicators aging out |
| SOAR failures rising | `automations.status='failed'` | Agent unreachable or permission issue |
| Shadow queue growing | `shadow_status='pending'` > 50 | Operator behind on approvals |
| Disk fill | `mysql_data` > 80% | Retention overflow |

### 5.5 Log shipping

Every container writes to stdout:

```yaml
  app:
    logging:
      driver: loki
      options:
        loki-url: "http://loki:3100/loki/api/v1/push"
        loki-batch-size: "400"
```

---

## 6. Identity, RBAC and Audit

### 6.1 Session model

The UI authenticates with a server-side session in `userdb.sessions`. The
browser holds an opaque token in an `HttpOnly` cookie; only its SHA-256 is
stored, so a database dump yields nothing presentable. Two clocks apply, both
enforced in SQL:

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `SESSION_IDLE_MINUTES` | 60 | Dies this long after the last request |
| `SESSION_ABSOLUTE_HOURS` | 12 | Hard ceiling regardless of activity |

Sessions are revoked immediately on password change, admin password reset,
role change and account deletion — removing someone's access does not leave
their open tab working.

Every route is deny-by-default. The exceptions are the login endpoint, the SPA
shell, static assets and the agent-facing endpoints, which authenticate with
`X-Agent-Key` or an enrolment token.

### 6.2 Hardening checklist

1. Change `admin / admin123` immediately under **Users & Roles**.
2. Create per-operator accounts; stop using the shared admin.
3. Map operators to roles:
   - `auditor` — `read_telemetry` only
   - `operator` — read + `manage_soar` (approve shadow, dispatch SOAR)
   - `admin` — full
4. Wire LDAP under **System Config**, map groups in `ldap_role_mappings`.
   LDAP identities are provisioned into `users` on first successful bind, so
   RBAC and audit attribution key off the same id as local accounts.
5. Set `AGENT_SHARED_SECRET` in `.env` (`scripts/init_secrets.py` does this).
   Leaving it unset makes the server generate an ephemeral one per boot, so
   any agent relying on the fallback breaks on every restart.
6. Set `SESSION_COOKIE_SECURE=1` once TLS is in front.
7. Leave `PROXY_ALLOWED_HOSTS` empty unless a playbook needs an outbound HTTP
   call. It is a server-side request forgery primitive by nature; empty means
   the endpoint is inert.

### 6.3 Audit retention

`login_logs` and `audit_logs` record every UI login attempt with source IP and
result, every SOAR dispatch, every shadow approve/reject with operator and
timestamp, every config push and rejection, and every admin action.

Attribution comes from the session, not from a request header. Retention is
unlimited by default; add a nightly purge if compliance requires shorter.

---

## 7. Air-Gap Deployment

### 7.1 What works offline

| Component | Offline behaviour |
| :--- | :--- |
| Ollama | Persisted in the `ollama` volume after first pull. No phone-home. |
| OpenSearch | Fully local. |
| OSV vuln scanner | `OSV_MODE=mirror` + `OSV_MIRROR_URL`. |
| Threat intel feeds | `THREAT_INTEL_MODE=off`, or override each feed URL to an internal mirror. |
| OTX / VirusTotal enrichment | No-op when the API keys are unset. |
| Outbound HTTP proxy | Disabled unless `PROXY_ALLOWED_HOSTS` names destinations. |
| UI fonts and assets | Bundled in the image. No CDN. |

### 7.2 Seeding

On a connected staging host:

```bash
docker compose pull
docker compose up -d ollama
docker exec sentora-ollama ollama pull llama3.2:3b

docker save -o sentora-images.tar \
  mysql:8.0 ollama/ollama:latest opensearchproject/opensearch:2.12.0 \
  opensearchproject/opensearch-dashboards:2.12.0 rabbitmq:3-management \
  sentora-community-edition_app:latest

tar czf ollama-models.tgz -C /var/lib/docker/volumes/sentora-community-edition_ollama _data
```

On the air-gapped host:

```bash
docker load -i sentora-images.tar
tar xzf ollama-models.tgz -C /var/lib/docker/volumes/sentora-community-edition_ollama
docker compose up -d
```

### 7.3 Air-gap `.env` block

```ini
OSV_MODE=mirror
OSV_MIRROR_URL=http://osv.internal:8080

THREAT_INTEL_MODE=off
# or serve the feeds internally:
# THREAT_INTEL_FEODO_URL=http://mirror.internal/feodo.json

PROXY_ALLOWED_HOSTS=
# OTX_API_KEY / VT_API_KEY left unset
```

With those set, nothing leaves the network. The OSV scanner fails closed when
no endpoint is reachable — it logs and produces no findings rather than
guessing.

---

## 8. High Availability

Community Edition runs single-host. For HA:

- **MySQL** — replica set behind ProxySQL / HAProxy; point `DB_HOST` at it.
- **OpenSearch** — native cluster, 3+ data nodes.
- **RabbitMQ** — mirrored queues across 3 nodes.
- **App / ingest / workers** — stateless and horizontally scalable behind a
  load balancer. Sessions live in MySQL, so no sticky sessions are needed for
  auth; WebSocket connections (screen stream) still want affinity.

Background tasks only run on Sanic worker `0-0`, so scaling `WORKERS` does not
duplicate the vuln scan, threat-intel refresh or alert dispatch.

---

## 9. Common Pitfalls

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Agent never comes back after a reboot | Fixed. The agent used to exit if the server was unreachable at startup, and the scheduled task's three restarts were spent in the first three minutes. | Rebuild and redeploy the agent. It now retries with backoff and a 15-minute watchdog task brings it back. |
| Alerts show `enc::gAAAAA...` | Fixed in `/all_alerts`, which returned rows undecrypted. | Rebuild the app image. |
| Alerts show `<decryption failed — key mismatch>` | The agent was enrolled against a different Fernet key than this server holds. | Check `FERNET_KEY` and the `sentora_data` volume; re-enrol the agent. Historical rows stay unreadable. |
| Some rows encrypted, others not | Fixed. The agent's encryption map was being overwritten at runtime, so most telemetry wrote plaintext after the first permission scan. | Rebuild and redeploy the agent. Existing plaintext rows are not retroactively encrypted. |
| `ollama-init` exits with no model | Network blocked during boot | `docker exec sentora-ollama ollama pull llama3.2:3b` |
| First inference very slow | Model not resident yet | 30 to 60 s on the first call. Warm it with a manual analysis. |
| Agent shows offline while running | `last_seen` only updates on telemetry push | Wait 60 to 120 s, or check `agent.log` in the install directory. |
| Compose refuses to start | `DB_PASSWORD` or `RABBITMQ_PASSWORD` unset | `python scripts/init_secrets.py`, then set `DB_PASSWORD` by hand. |
| App exits with a FERNET_KEY message | No key set and `/app` is not writable by the non-root user | `python scripts/init_secrets.py`. There is deliberately no auto-generate fallback in containers — a key that cannot be persisted would change every restart. |
| Cannot log in over plain HTTP | `SESSION_COOKIE_SECURE=1` without TLS | Set it to `0`, or terminate TLS. |
| Login does not stick under `npm run dev` | Dev server on :5173 talking to :8000 is cross-site; `SameSite=Lax` withholds the cookie | Build the frontend and let `app.py` serve it, or add a Vite proxy. |
| Frontend bundle stale | Image not rebuilt | `docker compose build --no-cache app && docker compose up -d --force-recreate app`, then hard-refresh the browser. |

---

## 10. Go-Live Checklist

- [ ] Hardware sized to agent count plus 30% headroom.
- [ ] `python scripts/init_secrets.py` run; `DB_PASSWORD` set by hand.
- [ ] `FERNET_KEY` and the `sentora_data` volume backed up to a vault.
- [ ] TLS terminating, `SESSION_COOKIE_SECURE=1`.
- [ ] `BIND_ADDR` left at `127.0.0.1`; no supporting service published.
- [ ] Default `admin / admin123` rotated; per-operator accounts created.
- [ ] Boot log shows a non-zero `permission-gated` route count.
- [ ] `PROXY_ALLOWED_HOSTS` empty, or scoped to named destinations.
- [ ] Backup cron in place; restore test passed **including decryption of
      historical alerts**.
- [ ] Monitoring dashboards live, alerts wired to oncall.
- [ ] `AI_SHADOW_MODE=1` for the first 2 to 4 weeks.
- [ ] `python scripts/api_smoke_test.py` reports 0 auth bypasses and 0 5xx.
- [ ] Phased agent rollout plan documented.
- [ ] Rollback runbook approved by the SecOps lead.
- [ ] Compliance sign-off on retention and audit trail.
