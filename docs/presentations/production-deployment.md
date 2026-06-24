# Production Deployment Guide

Companion technical document for the DTCloud pitch deck. Covers hardware
sizing, network topology, TLS handling, persistence, monitoring, and the
air-gap deployment path.

> Audience: SecOps lead + DevOps engineer responsible for standing up
> the production instance.

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

Peak load (large LLM inference): Ollama can spike to 5 to 7 GB. Keep
headroom.

### 1.3 GPU notes

A GPU is **not required**. `llama3.2:3b` runs on CPU within reasonable
latency (10 to 30 s per inference). Ollama auto-detects CUDA / Metal /
ROCm; if a GPU is present, average latency drops to under 3 s.

For higher throughput, swap to a smaller model:

```
OLLAMA_MODEL=qwen2.5:1.5b   # faster, slightly weaker analysis
OLLAMA_MODEL=phi3:mini      # alternative
```

Or, with a GPU available, scale up:

```
OLLAMA_MODEL=llama3.1:8b
```

Larger models improve verdict quality for ambiguous events at the cost
of throughput.

---

## 2. Network Topology

### 2.1 Recommended layout

```
                Internet
                   │
                   │  (only required if remote endpoints push telemetry)
                   ▼
          ┌──────────────────┐
          │  reverse proxy   │   nginx / Traefik / Caddy
          │  TLS terminate   │   - 443 → app :8000
          │                  │   - 5001 (or tunnelled) → ingest :5001
          └──────────────────┘
                   │ internal network
                   ▼
          ┌──────────────────┐
          │  Sentora host   │
          │  docker compose  │
          └──────────────────┘
                   │ internal LAN
                   ▼
          Endpoint fleet (agents)
```

### 2.2 Required ports

| Direction | Port | Protocol | Required when |
| :--- | :--- | :--- | :--- |
| Agent to server | 5001/tcp | length-framed binary | always |
| Agent to server | 8000/tcp | HTTPS REST + WS | always (agent polls SOAR queue, deploys, screen stream) |
| Operator to server | 8000/tcp | HTTPS | UI access |
| Internal | 3306, 5672, 9200, 11434 | various | container-network only, never exposed |

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

# Optional separate listener for ingest (length-framed TCP).
stream {
    upstream sentora_ingest { server 127.0.0.1:5001; }
    server {
        listen 5001;
        proxy_pass sentora_ingest;
        proxy_timeout 60s;
    }
}
```

The ingest channel is binary TCP, not HTTP. Use nginx `stream` module
or expose port 5001 directly.

---

## 3. TLS / Certificate Handling

### 3.1 Three deployment patterns

1. **Reverse proxy terminates TLS (recommended).**
   - Let's Encrypt or organisational CA cert on the proxy.
   - App listens on plain HTTP at `:8000`, ingest plain TCP at `:5001`.
   - Rotation is trivial (proxy reload).

2. **App container terminates TLS.**
   - Place cert under `certs/server.crt` + `certs/server.key`.
   - Set in `.env`:
     ```
     TLS_ENABLED=1
     TLS_CERT=/app/certs/server.crt
     TLS_KEY=/app/certs/server.key
     ```
   - Rotation requires `docker compose restart app`.

3. **Self-signed for lab.**
   - Run `python certs/generate_certs.py`.
   - Distribute the CA cert to test agents so they trust the chain.
   - Not for production.

### 3.2 Rotation procedure

Reverse proxy pattern:

```bash
# 1. New certs in place (Let's Encrypt or org CA)
# 2. Validate
nginx -t
# 3. Reload (no downtime)
nginx -s reload
```

App-terminated pattern:

```bash
cp new.crt /opt/sentora/certs/server.crt
cp new.key /opt/sentora/certs/server.key
docker compose restart app
# WebSocket clients (browser UI, screen stream) reconnect automatically.
```

**Agent trust:** agents do not pin a server cert. They trust whatever
the system trust store accepts. So rotation is a server-side concern;
agents do not need re-enrolment when the TLS cert changes.

---

## 4. Data Persistence and Backup

### 4.1 What to back up

| Path | Type | Backup priority | Restore strategy |
| :--- | :--- | :--- | :--- |
| Docker volume `mysql_data` | Critical: all telemetry, agents, AI insights, automations | High | `mysqldump --all-databases` daily |
| Docker volume `opensearch_data` | Log search index | Medium | Rebuildable from MySQL telemetry |
| File `data/fernet.key` | Agent telemetry encryption key | Critical (loss = unreadable at-rest data) | Encrypted vault |
| File `.env` | Server secrets, DB password, server Fernet key | Critical | Encrypted vault |
| Dir `Sentora/main*` | Built agent binaries | Low (CI rebuild) | Rebuild via `build_agent.sh/ps1` |

### 4.2 Recommended cron

```bash
#!/usr/bin/env bash
# /opt/sentora/backup.sh
set -euo pipefail
TS=$(date +%F-%H%M)
DEST=/var/backups/sentora/$TS
mkdir -p "$DEST"

# MySQL
docker exec sentora-db mysqldump --all-databases --single-transaction \
    -uroot -p"$(awk -F= '/^DB_PASSWORD=/{print $2}' /opt/sentora/.env)" \
    > "$DEST/mysql.sql"

# Critical files
cp /opt/sentora/data/fernet.key "$DEST/"
cp /opt/sentora/.env             "$DEST/"

# Compress + ship to S3 / NAS / wherever
tar czf /var/backups/sentora-$TS.tgz -C /var/backups/sentora "$TS"
aws s3 cp /var/backups/sentora-$TS.tgz s3://my-backups/sentora/
```

Run daily via systemd timer or cron. Keep 30 days hot, 1 year cold.

### 4.3 Restore test

Every quarter:

1. Spin up a sandbox host.
2. Restore latest backup.
3. Confirm UI logs in, dashboards populate, an agent can re-enrol.
4. Document any deviation.

---

## 5. Monitoring & Observability

### 5.1 Built-in surfaces

| Endpoint | What it exposes |
| :--- | :--- |
| `GET /health` (port 8000) | Liveness ping, returns `{status:"healthy"}` |
| `GET /api/ai-insights/all` | AI worker output rate (count over time) |
| `GET /devices` | Agent fleet, `last_seen` per agent |
| `:15672` (RabbitMQ) | Queue depth, throughput, dead letters |
| `:5601` (OpenSearch Dashboards) | Ad-hoc log search |

### 5.2 Recommended Prometheus scrape

Add sidecars to `docker-compose.yaml`:

```yaml
  rabbitmq-exporter:
    image: kbudde/rabbitmq-exporter:latest
    environment:
      RABBIT_URL: http://rabbitmq:15672
      RABBIT_USER: guest
      RABBIT_PASSWORD: guest
    ports: [ "9419:9419" ]
    depends_on: [ rabbitmq ]

  mysqld-exporter:
    image: prom/mysqld-exporter:v0.15.1
    command:
      - "--mysqld.username=root:${DB_PASSWORD}@(db:3306)/"
    ports: [ "9104:9104" ]
    depends_on: [ db ]
```

### 5.3 Key Grafana alerts

| Alert | Threshold | Why |
| :--- | :--- | :--- |
| Worker queue depth growing | `ai_*_queue` > 200 messages for 5 min | AI worker stuck on Ollama or DB |
| Agent silent | `last_seen` > 5 min for an agent flagged `online` | Endpoint compromise or agent crash |
| AI insight emit rate dropped | `ai_analysis_results` insert rate = 0 for 10 min while alerts ongoing | Worker stopped consuming |
| Defensive SOAR action failures | `automations.status='failed'` count rising | Agent unreachable or permission issue |
| Shadow queue growing | `shadow_status='pending'` > 50 | Operator behind on approvals |
| Disk fill | `mysql_data` > 80% | Retention overflow |

### 5.4 Application log shipping

Each container writes to stdout. Wire Docker's logging driver to Loki
or CloudWatch:

```yaml
  app:
    logging:
      driver: loki
      options:
        loki-url: "http://loki:3100/loki/api/v1/push"
        loki-batch-size: "400"
```

---

## 6. RBAC and Audit

### 6.1 Initial hardening checklist

1. First login `admin / admin123`. Change immediately under **Users & Roles**.
2. Disable the default `admin` and create per-operator accounts.
3. Map each operator to one of the built-in roles or a custom one:
   - `auditor`: `read_telemetry` only.
   - `operator`: read + `manage_soar` (can approve shadow, dispatch SOAR).
   - `admin`: full.
4. If using LDAP, wire it under **System Config > LDAP**, map LDAP groups
   to roles in `ldap_role_mappings`.
5. Rotate `AGENT_SHARED_SECRET` in `.env` and restart the stack
   (per-agent keys are unaffected).

### 6.2 Audit data retention

`login_logs` and `audit_logs` tables hold:

- Every UI login attempt (local + LDAP) with source IP, result.
- Every SOAR action dispatch with `actor`.
- Every shadow approve / reject with operator name and decision timestamp.
- Every database drop (admin actions).

Default retention is forever. Add a nightly purge if compliance requires
shorter retention.

---

## 7. Air-Gap Deployment

### 7.1 What works offline

| Component | Offline behaviour |
| :--- | :--- |
| Ollama LLM | Persisted in `./ollama` volume after first pull. No phone-home. |
| OpenSearch | Fully local. |
| OSV vuln scanner | Set `OSV_MODE=mirror`, point `OSV_MIRROR_URL` to an internal OSV mirror. |
| OTX / VirusTotal | Optional, no-op when API keys are unset. |
| UI fonts and assets | Bundled inside the image. No CDN. |

### 7.2 Initial seeding (air-gap)

On a connected staging host:

```bash
# Pull all images
docker compose pull

# Pull the Ollama model into the volume
docker compose up -d ollama
docker exec sentora-ollama ollama pull llama3.2:3b
docker exec sentora-ollama ollama pull <any-additional-models>

# Save images for transport
docker save -o sentora-images.tar \
  mysql:8.0 ollama/ollama:latest opensearchproject/opensearch:2.12.0 \
  opensearchproject/opensearch-dashboards:2.12.0 rabbitmq:3-management \
  sentora-community-edition_app:latest

# Snapshot the ollama model volume
tar czf ollama-models.tgz -C /var/lib/docker/volumes/sentora-community-edition_ollama _data
```

Transport to the air-gapped host and reverse:

```bash
docker load -i sentora-images.tar
tar xzf ollama-models.tgz -C /var/lib/docker/volumes/sentora-community-edition_ollama
docker compose up -d
```

### 7.3 OSV mirror

For air-gap, run an internal OSV API mirror (or static export):

```
OSV_MODE=mirror
OSV_MIRROR_URL=http://osv.internal:8080
```

If unset and air-gap, the vuln scanner runs in fail-closed mode (logs
"no OSV reachable", no false positives).

---

## 8. High Availability Notes

Community Edition runs as a single host. For HA:

- **MySQL:** standard replica setup. Point `DB_HOST` at a proxy
  (ProxySQL / HAProxy).
- **OpenSearch:** native cluster. Replace single-node with 3+ data nodes
  in `docker-compose.yaml`.
- **RabbitMQ:** mirrored queues across 3 nodes.
- **App / ingest / workers:** stateless, horizontally scalable behind a
  load balancer. Sticky sessions for the React UI (WebSocket).

Enterprise tier ships a tested HA reference architecture and helm
charts. Community covers single-host plus optional read replica.

---

## 9. Common Pitfalls

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| AI worker spins, no insights saved | Agent name has hyphen, `<name>_db` mismatch | Already fixed in current build (db name sanitiser). Restart workers. |
| `ollama-init` exits with no model pulled | Network blocked during boot, init silently retried curl | Run `docker exec sentora-ollama ollama pull llama3.2:3b` manually. |
| Defensive worker stuck on Ollama | Model not loaded into memory yet, first inference slow | First inference takes 30 to 60 s. Warm up by sending a manual analysis. |
| Agent shows offline despite running | `last_seen` updated only on telemetry push, agent has nothing to send | Wait 60-120 s for next collector cycle, or check agent log at `C:\Program Files\Sentora-Agent\agent.log`. |
| `Unknown database 'AGENT_db'` | Hyphenated hostname slipped through somewhere | Confirm everything is on current build (see DB-name normalisation fix). |
| Frontend bundle stale | Image not rebuilt with `--no-cache` | `docker compose build --no-cache app && docker compose up -d --force-recreate app` |

---

## 10. Sign-off Checklist Before Go-Live

- [ ] Hardware sized to the agent count plus 30% headroom.
- [ ] TLS in place (reverse proxy or app-terminated). Self-signed disabled.
- [ ] Default `admin / admin123` rotated, MFA or LDAP wired.
- [ ] Backup cron in place, restore test passed.
- [ ] Monitoring dashboards live, alerts wired to oncall.
- [ ] `AI_SHADOW_MODE=1` for the first 2 to 4 weeks of production.
- [ ] Phased agent rollout plan documented.
- [ ] Runbook for rollback approved by SecOps lead.
- [ ] Compliance officer signed off on retention and audit trail.
