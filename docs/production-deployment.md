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

> **If you are upgrading from a build before this section changed, assume the
> console was never encrypted.** `TLS_ENABLED`, `TLS_CERT` and `TLS_KEY` were
> described in this guide, in `.env.example`, and in the instructions
> `certs/generate_certs.py` prints when it finishes — and read by no line of
> code. Setting `TLS_ENABLED=1` produced a console that came up cleanly on
> plain HTTP while its operator had every reason to believe it was HTTPS, with
> the login form and the session cookie crossing the network in clear text.
> Rotate any credential that was typed into it.

Everything below was verified by turning it on against a running stack, and
then against a real agent. Six things were wrong that no test caught, because
each needed a real container, a real certificate and a real handshake to
appear; they are called out in place, because each is a way the same mistake
gets made again.

Three of the six were the same defect in different clothes: the agent's CA
reaching one connection and not the next. If you take one thing from this
section, take that -- trust is a property of the host, and wiring it per
connection guarantees you will miss one.

### 3.1 What TLS covers

Three connections, and **all three have to work or the deployment is worse
than it was**:

| Connection | Plain | TLS | Carries |
| :--- | :--- | :--- | :--- |
| Operator → console | `http://host:8000` | `https://host:8000` | The session cookie and every credential |
| Agent → ingest | `host:5001` | `host:5011` | All telemetry: logs, paths, process names, hostnames |
| Agent → channel | `ws://host:8000/agent-link` | `wss://host:8000/agent-link` | Config push, SOAR execute, console, screen stream |

The third is the one that bites. The agent opens the channel; the server never
dials an endpoint, and since the agent stopped listening on a port of its own
there is no second route to a host. **An agent whose channel is down but whose
telemetry still flows looks healthy and cannot be commanded** — the console
shows it reporting, and nothing reaches it.

### 3.2 Turning it on

```ini
# .env
TLS_ENABLED=1
TLS_CN=soc.example.com                    # the name agents and browsers use
TLS_SAN=soc.example.com,10.0.0.5          # every other name it answers to
```

`TLS_SAN` is comma separated and takes hostnames and addresses alike; anything
that parses as an address becomes an IP SAN rather than a DNS name, because a
bare address in the DNS list matches nothing. `localhost`, `127.0.0.1` and
`::1` are always included.

Put in it every name anyone will actually type. The old certificate carried
`DNS:localhost` and nothing else, so a console opened at `https://10.0.0.5`
failed hostname verification in every browser on top of the untrusted-CA
warning - two errors that look like one.

It also decides whether a security key can ever be used here. WebAuthn's RP ID
must be a domain, and browsers reject an IP address outright, so `https://` at
an address is not somewhere a passkey can be registered. That needs a name in
this list, resolvable from the operator's machine.

Generation is idempotent - a new identity on every restart would break every
agent that pinned the CA - so **changing these values on a deployment that
already has a certificate does nothing by itself**. The startup log says so and
prints the command to regenerate:

```
python certs/generate_certs.py --force --cn soc.example.com --san 10.0.0.5
```

That is enough. On first boot `app` generates a CA and a server certificate
for this deployment, `ingest` reads the same pair and opens `5011`, and the
channel URL becomes `wss://` because the agent derives it from `server_url`.

`INGEST_TLS_PORT` moves the encrypted telemetry port off `5011`. Both sides
have to agree, and only one of them reads this variable — the agent derives
`5011` from the `https://` scheme and has no way to learn you changed it — so
an agent pointed at a moved port needs `--ingest-port` to match. Leave it
alone unless something else already owns `5011`.

For a certificate you already have:

```ini
TLS_ENABLED=1
TLS_CERT=/app/data/certs/fullchain.pem
TLS_KEY=/app/data/certs/privkey.pem
```

Both or neither. Setting one alone is refused at startup — half a
configuration looks deliberate, and filling the other half from a generated
certificate would serve TLS the operator did not configure and will not know
is in use.

**A certificate that cannot be loaded stops the server.** Missing, unreadable
or mismatched, it exits with a message naming the file rather than falling
back to plain HTTP. Falling back is how the original problem comes back
wearing an error nobody reads in a container log.

#### Where the generated material lives

`TLS_DIR`, which compose sets to `/app/data/certs` — inside the `sentora_data`
volume, beside `data/fernet.key` and for the same reasons: it is state, it has
to survive a rebuild, and it is the one directory the image prepares for the
unprivileged user the container runs as.

> **This is the first thing that was wrong.** It went to `/app/certs`, which
> ships inside the image owned by root while the server runs as `sentora`.
> The first boot with TLS on died with
> `Permission denied: '/app/certs/rootCA.key'`, and because refusing to
> downgrade is correct, the container restart-looped instead of serving
> something weaker. The right behaviour turned a packaging mistake into an
> outage rather than a silent downgrade — which is the trade this whole
> section is built on.

A regenerated certificate is a **new identity for the deployment**. Every
agent holding the old CA stops verifying and stops reporting. Keep `TLS_DIR`
on a volume, and back that volume up.

`ingest` mounts the volume read-only and only ever reads. Two processes
generating independently would each hold a certificate the other does not, and
an agent that verified the console would then fail against ingest for no
visible reason. On a cold start `ingest` may lose the race and log

```
[!] ingest TLS was requested and cannot be served: no certificate at
    certs/server.crt yet. `app` generates it on first boot...
```

`restart: always` brings it back once `app` has written the pair. One or two
of those lines on a first boot is expected; a stream of them means the two
services are not sharing a volume.

### 3.3 What the agent has to trust

Against a self-signed server the agent verifies and therefore **fails**, which
is correct — an unverified TLS connection is encrypted to whoever answered,
which against an attacker on the path is what not encrypting it would have
achieved. So the agent needs the CA:

```jsonc
// config.json, beside agent_name / agent_key / server_url
{
  "server_url": "https://soc.example.com:8000",
  "server_ca":  "C:\\Program Files\\Sentora-Agent\\rootCA.crt"
}
```

`SENTORA_CA_CERT` and `--ca` do the same thing. The installer fetches it
automatically from `/api/agent/ca` when `server_url` is `https://`.

For an agent you are **re-pointing** rather than reinstalling, take the CA out
of the server instead of downloading it:

```powershell
cd C:\path\to\Sentora
docker compose cp app:/app/data/certs/rootCA.crt "$env:USERPROFILE\Desktop\rootCA.crt"

# then, from an *elevated* shell - the step above cannot do this one:
Copy-Item "$env:USERPROFILE\Desktop\rootCA.crt" "C:\Program Files\Sentora-Agent\rootCA.crt" -Force
```

Two commands, because `docker compose cp` writes the file as *you*, not as the
Docker daemon, and that fails against `C:\Program Files` even from an elevated
shell — `open ...: Access is denied`. Land it somewhere you own, then move it
with a shell that can write there.

That is out of band — it never crosses the network — so it sidesteps the
trust-on-first-use caveat above entirely, and it avoids a trap on Windows:
`Invoke-WebRequest -SkipCertificateCheck` is PowerShell 7+ only. On Windows
PowerShell 5.1 that parameter does not exist, the download fails, and if you
have already rewritten `config.json` the agent is now pointed at `https://`
with a `server_ca` that is not there. Put the file in place **before**
restarting the agent.

That endpoint serves the CA **certificate** and never `rootCA.key`. The
certificate is the half of the pair whose purpose is to be distributed, and
publishing it grants nothing — it lets a client check a signature it could not
otherwise check. Fetching it over the connection it is meant to secure is
trust on first use, and it is the same trust the enrolment token and the agent
binary already travel on in the same installer run. Ship `rootCA.crt` out of
band if that is not acceptable.

> **Second, third and fourth things wrong, all found here.**
> `/api/agent/ca` read `certs/rootCA.crt` directly while the generator wrote
> to `TLS_DIR`, so the endpoint an installer depends on for trust answered
> 404 on every containerised deployment.
>
> Then `server_ca` turned out to be reaching one connection at a time. The
> telemetry socket had it; the channel did not, so the agent shipped
> telemetry over TLS quite happily and could not open its channel at all --
> reporting, and unreachable. Fixing that left the `requests` calls, which
> failed on the first thing the agent does:
>
> ```
> [!] Agent bootstrap attempt 1 failed: SSLError(SSLCertVerificationError(
>     certificate verify failed: unable to get local issuer certificate))
> ```
>
> Three fixes for one defect. `server_ca` is a statement about the *host*,
> so the agent now installs it once at startup -- as a bundle of the system
> trust store **plus** this CA, written beside the CA and pointed at by
> `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `SSL_CERT_FILE`. Every client
> in the process picks it up, including any added later. Trusting the
> private CA *instead of* the system roots would have been the easier
> change, and would have made the agent distrust every other HTTPS
> endpoint on the machine.

The port and the scheme are derived from `server_url`, not configured
separately: `https://` means telemetry goes to `5011` inside TLS and the
channel goes to `wss://`. Two settings that have to agree, with nothing making
them agree, would be wrong in exactly the deployment that believed it was
encrypted. `--ingest-port` still overrides the port for a bastion setup.

With a certificate from a public CA, leave `server_ca` unset — the endpoint's
trust store already has what it needs.

### 3.4 Migrating a fleet, in this order

**Turning on TLS breaks the channel of every agent already installed.** Their
`config.json` still says `http://`, so they dial `ws://` against a port that
now answers only TLS. Telemetry keeps flowing on `5001`, so nothing looks
wrong — and no command reaches any host.

The agent says so, once, rather than leaving a reconnect loop to be read:

```
[link] channel closed: Connection to remote host was lost.
[link] soc.example.com:8000 is serving TLS, and this agent is configured for
       http:// - so telemetry still flows and no command can reach this host.
       Set server_url to https://... and give it the server's CA as server_ca
       (GET /api/agent/ca), then restart the agent.
```

Do it in this order:

1. **Enable TLS on the server.** `TLS_ENABLED=1`, `TLS_CN=<the name agents
   will use>`, then `docker compose up -d --build app ingest`. Leave `5001`
   published; both ingest listeners run.
2. **Confirm the server is serving what it says** — §3.7.
3. **Re-point the agents.** Set `server_url` to `https://…` and `server_ca` to
   the CA, then restart each agent. Reinstalling does both for you.
4. **Watch the plaintext listener go quiet.** `ingest` names each agent still
   arriving in the clear, once each:
   ```
   [!] web-01 is sending telemetry in the clear on port 5001. Its logs,
       hostnames and process names cross the network unencrypted...
   ```
5. **Close the plaintext path** when nothing is named any more. Two
   settings in `.env`, and both are needed:

   ```ini
   INGEST_TLS_REQUIRED=1            # stops the listener in the container
   INGEST_PLAINTEXT_BIND=127.0.0.1  # stops Docker publishing the port
   ```

> **Both, or you get the fourth thing that was wrong.**
> `INGEST_TLS_REQUIRED=1` closes the listener *inside the container*;
> Docker goes on publishing the host port. A connection is then accepted
> by the proxy, the batch is written into a socket nobody reads, and the
> close looks exactly like a server that stored everything. Verified on a
> live stack: the bytes were accepted, nothing was ingested, and the batch
> reported as sent.
>
> The agent no longer falls for this - once a server has acknowledged a
> batch, silence from it keeps the rows - but a refused connection is
> still the honest answer, and that means unpublishing the port.

   Verify from another machine, not from the server itself: the loopback
   binding still answers there, which is the point of it.

   ```bash
   nc -vz soc.example.com 5001   # expect: connection refused
   nc -vz soc.example.com 5011   # expect: succeeded
   ```

Setting `INGEST_TLS_REQUIRED=1` without `TLS_ENABLED=1` is a startup failure:
it would close the plaintext port and open nothing, leaving an ingest service
listening on nothing at all, which from the fleet's side is indistinguishable
from a quiet week.

### 3.5 Session cookies

**Unset, `SESSION_COOKIE_SECURE` now follows `TLS_ENABLED`.** It used to
default to `0` regardless, so turning on TLS and leaving it alone gave an
HTTPS console whose session cookie was still allowed onto plain HTTP.

Set it explicitly to `1` when a **reverse proxy** terminates TLS — that is
invisible from inside this process, so nothing can infer it for you.

The inverse is a real outage: `1` while serving plain HTTP means the browser
silently drops the cookie and nobody can log in.

`SESSION_COOKIE_SAMESITE` defaults to `Lax`, which blocks the cross-site
POST/XHR that CSRF needs. Only a split-origin deployment needs `None`, and
that requires `SESSION_COOKIE_SECURE=1`.

### 3.6 Terminating at a reverse proxy instead

Leave `TLS_ENABLED` unset, serve plain HTTP at `:8000` and plain TCP at
`:5001`, and put nginx in front (§2.3). Rotation is a proxy reload, and agents
verify the proxy's certificate against the system trust store with no
`server_ca`.

Two things this deployment still has to do by hand:

- `SESSION_COOKIE_SECURE=1`, per §3.5.
- Terminate TLS for **ingest** too, or leave it in the clear knowingly. It is
  binary TCP, not HTTP — nginx `stream`, not a `location` block.

### 3.7 Rotating a certificate

Replacing the **server certificate** is server-side only:

```bash
docker compose cp new.crt app:/app/data/certs/server.crt
docker compose cp new.key app:/app/data/certs/server.key
docker compose restart app ingest
```

Restart both. `ingest` reads the same pair read-only, and a console on the new
certificate with telemetry still presenting the old one is the kind of
half-migration that shows up as a few hosts going quiet.

Replacing the **CA** is not server-side only, and this is the trap.
`python certs/generate_certs.py --force` issues a new CA as well as a new
certificate, so every agent holding the old `rootCA.crt` refuses the new
server and stops sending. It is a new identity for the deployment, not a
renewal. Replace `rootCA.crt` on the endpoints first — or re-enrol them, which
does it for you.

Agents pin nothing: they verify against the system trust store plus
`server_ca` if one is set. With a certificate from a public CA, renewal needs
nothing on the endpoints at all.

### 3.8 Verifying it, rather than assuming it

Run these after enabling TLS. Every one of them found something the first time.

**The console is actually HTTPS, and only HTTPS:**

```bash
curl -sk -o /dev/null -w "https=%{http_code}\n" https://localhost:8000/health
curl -s  -o /dev/null -w "http=%{http_code}\n"  --max-time 5 http://localhost:8000/health
# expect: https=200, http=000
```

**The CA the server hands out verifies the certificate it presents.** This is
the test that matters, because it is what every agent does:

```bash
curl -sk https://localhost:8000/api/agent/ca -o /tmp/rootCA.crt
python - <<'EOF'
import socket, ssl
ctx = ssl.create_default_context(cafile="/tmp/rootCA.crt")
for port in (8000, 5011):
    with socket.create_connection(("localhost", port), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            print(port, tls.version(),
                  dict(x[0] for x in tls.getpeercert()["subject"])["commonName"])
EOF
# expect TLSv1.3 and the CN from TLS_CN on both ports
```

Use Python rather than `curl --cacert` on Windows: curl's schannel backend
cannot check revocation for a private CA and reports
`CERT_TRUST_REVOCATION_STATUS_UNKNOWN` against a chain that is perfectly
valid. Python's `ssl` is what the agent uses, so it is also the honest test.

**The plaintext listener still answers during the migration:**

```bash
docker compose logs ingest | grep "ingest listening"
# expect both: TLS ingest on 5011, and TCP ingest on 5001 (in the clear)
```

**Every agent has actually moved** — this is what tells you step 5 is safe:

```bash
docker compose logs ingest | grep "in the clear on port"
# expect nothing once the fleet has migrated
```

**Channels are up, not just telemetry.** The dashboard's agent list carries
`channel_connected` per host; an agent that is reporting with no channel is
the failure this section keeps warning about. Check it there rather than
inferring health from row counts.

### 3.9 Why not mTLS, and what it would take

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
| Volume `sentora_data` | `data/fernet.key` — the **agent** telemetry key, and `data/certs/` — this deployment's TLS certificate and CA | **Critical** | Encrypted vault (it holds two private keys) |
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

Losing `data/certs/` is recoverable but not free: a new certificate and a new
CA are generated, and every agent holding the old `rootCA.crt` refuses the new
server and stops sending until the file is replaced on the endpoint. It lives
in `sentora_data` beside the Fernet key rather than in a volume of its own,
because `certs/` inside the image is owned by root and the server runs
unprivileged — see §3.2. The backup script tars every volume
`docker-compose.yaml` declares, so both are picked up without anybody having
to remember them.

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

### 6.2 Two-factor authentication

Off per account until an operator turns it on, at **My Security** in the
sidebar. There is no permission gate on that page and there deliberately is
not one: two-factor protects the account, not the tenancy, so an operator
whose role can do nothing else still has to be able to secure their own login.

An account that has it on cannot be signed into with a password alone by
anybody, including an administrator. There is no override.

#### What it protects against

Nothing about the password changes. Guessing was already covered by
`core.login_guard`, which locks out per user and per address. What a second
factor adds is the case a lockout cannot touch: a password that is *correct*
and in the wrong hands - reused from a breached site, phished, or read out of
a browser. This console can isolate a host, run a command as SYSTEM on every
endpoint, and read every log the fleet has produced, and one string is enough
for all of it.

#### Enrolling

1. **My Security** -> *Turn on two-factor*.
2. Scan the QR with any authenticator, or type the key by hand - a QR is no
   use on the machine you are already sitting at.
3. Enter a code to confirm. **Nothing changes about the login until this
   step**: a secret written when the QR appeared, with no proof it was kept,
   would lock out everybody who scanned it into an app they then deleted.
4. Save the recovery codes. They are shown exactly once.

#### Recovery codes

Ten, each good for one sign-in, stored as SHA-256 hashes. The server cannot
show them again - that is the property that makes storing them safe, and it is
also the thing to tell operators before they close the tab.

**If they are lost and the authenticator is gone, the account cannot sign in.**
There is no support path that recovers it, by design: any mechanism that let
an administrator bypass somebody's second factor would be a bypass an attacker
could use too. The way back is a `users` row edit against the database, which
is deliberately awkward:

```sql
-- Only from a shell on the database host, and audit-log the fact you did it.
DELETE FROM userdb.user_totp          WHERE user_id = <id>;
DELETE FROM userdb.user_recovery_codes WHERE user_id = <id>;
```

Signing in with a recovery code raises `RECOVERY_CODE_USED` on the platform
events panel (see §6.4). It is usually an honest lost phone; the other reading
is a stolen password and a stolen list, and the two look identical from here.

#### Settings

There are none. The step is 30 seconds, codes are 6 digits, and the accepted
drift is one step either side - the interoperable values, and not worth being
unusual about. One step is 30 seconds of clock skew in each direction, which
covers a phone that has not synchronised recently; widening it would hand an
attacker more time to reuse a code they watched being typed.

A code works once. TOTP is a shared secret and a clock, so the same six digits
stay valid for their whole step, and without single use anyone who sees one
entered has the rest of that step to use it themselves. A second attempt
raises `TOTP_CODE_REPLAYED`.

#### Security keys

A code typed into a convincing copy of this login page works on the real one,
and the operator has no way to tell. That is the case a one-time code cannot
cover and a security key can: the browser signs over the origin it is actually
talking to, so a key registered against `soc.example.com` produces nothing
usable on a lookalike.

**There is nothing to configure.** The relying-party ID is derived from the
request, so a single-machine install at `https://localhost:8000` and an estate
at `https://soc.example.com` both work without being told anything, and no
setting can disagree with the URL people type.

The cost of that is that some origins cannot host a key at all, and the console
says which. Open **My Security** and it reports one of:

| Where the console is open | Security keys |
| :--- | :--- |
| `https://soc.example.com` | available |
| `http://localhost:8000` or `https://localhost:8000` | available — localhost is a secure context by definition |
| `https://10.0.0.5:8000` | **unavailable.** A relying-party ID must be a domain and browsers reject an address outright. Reach the console by a name — see `TLS_SAN` in §3.2. |
| `http://soc.example.com` | **unavailable.** WebAuthn needs a secure context; set `TLS_ENABLED=1`. |
| any, with the `webauthn` package absent | **unavailable.** The import is lazy, so a deployment that pulls new code without reinstalling loses this option rather than the console. |

One-time codes are unaffected in every one of those rows. A key is an addition,
not a replacement, and recovery codes remain the way back into an account whose
authenticator is gone.

Two consequences worth knowing before you roll it out:

- **A credential is bound to the origin it was made at.** A key registered
  while the console was at `localhost` is one the browser will not offer at a
  hostname. `user_webauthn.rp_id` records it, and the login step offers only
  the keys that can work where you are, rather than showing a prompt that times
  out. Register keys at the address operators actually use.
- **Whether a login needs a second factor is a property of the account, not of
  the origin.** An operator with a key and no authenticator is still challenged
  when they open the console at an address — otherwise the origin binding, the
  entire point of WebAuthn, would become a way around it.

A key that presents a signature counter lower than the last one seen is
refused and raises `WEBAUTHN_COUNTER_REGRESSED` (CRITICAL): that is what a
cloned key looks like, since the copy does not know how many times the original
has been used. A counter of zero means the authenticator does not implement one
— true of most platform passkeys and everything that syncs between devices —
and is accepted.

#### What is stored

| | |
| :--- | :--- |
| `user_totp.secret` | The seed, **Fernet-encrypted** with the server key. A dump of `userdb` alone does not hand over everybody's second factor. |
| `user_recovery_codes.code_hash` | SHA-256. Never the code. |
| `totp_pending.token_hash` | SHA-256 of the half-authenticated token, like a session. |
| `user_webauthn.public_key` | The credential's public key, base64url. Public by construction — it verifies signatures and cannot make them. |
| `webauthn_challenges` | Server-side and single use, expiring in two minutes. A challenge the browser chooses is not a challenge. |

The seed column is `VARCHAR(512)` for ciphertext, not for the ~32 characters a
base32 seed reads as - see §4.1 for what sizing a column to the human-readable
value cost this platform once already.

**Losing the Fernet key takes every enrolled second factor with it.** The
secret becomes undecryptable, the server reports the account as having none,
and each operator has to enrol again. That is the survivable failure; the
alternative - refusing the login outright - would lock the whole console out
of itself. Back the key up (§4.1).

#### LDAP accounts

Gated identically. A second factor that protected the local path and not the
directory path would protect nothing: an attacker holding a password picks the
path without it.

### 6.3 Hardening checklist

1. Change `admin / admin123` immediately under **Users & Roles**.
2. Create per-operator accounts; stop using the shared admin.
   Have each one turn on two-factor at **My Security** (§6.2) - especially the
   accounts that can reach SOAR, because those can run a command as SYSTEM on
   every endpoint.
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

### 6.4 Attacks on the platform itself

`userdb.platform_events`, surfaced under **Activity Logs**. The server already
detected all of this and told nobody: a lockout went to a container log, a
rejected agent key went to a container log, a permission denial went to a
table nobody opens unless they are already investigating. The platform watched
every host in the fleet and was the one machine nobody watched.

| Kind | Severity | What it means |
| :--- | :--- | :--- |
| `FLEET_KEY_ON_CHANNEL` | CRITICAL | The fleet-wide secret was offered on the agent channel. That channel carries `/self_destruct`, so a leaked master key must not open one against every endpoint at once. |
| `LOGIN_LOCKOUT` | HIGH | Failed logins crossed the threshold. Somebody guessing, or an integration on a credential that changed. |
| `AGENT_KEY_REJECTED` | HIGH | A channel was opened with a key this server does not know. Any revoked agent does this; so does anyone who found a key that no longer works. |
| `ENROLMENT_TOKEN_REUSED` | HIGH | A one-time token presented twice. Usually an installer re-run; the other reading is that it leaked. |
| `TOTP_CODE_REPLAYED` | HIGH | A second-factor code already used was presented again. |
| `TOTP_DISABLE_REFUSED` | HIGH | A wrong password when turning off two-factor. A hijacked session trying to remove the control that would have stopped it looks exactly like this. |
| `WEBAUTHN_COUNTER_REGRESSED` | CRITICAL | A security key presented a signature counter lower than the last one seen. That is what a copy of the key looks like — the copy does not know how many times the original has been used. The only other reading is a replayed response, and neither is benign. |
| `PERMISSION_DENIED` | MEDIUM | An operator reached past their role. One is a mis-click; a run of them is somebody mapping what they can touch. |
| `RECOVERY_CODE_USED` | MEDIUM | Signed in with a recovery code rather than an authenticator. |

Repeats fold into one row whose count climbs, within a ten-minute window. A
brute-force that wrote a row per attempt would make the view meant to reveal
it into the thing that buries it.

The panel is shown even when empty, and says so. An operator who never sees it
cannot tell "nothing has attacked us" from "this platform does not watch
itself" - and on a security view, a quiet twenty-four hours is a finding.

Nothing here records a credential. These rows describe attempts *on* secrets,
and the obvious fields to include - the password tried, the key presented -
are exactly the ones that turn an audit trail into a second breach.

### 6.5 Audit retention

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
