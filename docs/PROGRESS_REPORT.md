# Sentora Progress Report

This document summarises the technical work and security improvements
made to the Sentora platform, newest first.

---

## 2026-08 — Cross-host correlation, a Linux ruleset worth having, and a permission check that was never made

### Correlation could not see the more competent attack

The engine was per host. Five accounts sprayed against one machine is caught;
one account sprayed across fifty machines, once each, is not — no agent sees
more than one event. That is the *better* attack: wide and shallow stays under
both per-account lockout and per-host thresholds.

`fleet_engine()` now runs in the ingest path, where every agent's events pass
through one process, and counts distinct **hosts**. Wider windows (30 minutes,
not 5), because walking an estate takes longer than walking a user list.

The server only has the agent's flattened message, so `agent_event_fields`
puts the named fields back. That is reversible because the flattening is a
positional join in our own format on both ends. It was off by one at first —
the envelope's first separator loses its leading space to the regex, so
splitting on `" | "` left `"| Failed Logon"` as segment zero, nothing was
dropped, and every field landed one position late. `TargetUserName` came back
as a SID.

### The findings reached the database and stopped there

`events_alert` rows normally reach the AI workers because the ingest loop
publishes what it inserts. A row written from *inside* that loop is not an
item the loop iterates, so a correlation finding landed in the database,
appeared in the alerts view, and never became an AI insight — which reads from
the console exactly like not detecting it.

It also could never pass the gate: that asks whether the log contains a
criterion's markers, and the summary of a fired window contains none by
construction. So a correlated finding now surfaces regardless of the model's
verdict, the same way a threat-intel match does.

Verified on the live stack, over the real TCP wire: six failed logons from six
distinct hosts produced `fleet_spray` (CRITICAL, T1110.003) and
`fleet_account_spray`, an `events_alert` row carrying the technique, and an AI
insight filed as `Realtime_` with `[!!] CORRELATION:` attached — while the
model's own verdict was SUSPICIOUS and would not have surfaced.

Re-running produced nothing, which was the second half of the proof: the
window was in cooldown, firing once rather than once per event.

### Linux detection was a token gesture

Four rules against Windows' twelve. Cron persistence, systemd units,
LD_PRELOAD, kernel modules, container escape, reverse shells, SUID backdoors
and audit tampering were all blind.

Twelve Linux rules now, 23 in total covering 23 techniques. Measured: 12 of 12
attacks fire on both the journal and a plain syslog line, 0 of 12 pieces of
ordinary administration falsely flagged — and the negatives are the ones that
took the work, since each sits beside the attack it resembles. `docker ps`
beside a socket mount, `find / -perm -4000` beside setting SUID, `modprobe`
from `/lib` beside `insmod` from `/tmp`.

Every Linux rule carries both a `CommandLine` and a `Message` selection. The
journal supplies the first; a plain syslog line supplies only the second, and
a rule written for one path is dead on the other.

### Anonymous refusal is not proof of the right permission

The smoke test called every route anonymously and checked it refused. That
does not show the permission it demands is the correct one: a SOAR dispatch
gated on `read_telemetry` passes exactly like one gated on `manage_soar`. That
is privilege escalation between roles, and nothing tested for it.

Pass 3 creates a temporary account holding a role with an empty permission set
and calls every write route with it. Safe where a privileged probe is not,
because a 403 comes from the middleware **before the handler executes** —
nothing is dispatched, deleted or truncated. The payloads name agents and ids
that do not exist, so a wrongly-permissive route acts on nothing, and anything
answering 2xx fails the run. The account and role are removed in a `finally`.

What remains open is unchanged and still stated: no write handler is executed
by a session that should succeed. That needs a disposable database and an
agent endpoint that absorbs SOAR calls.

---

## 2026-08 — Correlation, an evidence-based gate, and a backup that was needed the day it was written

### The gate stopped asking the model how sure it was

Two rounds of measurement took the confidence threshold apart. Six CRITICAL
verdicts were held at 0.50 — an LSASS dump, a SAM hive export, shadow copies
being deleted — while every benign case also came back at 0.50. Moving the
threshold changes nothing between 0.60 and 0.90, because the model emits 0.50
or 0.90 and almost nothing in between.

Then, over 29 cases including ten real events: **every attack that surfaced
already had a verified criterion**, so the confidence path caught nothing
evidence had not — while admitting both false alarms that reached an analyst.
Those two were this platform's own Docker containers restarting, at
SUSPICIOUS / CRITICAL / 0.80.

The gate now asks one question: does the log contain the evidence?
`AI_CRIT_CONF` and `AI_SUS_CONF` are read only to warn that they no longer do
anything, because silently ignoring configuration somebody deliberately set is
its own bug class.

Replaying the saved run through the new gate: **9/10 attacks kept, false
alarms 2/19 → 0/19.** The live re-run agrees — 90% reaching an analyst, 0 of 9
benign events shown, with the model over-escalating six and the gate stopping
all six.

On SUSPICIOUS specifically: the model's own SUSPICIOUS label scored precision
0.00 and recall 0.00. It can use the top of the scale and not the middle. The
middle is real and now comes from layers that can be checked — a Sigma rule at
MEDIUM, or a correlation window — rather than from asking a 3B model to feel
uncertain.

### A whole class of detection was invisible

Sigma matches a rule against one event. It cannot express "count distinct
users where the source is the same, within a window", so password spray,
brute force and a guess landing after repeated failures were not missed by a
rule — there was no rule that could exist.

`core/correlation.py` covers those shapes. Three things it gets right on
purpose:

- **Fires once per window.** A sustained spray produces one detection. This is
  the bug class that had the defensive sweep re-queueing 4,919 duplicates.
- **Bounded memory.** Group keys are attacker-supplied usernames and source
  addresses; an unbounded counter on those is a memory exhaustion primitive.
- **A window becomes its own event**, rather than relabelling the event that
  completed it. The fifth failed logon is no more interesting than the first.

The corpus case Sigma skips is now covered, and the skip says where to look
instead of standing as a permanent documented hole.

### The Linux text path was weaker than it needed to be

`text_event_fields` returned `Message` and nothing else. Parsing every log
format is not worth it; parsing the handful that carry authentication and
command execution is, and it is the difference between a host on rsyslog
getting field rules and correlation, or neither.

sshd, sudo, PAM, cron and auditd now yield `TargetUserName`, `IpAddress`,
`CommandLine`, `Image` and a synthesised `AuthResult` — Linux has no
equivalent of EventID 4624/4625, and correlation needs something stabler than
"does this text contain the word failed". Fields the line does not contain
stay absent: a wrong `Image` matches rules the event has nothing to do with.

### A first-time install had never worked

`db/init.sql` was mounted into `docker-entrypoint-initdb.d` beside
`init_userdb.sql`. It is not a server-init script — it is the per-agent schema
template, applied after connecting to that agent's own database, which is why
it contains no `CREATE DATABASE` or `USE`.

Each file in that directory runs in its own mysql session, so the `USE userdb`
at the end of the first does not carry over. On a first boot the second failed
at line 5 with "No database selected", MySQL aborted initialisation and the
container came up unhealthy. Nobody had hit it because the volume already
existed on every machine that had ever run this — it only breaks for someone
setting the project up for the first time, which is everyone who clones it.

### Docker Desktop was reset and there was no backup

Every named volume went: `mysql_data` — all telemetry, every agent database,
users and sessions — plus `opensearch_data` and `sentora_data`. Nothing had
asked for them to be removed and nothing warned.

`scripts/backup_state.py` now takes both a logical dump and a tar of every
volume compose declares, and its restore path was verified the only way that
counts: back up, `docker compose down -v`, restore, read the data back.

Two bugs surfaced in that verification, both from running it rather than
reading it. `docker -v` reads a **relative** path as a named volume rather
than a host directory, and reports the drive letter as an invalid character —
which looks like a quoting bug. And the restore printed `[+] Restored` on a
run where every archive had failed. The second is the dangerous one: a restore
that reports success it did not have is noticed the next time somebody needs
the data.

It also clarified something the deployment doc said but was easy to read past.
**There are two Fernet keys.** The server key is `FERNET_KEY` in `.env`, on
the host filesystem, and it survived. The agent key is `data/fernet.key`
inside `sentora_data`, and it did not — regenerated on the next boot, which
permanently orphans telemetry encrypted under the old one. Backing up `.env`
and not the volume protects the half that was never at risk.

### Twenty minutes to score a one-line change

Every gating and criterion change was measured by paying for 29 model calls
twice, the second time to get an identical set of replies. The harness now
caches the raw reply keyed on **the model and the prompt text** — which is
what makes it safe, since `ai.utils`' production cache is keyed on the log
alone and would make a rewritten prompt look identical to the one it replaced.

Criteria and gating are scored fresh on every run because what is cached is
the reply, before either. Re-scoring went from twenty minutes to 2.3 seconds,
and a fully cached run says so rather than passing as a fresh measurement.

### Telemetry that a machine actually produced

`scripts/generate_telemetry.py` performs the harmless action that produces the
same event as a technique — `vssadmin list shadows` rather than deleting them,
a scheduled task created and removed, a real `-EncodedCommand` whose payload
prints the date. Each entry says whether it exercises a rule end to end or
only the collection path, and techniques with no harmless version — an actual
LSASS dump, actually clearing the Security log — are listed, refused, and
documented as the gap they are rather than quietly omitted.

---

## 2026-08 — Sigma detection, ATT&CK coverage, and a corpus that says what it is

### Detection did not depend on the model, and now it does not have to

Detection was a 1,575-entry regex list nobody outside this repository had
reviewed, plus an LLM. The regex list stops at the first pattern that matches,
so one broad pattern could label every event COMMAND INJECTION and hide
everything behind it.

Sigma now runs first on every collection path and the regex list is the
fallback. Sigma matches *named fields*, which is a different kind of claim:
`Image|endswith: '\vssadmin.exe'` cannot be defeated by the word "vssadmin"
appearing in an unrelated message. It is also deterministic, so it keeps
working when the model is unavailable or wrong.

Compiled in process rather than via pysigma, which targets query languages
(Splunk SPL, Elasticsearch DSL) and has no backend answering "does this dict
match" — the only question an agent has.

**An unsupported construct raises rather than compiling to false.** A rule
that silently never fires is worse than one that fails to load: the second is
visible on the next start, the first is discovered after an intrusion.

### Sigma ran only on Windows

The file and journal paths still used the regex list, so a Linux endpoint got
no Sigma at all and no ATT&CK technique on anything — the coverage page would
have reported a Windows-only estate as the whole estate.

All three paths now share one classifier. The journal gets real field mapping
(`_COMM`, `_CMDLINE`, `_SYSTEMD_UNIT`), because it genuinely carries those.
Plain log files get `Message` and whatever the enricher extracted, and that
limit is stated rather than papered over: a rule matching `CommandLine` cannot
fire on a syslog line, and a test pins the distinction so it cannot quietly
reverse.

### The rules directory was empty on purpose, and the purpose was wrong

The argument for shipping no rules — a detection nobody reviewed is not an
improvement — is a good one. The outcome was zero ATT&CK coverage on every
install and a coverage page with nothing to draw. "No detections" is not a
defensible default for a product whose job is detection.

15 rules now ship covering 16 techniques, scoped to what the agent actually
collects. Measured against the eval corpus rather than asserted: **9 of 10
attacks caught by Sigma alone, 0 of 9 hard negatives falsely flagged.** The
miss is password spray, which is a shape across several events and stateless
Sigma cannot express it — noted in the test rather than left as an
unexplained failure.

Two hard negatives caught real bugs in the baseline before it shipped:

- A management agent installing a service from `\\corp-sccm01\SoftwareDist$`.
  The rule matched any UNC path. ADMIN$ and C$ exist on every host without
  anybody creating them; a vendor's own distribution share does not, and
  restricting to the built-in hidden shares keeps the PsExec case and drops
  the false alarm.
- `[Convert]::FromBase64String($env:APP_CONFIG)` from a developer's terminal.
  Base64 on a PowerShell command line is not an indicator by itself.

### Two bugs in the Sigma evaluator, found by writing rules against it

**`base64offset` only trimmed the leading end.** base64 packs three bytes into
four characters, so both the first *and* last groups are shared with whatever
surrounds the needle — a needle carrying its own final group matches only when
it happens to sit at the very end of the payload. How much to trim from the
end depends on where the needle *ends*, which is the padding plus its own
length. Until this was fixed, `base64offset` found "Net.WebClient" in nothing
at all.

**No `utf16le` modifier.** PowerShell's `-EncodedCommand` takes UTF-16LE, so a
needle encoded as UTF-8 and base64'd cannot appear in that payload. Every
community SigmaHQ PowerShell rule uses `|utf16le|base64offset|contains`; all
of them were being rejected. Added, along with `utf16be`, `utf16` and `wide`,
and an encoding modifier used without base64 is now rejected outright rather
than compiled into a comparison that can never be true.

Together these are what let a rule read *inside* an encoded payload — the
difference between detecting that something was encoded and detecting what it
was.

### Sysmon IDs would have been read on the wrong channel

Sysmon's event IDs are small numbers — 1, 11, 13 — that mean something
entirely different on the System and Application channels. A single mapping
table would have read a System event through Sysmon's field layout, putting
arbitrary text into `Image` and `CommandLine` and inventing evidence for
whichever rule then matched it. Split into `SYSMON_FIELDS`, selected by
channel.

### Detections were flagged and never seen

The eval said 90% escalation recall; production showed 20% of them to an
analyst. The gap was the confidence gate.

Measuring the threshold instead of guessing at it disproved the obvious fix:
between 0.60 and 0.90 nothing changes, because the model returns 0.50 or 0.90
and nothing in between. Dropping to 0.50 gains one attack and admits six false
alarms. Six CRITICAL verdicts were blocked at confidence 0.50 — an LSASS dump,
a SAM hive export, shadow copies being deleted — and every benign case also
came back at 0.50. **The number carries no signal in either direction.**

A criterion verified by `ai/criteria` is not model output: it holds only when
the log itself contains the markers, which is a fact about the event. Those
now bypass the confidence gate. **Reaches an analyst: 20% → 80%**, against a
±20% noise floor the report states on every run.

### Two criteria treated location as evidence

Folding real telemetry into the attack corpus immediately failed a test, which
is the outcome that justifies having done it.

`C4` "persistence to a writable path" matched on the path alone. Windows Error
Reporting writes crash dumps to `C:\ProgramData\Microsoft\Windows\WER\Temp\`,
so three of the ten real events were being forced to CRITICAL — and a forced
criterion bypasses the confidence gate, so each one reached an analyst. A path
is a location; persistence is something that will run again. Each alternative
now names a mechanism as well.

`C5` "obfuscated execution" treated `-enc` as the indicator. This estate's own
tooling runs encoded commands on ordinary afternoons. The flag is not what
separates a cradle from a config string, so the base64 is now decoded (UTF-16LE
and UTF-8) and searched — moving the question from "was this encoded" to "what
does it do", which is the only one the two cases answer differently.

### The corpus now says what it is

Every positive case is written by hand from documented technique behaviour —
nobody has run mimikatz on this estate and nobody is going to. That makes
recall an upper bound, not a safety claim, and the report never said so.

Provenance now travels with each case and is printed on every run. Precision
does not have the same problem: a false alarm on a quiet estate is a real
false alarm, so the ten labelled real events were folded in as negatives. The
half that can be measured against reality is; the half that cannot says so.

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
