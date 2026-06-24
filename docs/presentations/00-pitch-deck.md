---
marp: true
theme: default
paginate: true
backgroundColor: '#0b1220'
color: '#e2e8f0'
style: |
  section { font-family: 'Inter', sans-serif; padding: 56px 72px; }
  h1 { color: #60a5fa; font-size: 2.2em; margin-bottom: 0.2em; }
  h2 { color: #93c5fd; font-size: 1.6em; }
  h3 { color: #a78bfa; }
  code { background: rgba(96,165,250,0.12); padding: 1px 6px; border-radius: 4px; color: #fbbf24; }
  pre { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; font-size: 0.7em; }
  table { font-size: 0.75em; }
  blockquote { border-left: 4px solid #60a5fa; color: #94a3b8; padding-left: 12px; }
  .lead { color: #cbd5e1; font-size: 1.2em; margin-top: 0.6em; }
  .small { font-size: 0.8em; color: #94a3b8; }
  .pill { display: inline-block; padding: 2px 10px; border-radius: 999px; background: rgba(96,165,250,0.15); color: #93c5fd; font-size: 0.7em; margin-right: 6px; }
  .danger { color: #ef4444; }
  .ok { color: #34d399; }
  .warn { color: #fbbf24; }
  footer { color: #64748b; font-size: 0.7em; }
footer: 'Sentora Community Edition · DTCloud meeting deck'
---

# Sentora
## Self-hosted SIEM, SOAR and EDR with local AI triage

<div class="lead">
Bir kutu içinde SIEM, SOAR, EDR ve lokal LLM analizi. Logları ağdan çıkarmadan threat triage. Tek <code>docker compose up</code>.
</div>

<div class="small" style="margin-top:80px;">
DTCloud · teknik + ticari sunum  
Hazırlayan: Oğuzhan Bayarslan
</div>

---

## Why this deck exists

Tipik bir SIEM/SOAR alımı 4 ayrı vendor ile başlar:

- Log toplama (Splunk, Elastic, Wazuh)
- Bulut tabanlı AI triage (OpenAI/Anthropic SaaS, log dışarı çıkar)
- SOAR (Cortex XSOAR, Tines, Shuffle)
- EDR (CrowdStrike, SentinelOne)

Yıllık maliyet 6 haneli rakamlara çıkıyor. Loglar firma dışına gidiyor.
KVKK/GDPR uyumluluğu için ekstra DPA imzalanıyor.

**Sentora dört kutuyu da tek stack'te self-hosted veriyor.**

---

## Tek slayt özet

<style scoped>
section { font-size: 0.9em; }
</style>

| Bileşen | Karşılığı | Bu pakette |
| :--- | :--- | :--- |
| Log toplama + index | Elastic / Wazuh / Splunk | <span class="ok">var (MySQL + OpenSearch)</span> |
| AI triage | OpenAI / Anthropic SaaS | <span class="ok">lokal Ollama (offline)</span> |
| SOAR otomasyonu | Cortex XSOAR / Tines | <span class="ok">visual playbook + autonomous worker</span> |
| EDR ajan | CrowdStrike Falcon / SentinelOne | <span class="ok">Windows + Linux cross-platform</span> |
| Vuln tarama | Tenable / Qualys | <span class="ok">OSV scanner</span> |
| Uzak masaüstü | TightVNC / TeamViewer | <span class="ok">WebSocket JPEG stream</span> |

`docker compose up -d` ile tek host'ta ayağa kalkıyor. AGPL-3.0 + commercial waiver opsiyonu.

---

# Demo: gerçek arayüz

Sıradaki 5 slayt sistemden alınmış canlı ekran görüntüleri.

---

## Security Command Center

![bg right:60% fit](../pics/dashboard.jpg)

Tek bakışta:
- Server CPU/RAM/Disk
- Bağlı agent sayısı
- Kritik alert sayacı
- AI Security Intelligence feed'i
- Recent Global Alerts (her agent'tan)

30 sn'de bir otomatik refresh.

---

## Per-agent overview

![bg right:60% fit](../pics/agent-overview.jpg)

Her endpoint kendi sayfası:
- 12 sekme (SIEM, Alerts, Vulns, Packages, Docker, Ports, Files, VNC, Config, AI Analysis, SOAR, System)
- Canlı CPU/RAM
- Latest SIEM logs (renkli source rozetleri)
- Threat Summary
- "Isolate" tek tıkla network izolasyonu

---

## AI Analysis

![bg right:60% fit](../pics/agent-ai-analysis.jpg)

Lokal Ollama her event'i analiz eder:
- Verdict (CRITICAL / SUSPICIOUS / MONITOR)
- Confidence skorlu
- MITRE ATT&CK techniques
- IOC çıkarımı
- "Next steps" madde madde
- **View Source** ile AI'nin gördüğü ham log

Her insight için ayrı kart. Counter rozetleri (TOTAL / AUTO-ACTIONS / CRITICAL).

---

## Asset Inventory

![bg right:55% fit](../pics/asset-inventory-network.jpg)

Hardware, software, network sockets:
- Her PnP device, her paket, her açık port
- Hangi process hangi porta bağlanmış (PID + path)
- Filtreli arama
- Cross-platform (Windows PnP + Linux psutil)

---

## Log Explorer

![bg right:55% fit](../pics/log-explorer.jpg)

OpenSearch backed cross-agent search:
- Tüm agent'lar tek sorguda
- Dataset tipine göre filtre (SIEM, Alerts, Process, Network, FIM, Audit)
- 10K+ kayıt anlık
- Kibana'ya (OpenSearch Dashboards) tek tık

---

# Mimari

Nasıl çalışıyor.

---

## Component topology

```
Endpoints (Windows / Linux agents)
    │
    │  TCP frames (port 5001) + REST polling
    ▼
┌─────────────────────────────────────────────────┐
│  ingest (server.py)                              │
│      ↓                                            │
│  MySQL  ←  per-agent <name>_db schemas           │
│      ↓                                            │
│  RabbitMQ  (AI task queues)                       │
│      ↓                                            │
│  AI workers x3 (automation / manual / defensive) │
│      ↓                                            │
│  Ollama (local LLM, llama3.2:3b default)         │
│      ↓                                            │
│  OpenSearch (full-text log search)               │
└─────────────────────────────────────────────────┘
    ↑
    │  REST + WebSocket (port 8000)
    │
React UI  (SPA, locally bundled fonts)
```

Hepsi tek `docker-compose.yaml`. 9 servis. ~16 GB RAM.

---

## AI pipeline detayı

Her event 3 paralel worker'a girer:

| Worker | Tetik | Görev |
| :--- | :--- | :--- |
| `automation` | Her ingest'te otomatik | Gerçek zamanlı triage. NOT_CRITICAL'ları filtreler, CRITICAL/SUSPICIOUS'ları AI Insight olarak kaydeder. |
| `manual` | Operatör "Run Manual Scan" der | Toplu deep-scan. Son N siem_events / events_alert üzerinde MITRE haritalama, IOC extraction. |
| `defensive` | Her `events_alert`'te otomatik | Verdict ACT + confidence yüksekse autonomous SOAR action kuyruğa atar. |

Confidence eşikleri `.env`'den ayarlı:
- `AI_AUTO_ACT_CONF=0.75` (autonomous dispatch için minimum)
- `AI_CRIT_CONF=0.6` (CRITICAL kaydı için minimum)

---

## Defensive autonomy: izinli action listesi

Autonomous worker sadece bu 11 action'ı **insan onayı olmadan** atabilir:

```
BLOCK_IP        KILL_PROCESS      RESTART_SERVICE   ISOLATE_HOST
DISABLE_USER    QUARANTINE_FILE   SUSPEND_PROCESS   LOGOFF_USER
CONTAINER_ISOLATE   CONTAINER_STOP   CONTAINER_KILL
```

Bunların dışı (`RUN_CMD`, `DELETE_FILE` gibi) advisory'e indirilir; operatör manuel approve eder. Tasarım gereği "AI keyfi komut çalıştıramaz" prensibi.

`AI_AUTO_ACT_CONF=1.0` set edilirse autonomy tamamen kapanır, AI sadece insight üretir.

---

## Shadow Mode

Production'a almadan modeli denemek için.

```
AI_SHADOW_MODE=1
```

Aktifken her autonomous verdict **proposal** olarak kaydedilir. Gerçek action atılmaz. SOAR Hub > Shadow Queue tab'ında listelenir:

- **Approve** → gerçek SOAR action dispatch edilir, kim onayladı + ne zaman audit'e düşer.
- **Reject** → karar kaydedilir, opsiyonel sebep yazılabilir.

Proposal'lar expire olmaz. Operatör karar verene kadar pending kalır.

Tipik kullanım: 2-4 hafta shadow modunda çalıştır, false-positive oranını ölç, prompt'u/threshold'u kalibre et, sonra production autonomy'e geç.

---

## Per-agent enrolment

Her agent ayrı 64 karakterlik key alır:

```powershell
iwr -useb 'https://soc.example.com/api/agent/deploy/windows?token=<TOKEN>' | iex
```

1. Server token'ı validate eder, agent için kayıt açar.
2. Agent yeni bir key alır, `config.json`'a yazar.
3. Agent her ingest çağrısında `X-Agent-Key` ile authenticate olur.
4. Server bootstrap'te Fernet key gönderir (telemetri at-rest şifreleme için).
5. Agent scheduled task (Windows) / systemd unit (Linux) olarak kalıcı kurulur.

Bir agent compromise olursa sadece kendi key'i revoke edilir; diğerleri etkilenmez.

---

# Production deployment

Hardware, network, sertifika, monitoring.

---

## Sizing rehberi

<style scoped>
table { font-size: 0.85em; }
</style>

| Tier | CPU | RAM | Disk | Agent | Not |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Lab / POC | 4 core | 12 GB | 40 GB SSD | ≤ 5 | OpenSearch heap 1 GB'a sıkıştır |
| Small team | 8 core | 16 GB | 100 GB SSD | 10-50 | Compose default'ları çalışır |
| Production | 16+ core | 32 GB+ | 250+ GB NVMe | 50-300 | OpenSearch ve Ollama'yı ayır |
| Scale-out | 32+ core | 64 GB+ | 1 TB+ NVMe | 300+ | OpenSearch cluster, ayrı RabbitMQ host |

Per-service idle: Ollama 3 GB, OpenSearch 2 GB, MySQL 0.5-1 GB, RabbitMQ 0.3 GB, app + 3 worker 1 GB.

**GPU gerekmez.** Ollama varsa otomatik kullanır, yoksa CPU'da çalışır.

---

## Önerilen network topology

```
                    Internet
                       │
                       │  (sadece dış agent kullanılacaksa)
                       ▼
              ┌──────────────────┐
              │   reverse proxy  │  (nginx/Traefik, TLS terminasyonu)
              │   :443 → :8000   │
              │   :5001 → :5001  │
              └──────────────────┘
                       │
                       │  internal network
                       ▼
              ┌──────────────────┐
              │   Sentora host  │
              │   docker compose │
              └──────────────────┘
                       │
                       │  agent push (TCP/443 over TLS proxy)
                       ▼
        ┌──────────────────────────────┐
        │   Endpoint fleet              │
        │   Windows + Linux agents       │
        └──────────────────────────────┘
```

İnternal-only deployment için reverse proxy opsiyonel; doğrudan `:8000` ve `:5001` açılır.

---

## Sertifika yönetimi

Üç senaryo:

1. **Lokal/POC:** `certs/generate_certs.py` self-signed CA + server cert üretir. Sadece test için.
2. **Kurumsal CA:** Mevcut iç CA'dan imzalı `server.crt` + `server.key` verilir. `.env`'de `TLS_ENABLED=1`, `TLS_CERT`/`TLS_KEY` set edilir.
3. **Reverse proxy ile Let's Encrypt:** TLS proxy'de sonlanır, app `:8000`'i plain HTTP olarak sunar. Pratik tercih.

Rotasyon:
- Yeni sertifikayı `certs/` altına koy.
- `docker compose restart app`.
- Agent'lar 64 karakterlik kendi key'leriyle authenticate olduğu için TLS değişikliği agent re-enrol gerektirmez.

---

## Veri kalıcılığı

Compose'da iki named volume:

| Volume | İçerik | Backup öncelik |
| :--- | :--- | :--- |
| `mysql_data` | Tüm SIEM logs, agent enrolment, AI insights, automations, playbooks | <span class="danger">Yüksek</span> |
| `opensearch_data` | Log search index (MySQL'den rebuild edilebilir) | <span class="warn">Orta</span> |

Ek dosya:

| Path | İçerik | Backup |
| :--- | :--- | :--- |
| `data/fernet.key` | Agent telemetri Fernet anahtarı | <span class="danger">Yüksek (kayıp = telemetri okunamaz)</span> |
| `.env` | DB password, FERNET_KEY, agent shared secret | <span class="danger">Yüksek</span> |
| `Sentora/main.exe` + `Sentora/main` | Production agent binary | <span class="warn">Rebuild edilebilir</span> |

Önerilen: günlük `mysqldump` + `data/fernet.key` + `.env` snapshot, ayrı bir host'a kopya.

---

## Monitoring & observability

Compose içinde 3 yerleşik yüzey:

| Servis | Port | Ne için |
| :--- | :--- | :--- |
| RabbitMQ management | `:15672` | Queue depth, dead letters, throughput |
| OpenSearch Dashboards | `:5601` | Log search + ad-hoc dashboard |
| App health check | `:8000/health` | Liveness probe |

Önerilen entegrasyon:

- Prometheus exporters (RabbitMQ, MySQL, Node) için sidecar ekle.
- Grafana dashboard'una bağla. Alert: `ai_analysis_results` saatlik yazım hızı, worker queue depth, agent `last_seen` > 5 dk.
- Application logs Docker'ın stdout'undan; Loki/CloudWatch'a yönlendir.

---

# Update mekanizması

Yeni sürüm geldiğinde nasıl yükselteceğiz.

---

## Sürüm modeli

İki ayrı binary akışı var:

1. **Server stack** (Docker image + compose)
2. **Agent binary** (`main.exe` / `main`)

Versiyonlama: `vMAJOR.MINOR.PATCH`.

| Tip | Anlam | Örnek |
| :--- | :--- | :--- |
| PATCH | Bugfix, UI iyileştirme, küçük endpoint düzeltmesi | v1.2.0 → v1.2.1 |
| MINOR | Yeni özellik, geriye uyumlu API değişikliği | v1.2.0 → v1.3.0 |
| MAJOR | Breaking API/DB change | v1.x → v2.0 |

Her release `CHANGELOG.md`'de "Breaking", "Added", "Fixed" başlıklarıyla yayınlanır.

---

## Server upgrade (PATCH/MINOR)

Standart akış, zero-downtime hedefli:

```bash
# 1. Backup
mysqldump --all-databases > backups/$(date +%F).sql
tar czf backups/$(date +%F)-config.tgz data/ .env

# 2. Yeni sürüme geç
git fetch && git checkout v1.3.0

# 3. Image rebuild
docker compose build --no-cache app ingest \
    ai-worker-automation ai-worker-manual ai-worker-defensive

# 4. Rolling restart
docker compose up -d --force-recreate \
    app ingest ai-worker-automation ai-worker-manual ai-worker-defensive

# 5. Smoke test
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/devices  # agents listesi
```

DB migration'lar `save_ai_results` / ensure-table fonksiyonlarında idempotent `ALTER TABLE` ile uygulanır. Manuel migration script genellikle gerekmez.

---

## Server upgrade (MAJOR)

Breaking change varsa README + CHANGELOG'da explicit prosedür yayınlanır. Tipik adımlar:

1. Tüm agent'ların önce yeni server ile uyumlu binary'ye çekildiğinden emin ol (aşağı uyumluluk).
2. Maintenance window planla (10-30 dk).
3. Bir snapshot al (VM/disk snapshot).
4. Yeni image'ı yükle, varsa migration runbook'unu uygula.
5. Smoke test, sonra agent'ları onla.

Rollback: snapshot geri yükle, eski `docker-compose.yaml`'a dön, eski image'ları çek.

---

## Agent rollout

Agent binary değiştiğinde:

1. `Sentora/build_agent.{sh,ps1}` ile yeni binary üret. Hash logla.
2. `docker compose restart app` (binary `/api/agent/download/...` endpoint'i tarafından serve edilir).
3. Hedef makinede:

```powershell
# Admin shell
Stop-ScheduledTask -TaskName SentoraAgent
Get-Process main -EA SilentlyContinue | Stop-Process -Force
iwr -useb 'https://soc.example.com/api/agent/deploy/windows?token=<TOKEN>' | iex
```

Deploy script `main.exe`'yi yerinde değiştirir, scheduled task'i yeniden register eder. Mevcut config (`agent_name`, `agent_key`) korunur. Re-enrolment gerekmez.

---

## Phased rollout stratejisi

Üretimde 200+ agent varsa:

| Faz | Hedef | Süre | Çıkış kriteri |
| :--- | :--- | :--- | :--- |
| 1. Canary | 3-5 test endpoint | 24 saat | crash yok, telemetri akıyor |
| 2. Wave 1 | %10 fleet | 3-7 gün | RAM/CPU baseline ile %20 içinde |
| 3. Wave 2 | %50 fleet | 1 hafta | OpenSearch index hızı stabil |
| 4. Full | %100 | < 1 hafta | Tüm `last_seen` < 2 dk |

Rollout aracı: kurum içi MDM (Intune, JAMF) veya kendi tooling'iniz. Tek satır PowerShell/bash deploy komutu olduğu için entegrasyon basit.

---

## Rollback

Agent rollback:

```powershell
# Eski binary'yi MDM ile geri push et
Stop-ScheduledTask -TaskName SentoraAgent
Copy-Item C:\Backups\main.exe.previous "C:\Program Files\Sentora-Agent\main.exe" -Force
Start-ScheduledTask -TaskName SentoraAgent
```

Server rollback:

```bash
git checkout v1.2.0
docker compose build --no-cache
docker compose up -d --force-recreate
# DB rollback gerekmiyorsa (PATCH/MINOR çoğu zaman) eski schema yeni binary ile uyumlu kalır.
```

Major rollback için snapshot geri yükleme zorunlu.

---

# Güvenlik & uyumluluk

---

## Güvenlik modeli özeti

| Katman | Mekanizma |
| :--- | :--- |
| Agent ↔ Server auth | Per-agent 64 karakterlik bearer key + opsiyonel TLS |
| Telemetri at-rest | Fernet AES-128-CBC + HMAC, anahtar `data/fernet.key` |
| Server-side at-rest (user table, SOAR comments vb.) | Fernet, ayrı `FERNET_KEY` env |
| UI auth | Local bcrypt + opsiyonel LDAP / LDAPS |
| RBAC | Permission-based (read_telemetry, manage_soar, manage_agent, ...) |
| Audit logs | Her login attempt + her SOAR dispatch + her shadow approve/reject |
| AI safety | Allow-list dışı action'lar autonomous tetiklenemez. Shadow mode ile insan-in-the-loop. |

---

## Compliance uyumu

Out-of-the-box destekler:

- **KVKK/GDPR data residency:** Loglar host'tan çıkmaz. Ollama lokal. Üçüncü taraf AI API'si yok.
- **ISO 27001 A.12.4 logging:** Tüm login attempt + SOAR action audit'i. Source IP + actor + timestamp.
- **ISO 27001 A.9 access control:** Local user + LDAP, RBAC permissions.
- **NIS2 incident reporting:** AI insights + SOAR action history retention.

Pro/Enterprise tier'da ek olarak:

- WORM audit retention (compliance-grade tamper-proof log)
- PCI-DSS / HIPAA / ISO 27001 hazır dashboard'lar
- SAML/SCIM SSO
- 4-eyes approval workflow

---

## Air-gap deployment

Tamamen internet'siz çalışır:

- Ollama modeli `./ollama` volume'unda persistent. Bir kere indir, sonra offline.
- OSV vuln scanner: `OSV_MODE=mirror` + internal mirror URL.
- OTX / VirusTotal: opsiyonel, key set edilmezse no-op.
- UI fontları image içinde gömülü (CDN yok).
- Hiçbir telemetri phone-home yok.

Tek dış bağımlılık (opsiyonel): public OSV ve threat intel feed'leri. İkisi de set edilmezse stack tamamen kapalı çalışır.

---

# Lisans & ticari

---

## Community Edition (AGPL-3.0)

Bu sunumdaki her şey **Community** sürümünde mevcut. Limit yok:

- Agent sayısı: sınırsız
- Retention: sınırsız (disk müsait olduğu sürece)
- Feature gating: yok, core detection capability tamamı açık
- Self-hosting: serbest, kaynak değiştirme serbest

**AGPL maddesi:** Modifiye edilmiş bir Sentora'u **harici kullanıcılara** SaaS olarak sunarsanız, modifikasyonları AGPL altında yayınlamak zorundasınız. Sadece internal kullanım için yayın zorunluluğu yok.

---

## Pro / Enterprise add-on

Core her zaman açık; sadece kurumsal glue paid:

<style scoped>
table { font-size: 0.7em; }
</style>

| Özellik | Community | Pro | Enterprise |
| :--- | :---: | :---: | :---: |
| Local AI triage (Ollama) | ✓ | ✓ | ✓ |
| SIEM + SOAR + EDR agent | ✓ | ✓ | ✓ |
| OSV vuln scanning | ✓ | ✓ | ✓ |
| Playbook engine | ✓ | ✓ | ✓ |
| Shadow Mode | ✓ | ✓ | ✓ |
| SAML/OIDC SSO | | ✓ | ✓ |
| SCIM 2.0 provisioning | | ✓ | ✓ |
| Splunk/Sentinel forwarder | | ✓ | ✓ |
| Multi-tenancy / MSSP | | | ✓ |
| Compliance dashboards (PCI/ISO/HIPAA) | | | ✓ |
| WORM audit retention | | | ✓ |
| HA clustering | | read replica | full HA |
| 4-eyes SOAR approval | | | ✓ |
| Signed air-gap update bundles | | | ✓ |
| Support | community | email 24h | phone + SLA |

---

## Commercial license waiver

AGPL'in network-copyleft maddesinden kaçınmak isteyen organizasyonlar için commercial waiver verilir:

- Closed-source ürün üzerine entegrasyon serbest.
- Modifikasyonları yayınlama zorunluluğu kalkar.
- Pro/Enterprise tier ile bundle'lanır.

Fiyatlandırma: agent sayısı + support seviyesi bazlı. Talep üzerine teklif.

---

# Roadmap

---

## Sonraki 6 ay

<style scoped>
section { font-size: 0.9em; }
</style>

| Çeyrek | Item | Tier |
| :--- | :--- | :--- |
| Q2 | macOS agent | Community |
| Q2 | Windows ETW provider entegrasyonu (deeper kernel-level telemetri) | Community |
| Q2 | Multi-model AI routing (lokal lightweight + opsiyonel daha büyük model) | Community |
| Q3 | Slack/Teams native notification connector | Pro |
| Q3 | Compliance dashboard suite (PCI-DSS, ISO 27001) | Enterprise |
| Q3 | OpenSearch cluster autoscaler | Enterprise |
| Q4 | Signed update bundles (kod + agent + LLM model birlikte imzalı) | Enterprise |
| Q4 | SAML/SCIM | Pro |
| Q4 | 4-eyes SOAR approval workflow | Enterprise |

Roadmap müşteri talebine göre öne çekilebilir.

---

# Sıradaki adım

---

## Önerilen DTCloud POC akışı

| Hafta | Aktivite | Çıktı |
| :--- | :--- | :--- |
| 1 | Lab kurulumu, 3-5 endpoint enrolment | Stack çalışıyor, dashboard'a veri akıyor |
| 2 | Shadow Mode aktif, defensive AI üretim trafiğinde | False-positive oranı ölçüldü, prompt kalibre edildi |
| 3 | Playbook tasarımı (kurumsal incident response runbook'larından) | 5-10 hazır playbook |
| 4 | Pilot fleet'e (20-30 agent) genişletme | Production benchmark'ı |
| 5-6 | Tam fleet rollout planı, monitoring, alerting | Go-live readiness |

POC süresince Community tier kullanılabilir. Pro/Enterprise teklifimiz POC çıktısına göre özelleştirilir.

---

<style scoped>
section { text-align: center; padding-top: 120px; }
h1 { font-size: 3em; }
</style>

# Teşekkürler

**Sentora Community Edition**  
github.com/0giv/Sentora-Community-Edition

oguzhanbayarslan@gmail.com

<div class="small" style="margin-top:60px;">
Soru / demo / POC için iletişime geçebilirsiniz.
</div>
