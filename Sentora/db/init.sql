
-- ========== critical_files ==========
CREATE TABLE IF NOT EXISTS critical_files (
    id           SERIAL PRIMARY KEY,
    path         TEXT,
    owner        TEXT,
    grp          TEXT,
    permissions  TEXT,
    last_opened  TEXT,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);
ALTER TABLE critical_files
    ADD COLUMN IF NOT EXISTS path         TEXT,
    ADD COLUMN IF NOT EXISTS owner        TEXT,
    ADD COLUMN IF NOT EXISTS grp          TEXT,
    ADD COLUMN IF NOT EXISTS permissions  TEXT,
    ADD COLUMN IF NOT EXISTS last_opened  TEXT,
    ADD COLUMN IF NOT EXISTS collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS sent         BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dup_fp       CHAR(64);
CREATE INDEX IF NOT EXISTS idx_cf_path ON critical_files (path);
CREATE INDEX IF NOT EXISTS idx_cf_dup  ON critical_files (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_cf_dup_not_null
  ON critical_files (dup_fp) WHERE dup_fp IS NOT NULL;

-- ========== portscan_result ==========
CREATE TABLE IF NOT EXISTS portscan_result (
    id         SERIAL PRIMARY KEY,
    port       INTEGER,
    protocol   TEXT,
    service    TEXT,
    product    TEXT,
    version    TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent       BOOLEAN DEFAULT FALSE,
    dup_fp     CHAR(64)
);
ALTER TABLE portscan_result
    ADD COLUMN IF NOT EXISTS port       INTEGER,
    ADD COLUMN IF NOT EXISTS protocol   TEXT,
    ADD COLUMN IF NOT EXISTS service    TEXT,
    ADD COLUMN IF NOT EXISTS product    TEXT,
    ADD COLUMN IF NOT EXISTS version    TEXT,
    ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS sent       BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dup_fp     CHAR(64);
CREATE INDEX IF NOT EXISTS idx_ps_port ON portscan_result (port);
CREATE INDEX IF NOT EXISTS idx_ps_dup  ON portscan_result (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ps_dup_not_null
  ON portscan_result (dup_fp) WHERE dup_fp IS NOT NULL;

-- ========== resource_usage (snapshot) ==========
CREATE TABLE IF NOT EXISTS resource_usage (
    id             SERIAL PRIMARY KEY,
    cpu_percent    REAL,
    mem_total      BIGINT,
    mem_available  BIGINT,
    mem_used       BIGINT,
    mem_percent    REAL,
    "timestamp"    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent           BOOLEAN DEFAULT FALSE
);
ALTER TABLE resource_usage
    ADD COLUMN IF NOT EXISTS cpu_percent    REAL,
    ADD COLUMN IF NOT EXISTS mem_total      BIGINT,
    ADD COLUMN IF NOT EXISTS mem_available  BIGINT,
    ADD COLUMN IF NOT EXISTS mem_used       BIGINT,
    ADD COLUMN IF NOT EXISTS mem_percent    REAL,
    ADD COLUMN IF NOT EXISTS "timestamp"    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS sent           BOOLEAN DEFAULT FALSE;

-- ========== disk_usage (snapshot) ==========
CREATE TABLE IF NOT EXISTS disk_usage (
    id         SERIAL PRIMARY KEY,
    device     TEXT,
    mountpoint TEXT,
    total_gb   REAL,
    used_gb    REAL,
    free_gb    REAL,
    percent    REAL,
    "timestamp" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent       BOOLEAN DEFAULT FALSE
);
ALTER TABLE disk_usage
    ADD COLUMN IF NOT EXISTS device      TEXT,
    ADD COLUMN IF NOT EXISTS mountpoint  TEXT,
    ADD COLUMN IF NOT EXISTS total_gb    REAL,
    ADD COLUMN IF NOT EXISTS used_gb     REAL,
    ADD COLUMN IF NOT EXISTS free_gb     REAL,
    ADD COLUMN IF NOT EXISTS percent     REAL,
    ADD COLUMN IF NOT EXISTS "timestamp" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS sent        BOOLEAN DEFAULT FALSE;

-- ========== packages ==========
CREATE TABLE IF NOT EXISTS packages (
    id         SERIAL PRIMARY KEY,
    package    TEXT,
    version    TEXT,
    sent       BOOLEAN DEFAULT FALSE,
    dup_fp     CHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE packages
    ADD COLUMN IF NOT EXISTS package    TEXT,
    ADD COLUMN IF NOT EXISTS version    TEXT,
    ADD COLUMN IF NOT EXISTS sent       BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dup_fp     CHAR(64),
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_pk_name ON packages (package);
CREATE INDEX IF NOT EXISTS idx_pk_dup  ON packages (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pk_dup_not_null
  ON packages (dup_fp) WHERE dup_fp IS NOT NULL;

-- ========== vulnerabilities_report (PG sürüm) ==========
CREATE TABLE IF NOT EXISTS vulnerabilities_report (
    id               SERIAL PRIMARY KEY,
    package_name     TEXT,
    package_version  TEXT,
    vulnerability_id TEXT,
    summary          TEXT,
    details_url      TEXT,
    dup_fp           CHAR(64),
    sent             BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE vulnerabilities_report
    ADD COLUMN IF NOT EXISTS package_name     TEXT,
    ADD COLUMN IF NOT EXISTS package_version  TEXT,
    ADD COLUMN IF NOT EXISTS vulnerability_id TEXT,
    ADD COLUMN IF NOT EXISTS summary          TEXT,
    ADD COLUMN IF NOT EXISTS details_url      TEXT,
    ADD COLUMN IF NOT EXISTS dup_fp           CHAR(64),
    ADD COLUMN IF NOT EXISTS sent             BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_vr_vuln ON vulnerabilities_report (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vr_pkg  ON vulnerabilities_report (package_name);
CREATE INDEX IF NOT EXISTS idx_vr_dup  ON vulnerabilities_report (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vr_dup_not_null
  ON vulnerabilities_report (dup_fp) WHERE dup_fp IS NOT NULL;

-- ========== siem_events ==========
CREATE TABLE IF NOT EXISTS siem_events (
    id         SERIAL PRIMARY KEY,
    source     TEXT,
    "timestamp" TEXT,
    message    TEXT,
    dup_fp     CHAR(64),
    sent       BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE siem_events
    ADD COLUMN IF NOT EXISTS source      TEXT,
    ADD COLUMN IF NOT EXISTS "timestamp" TEXT,
    ADD COLUMN IF NOT EXISTS message     TEXT,
    ADD COLUMN IF NOT EXISTS dup_fp      CHAR(64),
    ADD COLUMN IF NOT EXISTS sent        BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_siem_src ON siem_events (source);
CREATE INDEX IF NOT EXISTS idx_siem_dup ON siem_events (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_siem_dup_not_null
  ON siem_events (dup_fp) WHERE dup_fp IS NOT NULL;

-- ========== events_alert ==========
CREATE TABLE IF NOT EXISTS events_alert (
    id         SERIAL PRIMARY KEY,
    source     TEXT,
    "timestamp" TEXT,
    severity   TEXT,
    score      INTEGER,
    categories TEXT,
    message    TEXT,
    dup_fp     CHAR(64),
    sent       BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE events_alert
    ADD COLUMN IF NOT EXISTS source      TEXT,
    ADD COLUMN IF NOT EXISTS "timestamp" TEXT,
    ADD COLUMN IF NOT EXISTS severity    TEXT,
    ADD COLUMN IF NOT EXISTS score       INTEGER,
    ADD COLUMN IF NOT EXISTS categories  TEXT,
    ADD COLUMN IF NOT EXISTS message     TEXT,
    ADD COLUMN IF NOT EXISTS dup_fp      CHAR(64),
    ADD COLUMN IF NOT EXISTS sent        BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_ea_sev ON events_alert (severity);
CREATE INDEX IF NOT EXISTS idx_ea_dup ON events_alert (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ea_dup_not_null
  ON events_alert (dup_fp) WHERE dup_fp IS NOT NULL;

-- ========== soar_actions ==========
CREATE TABLE IF NOT EXISTS soar_actions (
    id         SERIAL PRIMARY KEY,
    event_id   INTEGER,
    "timestamp" TEXT,
    action     TEXT,
    target     TEXT,
    comment    TEXT,
    status     TEXT,
    expires_at TIMESTAMP NULL,
    resolved_at TIMESTAMP NULL,
    dup_fp     CHAR(64),
    sent       BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE soar_actions
    ADD COLUMN IF NOT EXISTS event_id    INTEGER,
    ADD COLUMN IF NOT EXISTS "timestamp" TEXT,
    ADD COLUMN IF NOT EXISTS action      TEXT,
    ADD COLUMN IF NOT EXISTS target      TEXT,
    ADD COLUMN IF NOT EXISTS comment     TEXT,
    ADD COLUMN IF NOT EXISTS status      TEXT,
    ADD COLUMN IF NOT EXISTS expires_at  TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS dup_fp      CHAR(64),
    ADD COLUMN IF NOT EXISTS sent        BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_soar_exp ON soar_actions (expires_at);
CREATE INDEX IF NOT EXISTS idx_soar_dup ON soar_actions (dup_fp);
CREATE UNIQUE INDEX IF NOT EXISTS uq_soar_dup_not_null
  ON soar_actions (dup_fp) WHERE dup_fp IS NOT NULL;

CREATE TABLE IF NOT EXISTS automations (
  id BIGSERIAL PRIMARY KEY,
  device TEXT NOT NULL,
  event_id BIGINT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  comment TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending','active','paused','completed','failed')),
  "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- YENİ EDR & ENVANTER TABLOLARI
-- =============================================================================

-- FIM Baselines & Changes
CREATE TABLE IF NOT EXISTS fim_data (
    id           SERIAL PRIMARY KEY,
    path         TEXT NOT NULL,
    hash_sha256  TEXT,
    status       TEXT, -- "baseline", "changed", "deleted", "new"
    last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_fim_path ON fim_data(path);

-- Windows Registry Monitoring
CREATE TABLE IF NOT EXISTS registry_logs (
    id           SERIAL PRIMARY KEY,
    hive         TEXT,
    key_path     TEXT,
    value_name   TEXT,
    value_data   TEXT,
    status       TEXT, -- "new", "changed", "deleted"
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);

-- Network Connections
CREATE TABLE IF NOT EXISTS network_connections (
    id           SERIAL PRIMARY KEY,
    pid          INTEGER,
    process_name TEXT,
    local_addr   TEXT,
    local_port   INTEGER,
    remote_addr  TEXT,
    remote_port  INTEGER,
    state        TEXT,
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);

-- Process Tree & Anomaly
CREATE TABLE IF NOT EXISTS process_events (
    id           SERIAL PRIMARY KEY,
    pid          INTEGER,
    ppid         INTEGER,
    name         TEXT,
    cmdline      TEXT,
    username     TEXT,
    status       TEXT, -- "started", "suspicious_child", "hidden"
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);

-- Hardware & USB Inventory
CREATE TABLE IF NOT EXISTS hardware_inventory (
    id           SERIAL PRIMARY KEY,
    type         TEXT, -- "usb", "pci", "disk"
    name         TEXT,
    vendor_id    TEXT,
    product_id   TEXT,
    serial_number TEXT,
    status       TEXT, -- "connected", "disconnected"
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);

-- AD Audit & Misconfigurations
CREATE TABLE IF NOT EXISTS security_audit (
    id           SERIAL PRIMARY KEY,
    category     TEXT, -- "AD", "User", "Service"
    finding      TEXT,
    severity     TEXT,
    details      TEXT,
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);

-- ========== network_inventory ==========
CREATE TABLE IF NOT EXISTS network_inventory (
    id             SERIAL PRIMARY KEY,
    protocol       TEXT,
    local_address  TEXT,
    local_port     INTEGER,
    remote_address TEXT,
    state          TEXT,
    process_name   TEXT,
    pid            INTEGER,
    "timestamp"    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent           BOOLEAN DEFAULT FALSE,
    dup_fp         CHAR(64)
);

-- ========== software_inventory ==========
CREATE TABLE IF NOT EXISTS software_inventory (
    id           SERIAL PRIMARY KEY,
    name         TEXT,
    version      TEXT,
    vendor       TEXT,
    install_date TEXT,
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);

-- ========== docker_containers ==========
CREATE TABLE IF NOT EXISTS docker_containers (
    id           SERIAL PRIMARY KEY,
    container_id TEXT,
    name         TEXT,
    image        TEXT,
    status       TEXT,
    state        TEXT,
    created_at   TEXT,
    "timestamp"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         BOOLEAN DEFAULT FALSE,
    dup_fp       CHAR(64)
);
