SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- Ortak yardımcı tablolar
CREATE TABLE IF NOT EXISTS agent_info (
  id INT AUTO_INCREMENT PRIMARY KEY,
  agent_name  VARCHAR(255) NOT NULL,
  hostname    VARCHAR(255),
  mac_address VARCHAR(48),
  public_ip   VARCHAR(45),
  os_info     VARCHAR(255),
  last_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_agent (agent_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ingest_fingerprint (
  table_name VARCHAR(64) NOT NULL,
  fp         CHAR(64)    NOT NULL,
  first_seen TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (table_name, fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== critical_files ==================
CREATE TABLE IF NOT EXISTS critical_files (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  path         TEXT,
  owner        TEXT,
  grp          TEXT,
  permissions  TEXT,
  last_opened  TEXT,
  collected_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  sent         TINYINT(1) NOT NULL DEFAULT 0,
  dup_fp       CHAR(64) NULL,
  KEY idx_cf_path (path(191)),
  KEY idx_cf_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== disk_usage (snapshot) ==================
CREATE TABLE IF NOT EXISTS disk_usage (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  device     TEXT,
  mountpoint TEXT,
  total_gb   DOUBLE,
  used_gb    DOUBLE,
  free_gb    DOUBLE,
  percent    DOUBLE,
  `timestamp` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  sent       TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== portscan_result ==================
-- Superset: product/version VEYA state/banner/target_ip ikisini de destekle
CREATE TABLE IF NOT EXISTS portscan_result (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  target_ip  VARCHAR(45) NULL,
  port       INT NULL,
  protocol   VARCHAR(16) NULL,
  state      VARCHAR(16) NULL,
  service    VARCHAR(64) NULL,
  product    VARCHAR(128) NULL,
  `version`  VARCHAR(128) NULL,
  banner     TEXT NULL,
  scanned_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  sent       TINYINT(1) NOT NULL DEFAULT 0,
  dup_fp     CHAR(64) NULL,
  KEY idx_ps_ip (target_ip),
  KEY idx_ps_port (port),
  KEY idx_ps_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ================== resource_usage (snapshot) ==================
CREATE TABLE IF NOT EXISTS resource_usage (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  cpu_percent    DOUBLE,
  mem_total      BIGINT,
  mem_available  BIGINT,
  mem_used       BIGINT,
  mem_percent    DOUBLE,
  `timestamp`    TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  sent           TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== packages ==================
CREATE TABLE IF NOT EXISTS packages (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  package    TEXT,
  `version`  TEXT,
  sent       TINYINT(1) NOT NULL DEFAULT 0,
  dup_fp     CHAR(64) NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_pkg_name (package(191)),
  KEY idx_pkg_dup  (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== vulnerabilities_report ==================
CREATE TABLE IF NOT EXISTS vulnerabilities_report (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  package_name     TEXT NULL,
  package_version  TEXT NULL,
  vulnerability_id TEXT NULL,
  summary          TEXT NULL,
  details_url      TEXT NULL,
  dup_fp           CHAR(64) NULL,
  sent             TINYINT(1) NOT NULL DEFAULT 0,
  created_at       TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_vr_vuln (vulnerability_id(32)),
  KEY idx_vr_pkg  (package_name(191)),
  KEY idx_vr_dup  (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== siem_events ==================
-- Agent JSON: source + severity + timestamp + message + dup_fp + sent
--
-- `severity` did not exist and `source` was never written: the agent put the
-- whole enriched event into `message` as JSON and left the columns NULL. That
-- is why alerts rendered "Source: Unknown", why idx_siem_src matched nothing,
-- and why the server-side severity gate found no severity to compare and so
-- analysed every event. The JSON body still carries both, unchanged.
CREATE TABLE IF NOT EXISTS siem_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  source         TEXT NULL,
  severity       VARCHAR(16) NULL,
  `timestamp`    TEXT NULL,
  message        TEXT NULL,
  sent           TINYINT(1) NOT NULL DEFAULT 0,
  ai_analyzed    TINYINT(1) NOT NULL DEFAULT 0,
  ai_analyzed_at TIMESTAMP NULL,
  dup_fp         CHAR(64) NULL,
  -- MITRE ATT&CK technique IDs from the Sigma rules that matched, comma
  -- separated. A column rather than a field inside the JSON body, because
  -- coverage is a question asked across every event - "which techniques have
  -- we ever seen" - and that cannot be answered by parsing a text column.
  techniques     VARCHAR(255) NULL,
  created_at     TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_siem_src (source(64)),
  KEY idx_siem_tech (techniques),
  KEY idx_siem_sev (severity),
  KEY idx_siem_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Existing deployments: the table above is only created once, so the column
-- has to be added separately. Errors here are printed and skipped by
-- create_tables_if_not_exist when it already exists.
ALTER TABLE siem_events ADD COLUMN severity VARCHAR(16) NULL;
ALTER TABLE siem_events ADD KEY idx_siem_sev (severity);
ALTER TABLE siem_events ADD COLUMN techniques VARCHAR(255) NULL;
ALTER TABLE siem_events ADD KEY idx_siem_tech (techniques);

-- ================== ai_log_checker_results (opsiyonel AI) ==================
CREATE TABLE IF NOT EXISTS ai_log_checker_results (
  id INT AUTO_INCREMENT PRIMARY KEY,
  `timestamp` VARCHAR(50) NOT NULL,
  source_file VARCHAR(100) NOT NULL,
  critical_summary TEXT,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== events_alert ==================
CREATE TABLE IF NOT EXISTS events_alert (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  source      TEXT,
  `timestamp` TEXT,
  severity    TEXT,
  score       INT,
  categories  TEXT,
  message     TEXT,
  sent        TINYINT(1) NOT NULL DEFAULT 0,
  dup_fp      CHAR(64) NULL,
  created_at  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_ea_sev (severity(16)),
  KEY idx_ea_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== soar_actions ==================
-- TIMESTAMP şart: expires filtreleri tarih karşılaştırması yapıyor
CREATE TABLE IF NOT EXISTS soar_actions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_id    BIGINT NULL,
  `timestamp` TEXT NULL,
  action      TEXT NULL,
  target      TEXT NULL,
  comment     TEXT NULL,
  status      TEXT NULL,
  expires_at  TIMESTAMP NULL,
  resolved_at TIMESTAMP NULL,
  sent        TINYINT(1) NOT NULL DEFAULT 0,
  dup_fp      CHAR(64) NULL,
  created_at  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_soar_exp (expires_at),
  KEY idx_soar_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- tip düzelt (idempotent)
ALTER TABLE soar_actions
  MODIFY COLUMN expires_at  TIMESTAMP NULL,
  MODIFY COLUMN resolved_at TIMESTAMP NULL;


-- ================== automations ==================
CREATE TABLE IF NOT EXISTS automations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  device VARCHAR(255) NOT NULL,
  event_id BIGINT NOT NULL,
  action VARCHAR(64) NOT NULL,
  target VARCHAR(255) NOT NULL,
  comment TEXT NULL,
  -- 'cancelled' is distinct from 'failed': the action did not run because we
  -- stopped it, not because it went wrong. Without it, cancelling a runaway
  -- dispatch had to be recorded as 'failed' with the real reason buried in a
  -- comment prefix, which is not something a query can filter on.
  status ENUM('pending','active','paused','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  payload LONGTEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_device_status (device, status),
  KEY idx_device_event (device, event_id),
  KEY idx_timestamp (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The ALTER that widens this ENUM on existing deployments is NOT here. It
-- lives in server.py:_migrate_automation_status, guarded by a check of
-- information_schema.
--
-- MODIFY is idempotent in the sense that re-running it leaves the same
-- definition, but it is not free: it takes a metadata lock every time, and
-- this whole file is executed on every call to create_tables_if_not_exist.
-- With one connection holding an open transaction on `automations`, the
-- repeated ALTER queued behind it - and in MySQL a *waiting* DDL blocks the
-- readers that arrive after it. Agents polling /automations/pending stopped
-- getting answers and saw 500s at the response timeout instead.

-- ================== playbooks (merkezi tanım) ==================
CREATE TABLE IF NOT EXISTS playbooks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  agent_name   VARCHAR(255) NOT NULL,
  name         VARCHAR(255) NOT NULL,
  nodes        LONGTEXT     NOT NULL,  
  connections  LONGTEXT     NOT NULL,  
  created_by   BIGINT NULL,            
  updated_by   BIGINT NULL,            
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_agent_playbook (agent_name, name),
  KEY idx_pb_agent (agent_name),
  KEY idx_pb_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS soar_playbooks (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  agent_name       VARCHAR(255) NOT NULL,      -- UI'deki `device` paramı
  name             VARCHAR(255) NOT NULL,
  description      TEXT NULL,
  nodes_json       JSON NOT NULL,
  connections_json JSON NOT NULL,
  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_agent_playbook2 (agent_name, name),
  KEY idx_sp_agent (agent_name),
  KEY idx_sp_active (is_active),
  KEY idx_sp_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS soar_notification_templates (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  agent_name  VARCHAR(255) NULL,         -- null ise global, doluysa belirli device'a özel
  name        VARCHAR(150) NOT NULL,
  type        VARCHAR(32) NOT NULL DEFAULT 'email',  -- email/sms/slack/teams vs
  subject     VARCHAR(255) NOT NULL,
  body        TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_template_name (agent_name, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ================== playbook_runs (çalıştırma günlükleri) ==================
CREATE TABLE IF NOT EXISTS playbook_runs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  agent_name    VARCHAR(255) NOT NULL,
  playbook_name VARCHAR(255) NOT NULL,
  status ENUM('running','success','failed','cancelled') NOT NULL DEFAULT 'running',
  started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TIMESTAMP NULL,
  timeline   LONGTEXT NULL,   
  last_error TEXT NULL,
  KEY idx_runs_agent_started (agent_name, started_at),
  KEY idx_runs_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== FIM & Inventory & Threat Intel ==================

CREATE TABLE IF NOT EXISTS fim_data (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    path         TEXT NOT NULL,
    hash_sha256  TEXT,
    status       VARCHAR(32), -- "baseline", "changed", "deleted", "new"
    last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         TINYINT(1) DEFAULT 0,
    dup_fp       CHAR(64) NULL,
    KEY idx_fim_path (path(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS hardware_inventory (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    type         VARCHAR(64), -- "cpu", "disk", "usb"
    name         VARCHAR(255),
    vendor_id    VARCHAR(128),
    product_id   VARCHAR(128),
    serial_number VARCHAR(128),
    status       VARCHAR(32),
    `timestamp`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         TINYINT(1) DEFAULT 0,
    dup_fp       CHAR(64) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS threat_intel (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    type        VARCHAR(32), -- "ip", "domain", "hash"
    value       VARCHAR(255) NOT NULL,
    source      VARCHAR(128),
    severity    VARCHAR(16),
    description TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_intel (type, value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== docker_containers ==================
CREATE TABLE IF NOT EXISTS docker_containers (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    container_id VARCHAR(128) NOT NULL,
    name         VARCHAR(255),
    image        VARCHAR(255),
    status       VARCHAR(64),
    state        VARCHAR(64),
    created_at   TEXT,
    `timestamp`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         TINYINT(1) DEFAULT 0,
    dup_fp       CHAR(64) NULL,
    UNIQUE KEY uniq_container (container_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS software_inventory (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    version      VARCHAR(100),
    vendor       VARCHAR(255),
    install_date VARCHAR(50),
    `timestamp`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         TINYINT(1) DEFAULT 0,
    dup_fp       CHAR(64) NULL,
    KEY idx_sw_name (name(191)),
    KEY idx_sw_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS network_inventory (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    protocol       VARCHAR(16),
    local_address  VARCHAR(45),
    local_port     INT,
    remote_address VARCHAR(45),
    remote_port    INT,
    state          VARCHAR(32),
    process_name   VARCHAR(255),
    pid            INT,
    `timestamp`    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent           TINYINT(1) DEFAULT 0,
    dup_fp         CHAR(64) NULL,
    KEY idx_net_port (local_port),
    KEY idx_net_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ================== network_connections (live snapshot from agent) ==================
CREATE TABLE IF NOT EXISTS network_connections (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    pid          INT,
    process_name VARCHAR(255),
    local_addr   VARCHAR(64),
    local_port   INT,
    remote_addr  VARCHAR(64),
    remote_port  INT,
    state        VARCHAR(32),
    `timestamp`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent         TINYINT(1) DEFAULT 0,
    dup_fp       CHAR(64) NULL,
    KEY idx_nc_port (local_port),
    KEY idx_nc_dup (dup_fp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
