CREATE DATABASE IF NOT EXISTS userdb;
USE userdb;

CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO roles (role_name, created_by) VALUES ('admin', 'system');
  

UPDATE roles SET updated_by = created_by WHERE updated_by IS NULL;

CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    -- The seeded admin below carries a password hash that is published in
    -- this repository. Until it is changed, that session may do nothing
    -- except change it. See app.py:init_password_policy for the migration
    -- that adds this to deployments created before the column existed.
    must_change_password TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


INSERT INTO users (username, password, role, created_by, must_change_password)
VALUES ('admin', '$2b$12$YrcCyrQMGN16pntv7BfpWuayUJ2Kg7Dpr4XsYOSa4JXLDEMDzkNW.', 'admin', 'system', 1);




CREATE TABLE email_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    smtp_server VARCHAR(255) NOT NULL,
    smtp_port INT NOT NULL,
    smtp_user VARCHAR(255),
    smtp_password VARCHAR(255),
    smtp_use_tls BOOLEAN DEFAULT FALSE,
    email_from VARCHAR(255) NOT NULL,
    email_to VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Read by send_email() and /<agent>/notifications/templates. Was missing
-- entirely, so templated alert mail failed at the SELECT.
CREATE TABLE IF NOT EXISTS email_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    template_name VARCHAR(255) NOT NULL UNIQUE,
    subject_template TEXT NOT NULL,
    body_template TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- dispatch_critical_alerts() looks up a per-agent template name
-- ("Critical Alerts - Agent: WIN-01"). This generic row is the fallback
-- send_email() uses when no agent-specific template has been created, so
-- alert mail works out of the box instead of failing with a log line.
INSERT IGNORE INTO email_templates (template_name, subject_template, body_template)
VALUES ('Critical Alerts (default)',
        '[Sentora] Critical alerts on {{agent}}',
        'Agent: {{agent}}\n\n{{body}}\n\n-- Sentora');

CREATE TABLE ai_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL UNIQUE,
    api_key VARCHAR(500) NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE role_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE(role_id, permission_id)
);


INSERT INTO permissions (name, description) VALUES
('manage_db', 'Manage DB permission'),
('user_create', 'New User Create permission'),
('role_create', 'New Role Create permission'),
('manage_users','Manage Users'),
('manage_agent', 'Manage Agent Operation permissions '),
('clear_logs', 'Deleting Logs permission'),
('analyze_logs', 'Analyze Logs with AI permission'),
('all_permission','All permission.'),
('set_email_config', 'Mail Config Setup permission'),
('read_telemetry', 'View agents, alerts and logs'),
('manage_soar', 'Manage SOAR automations and playbooks'),
('manage_system', 'Manage LDAP, AI and System settings');


INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.role_name = 'admin' AND p.name IN (
  'all_permission', 'manage_db', 'user_create', 'role_create', 
  'manage_users', 'manage_agent', 'clear_logs', 'analyze_logs', 
  'set_email_config', 'read_telemetry', 'manage_soar', 'manage_system'
);


CREATE TABLE IF NOT EXISTS ldap_conf (
  id TINYINT NOT NULL DEFAULT 1, 
  ldap_host VARCHAR(255) NOT NULL,
  ldap_port INT DEFAULT 389,
  bind_dn TEXT NOT NULL,
  bind_password TEXT NOT NULL,
  users_base TEXT NOT NULL,
  group_base TEXT NOT NULL,
  login_filter TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)    
);



CREATE TABLE login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    auth_type ENUM('ldap', 'local'),
    status ENUM('success', 'failure'),
    reason TEXT,
    ip_address VARCHAR(45),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);



CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    username VARCHAR(100),
    action VARCHAR(100),
    resource VARCHAR(255),
    details TEXT,
    ip_address VARCHAR(45),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token CHAR(64) NOT NULL UNIQUE,
    created_by_user_id INT,
    created_by_username VARCHAR(100),
    hostname_hint VARCHAR(255),
    note VARCHAR(500),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    used_by_agent VARCHAR(128) NULL,
    used_from_ip VARCHAR(45) NULL,
    INDEX idx_expires (expires_at),
    INDEX idx_used (used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS agent_identities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_name VARCHAR(128) NOT NULL UNIQUE,
    agent_key CHAR(64) NOT NULL UNIQUE,
    os_type VARCHAR(32),
    hostname VARCHAR(255),
    enrolled_from_ip VARCHAR(45),
    enrolled_via_token CHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NULL,
    revoked_at DATETIME NULL,
    INDEX idx_agent_name (agent_name),
    INDEX idx_revoked (revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

 


