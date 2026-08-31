"""Schema that the server creates for itself at boot.

Five idempotent migrations that ran on every start and lived in the middle of
app.py, between the request helpers and the route handlers. They are DDL, they
share one dependency, and nothing about them is web-facing.

They stay idempotent on purpose: `setup_hub` calls all five on every start, so
each has to be safe to re-run against a database that already has the table.
`init_password_policy` is the one to read first if you want the pattern - it
checks information_schema before altering, because an unconditional ALTER
takes a metadata lock on a table the whole platform reads, and a lock taken on
every boot is a lock taken while something else is mid-transaction.

`conn_factory` is passed in rather than imported. It keeps this module out of
app.py's import cycle, and it means the migrations can be run against a
throwaway database in a test without starting a server.
"""

from __future__ import annotations

import asyncio
import time

import mysql.connector

from security import session as session_store

# The bcrypt hash db/init_userdb.sql seeds `admin` with. It is published in
# this repository, so it is a placeholder rather than a secret - which is
# exactly why an account still carrying it must set a real one.
SEEDED_ADMIN_HASH = "$2b$12$YrcCyrQMGN16pntv7BfpWuayUJ2Kg7Dpr4XsYOSa4JXLDEMDzkNW."

DEFAULT_ALERT_TEMPLATE = None      # injected by app.py; see set_defaults()
sync_mysql_conn = None


def set_defaults(*, conn_factory, alert_template):
    """Wire the two things these migrations need from the application."""
    global sync_mysql_conn, DEFAULT_ALERT_TEMPLATE
    sync_mysql_conn = conn_factory
    DEFAULT_ALERT_TEMPLATE = alert_template


DB_WAIT_S = 60

#: Tables the platform cannot serve a single request without. Checked after
#: the migrations, because "every migration reported an error" and "the
#: database is fine" look identical from here otherwise.
REQUIRED_TABLES = ("users", "sessions")


async def _wait_for_database(timeout: float = DB_WAIT_S) -> bool:
    """Block until userdb answers, or give up and say so.

    These migrations run from `main_process_start`, which fires before any
    worker exists and long before the connection pool is built. Under compose
    the database container starts alongside the app, so they raced it - all
    five failed, each printed its own line, and the server started anyway.
    """
    deadline = time.monotonic() + timeout
    delay, last = 1.0, None
    while True:
        try:
            with sync_mysql_conn("userdb") as conn:
                conn.cursor().close()
            return True
        except Exception as e:
            last = e
            if time.monotonic() >= deadline:
                print(f"[Schema] Database unreachable after {timeout:.0f}s: "
                      f"{last}. Migrations will not run, and this server will "
                      f"answer every login with an authentication failure.",
                      flush=True)
                return False
            await asyncio.sleep(delay)
            delay = min(delay * 2, 8.0)


async def run_all():
    """Every migration, in the order app.py ran them.

    Waits for the database first, and checks afterwards that the tables it was
    supposed to create are there.

    The check is not belt and braces. Each migration below catches its own
    exceptions - correctly, because one failing must not stop the rest - and
    the result was that a database that was simply not up yet produced five
    tidy error lines and a server that started. `sessions` was never created,
    so every login authenticated correctly and then failed to issue a session,
    which the login handler read as "not a local user" and answered 401. A
    correct password, told it was wrong, because of a table.
    """
    if not await _wait_for_database():
        return

    await init_hub_db()
    await init_enrollment_tables()
    await init_password_policy()
    await init_session_table()
    await init_email_templates_table()

    missing = _missing_required_tables()
    if missing:
        print(f"[Schema] FATAL: {', '.join(missing)} missing after migration. "
              f"Logins will fail as though the password were wrong. The "
              f"errors above say why.", flush=True)


def _missing_required_tables() -> list[str]:
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = DATABASE()")
                present = {str(r[0]).lower() for r in cur.fetchall()}
            finally:
                cur.close()
        return [t for t in REQUIRED_TABLES if t not in present]
    except Exception as e:
        print(f"[Schema] could not verify the schema: {e}", flush=True)
        return []


async def init_hub_db():
    """
    Ensures that the sentora_hub database and its global tables exist.
    """
    try:
        with sync_mysql_conn() as conn:
            cur = conn.cursor()
            try:
                cur.execute("CREATE DATABASE IF NOT EXISTS sentora_hub")
                cur.execute("USE sentora_hub")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS hardware_inventory (
                        id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        type         VARCHAR(64),
                        name         VARCHAR(255),
                        vendor_id    VARCHAR(128),
                        product_id   VARCHAR(128),
                        serial_number VARCHAR(128),
                        status       VARCHAR(32),
                        `timestamp`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        sent         TINYINT(1) DEFAULT 0,
                        dup_fp       CHAR(64) NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intel (
                        id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        type        VARCHAR(32),
                        value       VARCHAR(255) NOT NULL,
                        source      VARCHAR(128),
                        severity    VARCHAR(16),
                        description TEXT,
                        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE KEY uniq_intel (type, value),
                        INDEX idx_intel_value (value),
                        INDEX idx_intel_seen (last_seen)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                # `last_seen` drives staleness pruning and the freshness
                # readout. It was added by the feed refresher's own ALTER,
                # which only ran once a feed had actually returned something —
                # so on a deployment whose feeds were failing, the column did
                # not exist and anything querying it broke.
                for ddl in (
                    "ALTER TABLE threat_intel ADD COLUMN last_seen TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP",
                    "ALTER TABLE threat_intel ADD INDEX idx_intel_value (value)",
                    "ALTER TABLE threat_intel ADD INDEX idx_intel_seen (last_seen)",
                ):
                    try:
                        cur.execute(ddl)
                    except mysql.connector.Error as e:
                        # 1060 duplicate column, 1061 duplicate key: the
                        # migration has already run, which is the normal case.
                        # Anything else - a lock timeout, a missing table, a
                        # syntax error - meant the column silently never
                        # appeared and every query against it failed later,
                        # far from here.
                        if e.errno not in (1060, 1061):
                            print(f"[HubDB] migration failed: {ddl[:60]}... -> {e}",
                                  flush=True)

                conn.commit()
            finally:
                cur.close()
        print("[HubDB] Central database 'sentora_hub' initialized successfully.")
    except Exception as e:
        print(f"[HubDB] Error initializing central database: {e}")

async def init_enrollment_tables():
    """Ensure enrollment_tokens + agent_identities exist in userdb (idempotent migration)."""
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute("""
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
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                cur.execute("""
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
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)

                # `CREATE TABLE IF NOT EXISTS` leaves an existing table alone,
                # so without this the column only appears on installations
                # made after today. Guarded by information_schema rather than
                # a swallowed exception: a DDL that fails for some other
                # reason should be visible, not indistinguishable from
                # "already applied".
                cur.execute("""
                    SELECT column_name FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'agent_identities'
                """)
                present = {str(r[0]).lower() for r in cur.fetchall()}
                pending = [ddl for column, ddl in (
                    ("display_name",
                     "ADD COLUMN display_name VARCHAR(128) NULL AFTER agent_name"),
                    # What the agent reported on its last handshake. NULL means
                    # it sent no version header, which is itself the answer:
                    # it predates version reporting.
                    ("agent_version",
                     "ADD COLUMN agent_version VARCHAR(48) NULL"),
                ) if column not in present]
                if pending:
                    cur.execute("SET SESSION lock_wait_timeout = 3")
                    cur.execute(f"ALTER TABLE agent_identities {', '.join(pending)}")
                    print(f"[Enrollment] agent_identities gained "
                          f"{len(pending)} column(s).")

                conn.commit()
            finally:
                cur.close()
        print("[Enrollment] Tables ready in userdb.")
    except Exception as e:
        print(f"[Enrollment] Error initializing tables: {e}")

async def init_email_templates_table():
    """Ensure `email_templates` exists in userdb (idempotent migration).

    `send_email` and `/<agent>/notifications/templates` both query this table,
    but init_userdb.sql never created it — so every templated alert mail failed
    at the SELECT and the notifications endpoint returned a 500. Columns match
    what send_email reads: template_name, subject_template, body_template.
    """
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS email_templates (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        template_name VARCHAR(255) NOT NULL UNIQUE,
                        subject_template TEXT NOT NULL,
                        body_template TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                # `dispatch_critical_alerts` looks up a per-agent template name
                # ("Critical Alerts - Agent: WIN-01"), so without this generic
                # fallback an operator would have to create one row per
                # enrolled endpoint before any alert mail went out — with a log
                # line as the only symptom of not having done so.
                cur.execute("""
                    INSERT IGNORE INTO email_templates
                        (template_name, subject_template, body_template)
                    VALUES (%s, %s, %s)
                """, (
                    DEFAULT_ALERT_TEMPLATE,
                    "[Sentora] Critical alerts on {{agent}}",
                    "Agent: {{agent}}\n\n{{body}}\n\n-- Sentora",
                ))
                conn.commit()
            finally:
                cur.close()
        print("[Email] Templates table ready in userdb.")
    except Exception as e:
        print(f"[Email] Error initializing templates table: {e}")


async def init_session_table():
    """Ensure the `sessions` table exists in userdb (idempotent migration)."""
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute(session_store.CREATE_TABLE_SQL)
                conn.commit()
            finally:
                cur.close()
        print("[Session] Table ready in userdb.")
    except Exception as e:
        print(f"[Session] Error initializing table: {e}")


async def init_password_policy():
    """Add `users.must_change_password`, and set it on the seeded admin.

    `db/init_userdb.sql` seeds `admin` with a fixed bcrypt hash, so every
    deployment of this project ships with the same known password and nothing
    ever required it to be changed. A console that manages endpoint isolation
    and command execution was reachable with a credential published in the
    repository.

    Guarded by information_schema rather than an unconditional ALTER: this
    runs on every start, and an ALTER that takes a metadata lock each time is
    how the automations table blocked every reader once already.
    """
    try:
        with sync_mysql_conn("userdb") as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT COUNT(*) FROM information_schema.columns "
                    "WHERE table_schema='userdb' AND table_name='users' "
                    "AND column_name='must_change_password'"
                )
                if cur.fetchone()[0]:
                    return
                cur.execute("SET SESSION lock_wait_timeout = 3")
                cur.execute(
                    "ALTER TABLE users ADD COLUMN must_change_password "
                    "TINYINT(1) NOT NULL DEFAULT 0"
                )
                # Only an account whose password is still the one published
                # in db/init_userdb.sql.
                #
                # The first version of this matched on username and
                # created_by, which flags the seeded admin whether or not the
                # password was ever changed. On a running deployment that is
                # not a policy, it is a lockout: every request except
                # /change-password starts returning 403 to somebody who had
                # already set a password months ago.
                #
                # Comparing the hash is exact. bcrypt embeds its own salt, so
                # this literal only matches an account still using the shipped
                # credential.
                cur.execute(
                    "UPDATE users SET must_change_password = 1 "
                    "WHERE username = 'admin' AND created_by = 'system' "
                    "AND password = %s",
                    (SEEDED_ADMIN_HASH,)
                )
                conn.commit()
                print("[Auth] users.must_change_password added; the seeded "
                      "admin must set a password before doing anything else.")
            finally:
                cur.close()
    except Exception as e:
        print(f"[Auth] Could not apply the password policy migration: {e}")
