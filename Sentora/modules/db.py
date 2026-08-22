import os
import psycopg2
from psycopg2.extras import DictCursor

DB_NAME = os.getenv('DB_NAME', 'sentora')
DB_USER = os.getenv('DB_USER', 'sentorauser')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'sentorapass')
DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_PORT = int(os.getenv('DB_PORT', '5432'))


def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
    )


def _schema_path():
    """db/init.sql, whether running from source or from the PyInstaller bundle."""
    import sys
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, "db", "init.sql")
    return os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "db", "init.sql")
    )


def apply_schema(verbose: bool = True) -> tuple[int, int]:
    """Bring the local database up to the shipped schema. Returns (ok, skipped).

    The agent had no migration path at all. Its postgres mounts db/init.sql
    into docker-entrypoint-initdb.d, which postgres runs *only* when the data
    directory is empty - so on any machine where the agent had run before, a
    new column simply never appeared. The agent then failed every insert with

        column "severity" of relation "siem_events" does not exist

    into its own log, where nothing on the server could see it. Telemetry
    stopped and the platform reported the agent as healthy.

    init.sql is written to be re-runnable (CREATE TABLE IF NOT EXISTS, ADD
    COLUMN IF NOT EXISTS), so applying it on every start is safe. Statements
    that fail are counted rather than raised: a schema the agent cannot fully
    apply must not stop it from collecting what it can.
    """
    path = _schema_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            sql = fh.read()
    except OSError as e:
        if verbose:
            print(f"[!] Agent schema {path} unreadable ({e}); "
                  f"columns added in a later release will be missing.", flush=True)
        return 0, 0

    ok = skipped = 0
    reasons: dict[str, int] = {}
    conn = get_conn()
    try:
        # Set once, before anything executes. Postgres aborts the whole
        # transaction on any error, so each statement needs to stand alone -
        # but psycopg2 refuses to switch autocommit once a transaction is
        # open, so doing this inside the loop failed on every statement after
        # the first and reported them all as "skipped".
        conn.autocommit = True
        for statement in sql.split(";"):
            stmt = statement.strip()
            if not stmt or stmt.startswith("--"):
                continue
            try:
                with conn.cursor() as cur:
                    cur.execute(stmt)
                ok += 1
            except psycopg2.Error as e:
                skipped += 1
                # Counting silently is how the previous version hid the fact
                # that it was failing on 32 of 33 statements while reporting
                # a successful migration.
                reasons[str(e).strip().splitlines()[0]] = \
                    reasons.get(str(e).strip().splitlines()[0], 0) + 1
    finally:
        conn.close()

    if verbose:
        print(f"[*] Agent schema applied: {ok} statement(s), {skipped} skipped.", flush=True)
        for msg, n in reasons.items():
            print(f"      [{n}x] {msg}", flush=True)
    return ok, skipped


def delete_all(table: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"DELETE FROM {table}")
        conn.commit()


def insert_record(table: str, data: dict):
    columns = ','.join(data.keys())
    placeholders = ','.join(['%s'] * len(data))
    values = list(data.values())
    query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, values)
        conn.commit()


def fetch_unsent(table: str, limit: int = 100):
    query = f"SELECT * FROM {table} WHERE sent = FALSE LIMIT %s"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(query, (limit,))
            rows = cur.fetchall()
    return rows


def mark_sent(table: str, ids: list):
    if not ids:
        return
    query = f"UPDATE {table} SET sent = TRUE WHERE id = ANY(%s)"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (ids,))
        conn.commit()

def fetch_one(table: str, where: str = "1=1", params: tuple = (), order_by: str = None):
    query = f"SELECT * FROM {table} WHERE {where}"
    if order_by:
        query += f" ORDER BY {order_by}"
    query += " LIMIT 1"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(query, params)
            row = cur.fetchone()
    return row


def fetch_recent(table: str, limit: int = 100):
    """Return the most recent rows from a table in descending order."""
    query = f"SELECT * FROM {table} ORDER BY id DESC LIMIT %s"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(query, (limit,))
            rows = cur.fetchall()
    return rows


def fetch_where(table: str, where: str = "1=1", params: tuple = (), order_by: str | None = None, limit: int | None = None):
    query = f"SELECT * FROM {table} WHERE {where}"
    if order_by:
        query += f" ORDER BY {order_by}"
    if limit is not None:
        query += " LIMIT %s"
        params = params + (limit,)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
    return rows


def update_record(table: str, data: dict, where: str, params: tuple = ()):
    sets = ','.join([f"{k}=%s" for k in data])
    values = list(data.values()) + list(params)
    query = f"UPDATE {table} SET {sets} WHERE {where}"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, values)
        conn.commit()
