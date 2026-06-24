import os
import psycopg2
from psycopg2.extras import DictCursor

DB_NAME = os.getenv('DB_NAME', 'sentora')
DB_USER = os.getenv('DB_USER', 'sentorauser')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'sentorapass')
DB_HOST = "127.0.0.1"
DB_PORT = int(os.getenv('DB_PORT', '5432'))


def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
    )


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
