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


def _split_statements(sql: str) -> list[str]:
    """Split a schema file into executable statements, dropping comments.

    The naive version of this was `if stmt.startswith("--"): continue`, meant
    to skip chunks that are only a comment. Splitting on `;` puts a
    statement's *leading* comment in the same chunk as the statement, so any
    statement documented with a comment above it began with `--` and was
    discarded along with its comment.

    That silently skipped 19 of the 52 statements in the agent schema -
    siem_events, events_alert, soar_actions, fim_data, network_connections
    and docker_containers among them - while reporting "33 statements, 0
    skipped", because the 19 were never counted as statements at all. It
    only escaped notice because those tables already existed from the
    initdb run that happens on a fresh data directory.

    Comment lines are stripped instead, and what remains decides whether
    there is a statement to run.

    The second version of that had its own trap: it stripped comment *lines*
    after splitting on `;`, so a semicolon *inside* a comment cut the
    statement it belonged to -

        agent_name VARCHAR(255) NULL,  -- NULL means global; a value scopes …

    That line is in the server's schema, where it left
    `soar_notification_templates` uncreated and produced two syntax errors on
    every ingest, one of them the comment text itself. No comment in *this*
    schema happens to contain a semicolon, so the identical trap sat here
    unsprung - which is the only reason to fix it in both places rather than
    just where it went off. Comments now go first, and the split sees only SQL.
    """
    return [chunk.strip() for chunk in _strip_comments(sql).split(";")
            if chunk.strip()]


def _strip_comments(sql: str) -> str:
    """Remove `--` comments, leaving string literals alone.

    Duplicated from `server._strip_sql_comments`: the agent ships standalone
    and cannot import from the server. `tests/test_agent_schema_migration.py`
    keeps the two honest.
    """
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(sql):
        ch = sql[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(sql):
                out.append(sql[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "-" and sql.startswith("--", i):
            newline = sql.find("\n", i)
            if newline == -1:
                break
            i = newline
            continue
        out.append(ch)
        i += 1
    return "".join(out)


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
        for statement in _split_statements(sql):
            stmt = statement
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

def reoffer_recent(table: str, limit: int) -> int:
    """Mark the newest `limit` rows unsent again, and say how many.

    For one situation: the server's database for this agent has been recreated
    and no longer holds what `sent` claims it does. `sent` is the agent's
    private record of the server's contents, so a server-side reset is
    invisible from here - and a row marked sent is never offered again. Tables
    that produce rows constantly refill on their own, so the damage lands
    entirely on the quiet ones: a host sat holding 93 port-scan rows against a
    server holding none, with nothing wrong at either end.

    Bounded, and that bound is the point. `hardware_inventory` on one host
    holds 530,000 rows; re-offering all of them at fifty per batch is a replay
    measured in days, during which nothing current gets through. The newest
    rows are the ones worth having back, and the tables this actually rescues
    are small enough to be covered completely.

    The resend is safe because the server deduplicates: rows it already holds
    are recognised and skipped rather than stored twice.
    """
    from modules import enc_db

    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT %s",
                        (limit,))
            candidates = cur.fetchall()

        # Skip what this agent can no longer read itself.
        #
        # The Fernet key comes from the server's bootstrap and there is no
        # rotation path, so an agent that has outlived one key holds rows it
        # cannot decrypt - and neither can the server. Offering them again
        # imports rows that render as `<decryption failed - key mismatch>` for
        # ever, spending a bounded recovery budget on data nobody can read.
        #
        # Found by doing it: the first re-offer on a live host moved about two
        # thousand such rows onto the server, and the readable/unreadable
        # boundary in the result was exact.
        keep = []
        for row in candidates:
            try:
                if enc_db.is_readable(table, dict(row)):
                    keep.append(row["id"])
            except Exception:
                # No key configured yet, or a shape this does not understand.
                # Offering it is the older behaviour and the safer default:
                # the cost is an unreadable row, not a lost one.
                keep.append(row["id"])

        if not keep:
            return 0
        with conn.cursor() as cur:
            cur.execute(f"UPDATE {table} SET sent = FALSE WHERE id = ANY(%s)",
                        (keep,))
            changed = cur.rowcount
        conn.commit()
    return changed if changed and changed > 0 else 0


def prune_sent(table: str, keep: int) -> int:
    """Drop rows the server already has, beyond the newest `keep`.

    Nothing pruned this table before, and the agent is append-only, so the
    local database grew for the life of the install. On one host after a few
    weeks: 530,428 rows of `hardware_inventory`, 225,145 of
    `network_connections`, 88,201 of `fim_data` - every one of them marked
    sent, none of them ever read again. That is disk on a monitored endpoint,
    which is the one place a monitoring tool has no business consuming.

    It also constrains recovery. `reoffer_recent` has to be bounded because
    replaying half a million rows at fifty a batch takes days, so the backlog
    was actively limiting how much could be rescued after a server reset.

    Two rules, and both matter:

    Only `sent` rows. An unsent row has not reached the server, and deleting
    it is the data loss this whole module has spent the day preventing.

    Always keep the newest `keep`, which is set comfortably above
    `_REOFFER_LIMIT` so a server-side reset still has rows to offer again.

    The delete is bounded by a threshold id rather than `NOT IN (...)`: one
    index lookup and a range scan instead of a comparison against a five
    thousand row list, on a table that may hold half a million.
    """
    query = (
        f"DELETE FROM {table} WHERE sent = TRUE AND id < "
        f"(SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET %s)"
    )
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Fewer rows than `keep` means the subquery is NULL, `id < NULL`
            # is NULL, and nothing is deleted - which is the right answer.
            cur.execute(query, (keep,))
            removed = cur.rowcount
        conn.commit()
    return removed if removed and removed > 0 else 0


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
