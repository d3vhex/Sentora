"""The AI tables migrated themselves on every write.

`set_ai_cache` and `save_ai_results` each ran a block of unconditional ALTERs
before their INSERT - seventeen of them in the results case - every one of
which failed with a duplicate-column error on any database that had already
seen them, behind `except Exception: pass`.

The silence is what made it look free. It is not: MySQL takes a metadata lock
for an ALTER whether or not the statement changes anything, and a lock taken
at write frequency queues behind any open transaction on the table, at which
point it blocks every reader that arrives after it. That is the failure that
took `/automations/pending` down, and `db/init.sql` carried the same shape
until the guarded `_migrate_*` functions replaced it.

`_bring_table_up_to_date` asks information_schema first and issues one ALTER
containing only what is actually missing.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AI_UTILS = ROOT / "ai" / "utils.py"


def _load(name: str):
    """Compile one function out of ai/utils.py without importing it.

    Importing the module opens a database connection at call time and drags
    in the Ollama client; the migration helper is a pure function over a
    cursor.
    """
    tree = ast.parse(AI_UTILS.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns: dict = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(AI_UTILS), "exec"), ns)
    return ns[name]


class FakeCursor:
    """Answers the two information_schema queries and records what ran."""

    def __init__(self, columns: dict, indexes: list):
        self._columns = columns
        self._indexes = indexes
        self._rows: list = []
        self.executed: list[str] = []

    def execute(self, sql, params=()):
        self.executed.append(sql)
        if "information_schema.columns" in sql:
            self._rows = list(self._columns.items())
        elif "information_schema.statistics" in sql:
            self._rows = [(i,) for i in self._indexes]
        else:
            self._rows = []

    def fetchall(self):
        return self._rows

    @property
    def alters(self):
        return [s for s in self.executed if s.upper().startswith("ALTER TABLE")]


COLUMNS = (("verdict", "ADD COLUMN verdict VARCHAR(24) NULL"),
           ("payload", "ADD COLUMN payload JSON NULL"))
INDEXES = (("idx_air_fp", "ADD INDEX idx_air_fp (fingerprint)"),)
MODIFY = (("prompt_hash", "char(64)",
           "MODIFY COLUMN prompt_hash CHAR(64) NOT NULL"),)


def test_a_table_that_is_already_correct_is_never_touched():
    """The whole point. This ran on every cache write and every results write."""
    cur = FakeCursor({"verdict": "varchar(24)", "payload": "json"},
                     ["idx_air_fp"])
    _load("_bring_table_up_to_date")(
        cur, "ai_analysis_results", columns=COLUMNS, indexes=INDEXES)
    assert cur.alters == []


def test_only_what_is_missing_is_applied():
    cur = FakeCursor({"verdict": "varchar(24)"}, [])
    _load("_bring_table_up_to_date")(
        cur, "ai_analysis_results", columns=COLUMNS, indexes=INDEXES)
    assert len(cur.alters) == 1, "one ALTER, not one per change"
    alter = cur.alters[0]
    assert "ADD COLUMN payload" in alter
    assert "ADD INDEX idx_air_fp" in alter
    assert "verdict" not in alter, "a column that is already there was re-added"


def test_a_column_of_the_wrong_type_is_widened():
    """CHAR(32) was MD5. The key is SHA-256 with the prompt version appended,
    so on an older table every write truncated silently and the cache stopped
    matching anything it had stored."""
    cur = FakeCursor({"prompt_hash": "char(32)"}, [])
    _load("_bring_table_up_to_date")(cur, "ai_cache", modify=MODIFY)
    assert cur.alters and "MODIFY COLUMN prompt_hash CHAR(64)" in cur.alters[0]


def test_a_column_of_the_right_type_is_left_alone():
    """MySQL takes the lock for a MODIFY whether or not the type changes,
    which is exactly why `soar_actions` looked idempotent and was not."""
    cur = FakeCursor({"prompt_hash": "char(64)"}, [])
    _load("_bring_table_up_to_date")(cur, "ai_cache", modify=MODIFY)
    assert cur.alters == []


def test_a_missing_table_is_not_migrated():
    """information_schema returning nothing means the CREATE above has not
    run yet - not that every column is missing."""
    cur = FakeCursor({}, [])
    _load("_bring_table_up_to_date")(
        cur, "ai_analysis_results", columns=COLUMNS, indexes=INDEXES)
    assert cur.alters == []


def test_it_never_waits_on_the_lock():
    """Blocking here stalls whatever is reading the table; the next write
    tries again."""
    cur = FakeCursor({"verdict": "varchar(24)"}, [])
    _load("_bring_table_up_to_date")(
        cur, "ai_analysis_results", columns=COLUMNS, indexes=INDEXES)
    assert cur.alters, "nothing was applied, so the timeout proves nothing"
    assert any("lock_wait_timeout" in s for s in cur.executed)


def test_a_failure_is_reported_rather_than_swallowed():
    """A column that never appears turns into a failing INSERT somewhere else
    entirely, which is how the previous version hid."""
    class Failing(FakeCursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            if sql.upper().startswith("ALTER TABLE"):
                raise RuntimeError("lock wait timeout exceeded")

    cur = Failing({"verdict": "varchar(24)"}, [])
    # It must not propagate: a schema hiccup cannot stop an insight being
    # written. It must also not be silent.
    _load("_bring_table_up_to_date")(
        cur, "ai_analysis_results", columns=COLUMNS, indexes=INDEXES)


@pytest.mark.parametrize("func", ["set_ai_cache", "save_ai_results"])
def test_the_write_paths_use_the_guard(func):
    """Docstrings dropped first: these functions describe the migration they
    used to run, and matching prose would read the explanation as the code."""
    tree = ast.parse(AI_UTILS.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == func)
    statements = fn.body
    if (statements and isinstance(statements[0], ast.Expr)
            and isinstance(statements[0].value, ast.Constant)):
        statements = statements[1:]
    code = "\n".join(ast.unparse(n) for n in statements)

    assert "_bring_table_up_to_date" in code
    assert "ALTER TABLE" not in code.upper(), (
        f"{func} still alters unconditionally on every write"
    )


def test_the_insert_columns_all_exist_in_the_create():
    """The INSERT names `fingerprint`, which the CREATE did not declare - so a
    fresh database depended on the migration having run before its first
    write. A guarded migration that correctly does nothing would have made
    that dependency fail."""
    source = AI_UTILS.read_text(encoding="utf-8")
    create = source[source.index("CREATE TABLE IF NOT EXISTS ai_analysis_results"):]
    create = create[:create.index(")\n")]
    for column in ("fingerprint", "verdict", "severity", "confidence",
                   "payload", "prompt_version"):
        assert column in create, f"{column} is inserted but never created"
