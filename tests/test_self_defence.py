"""The platform watches every host in the fleet. Nobody watched the platform.

Every one of these was already detected and none of it was visible. A
brute-force against the console produced `login_logs` rows and a lockout, and
the alert view showed nothing. A revoked agent key retrying produced

    [agent-link] refused a connection from 203.0.113.9

in a container log, which nobody reads until they already suspect something -
the wrong order for the one signal that says a key is being used after it was
taken away.

So these become events of the same shape as everything else the console
surfaces, and this file pins the three properties that stop the cure being
worse than the disease.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"

from core import self_defence  # noqa: E402


class _FakeCursor:
    """Enough of a DB-API cursor to exercise the fold.

    `rowcount` is set by each statement, the way a real driver does it - the
    first version seeded it in the constructor, and the DDL that runs first
    then cleared it before the UPDATE could be read. The fake was wrong and
    the code was right, which is the more expensive way round.
    """

    def __init__(self, updates_match: bool = False):
        self.statements: list[tuple[str, tuple]] = []
        self.updates_match = updates_match
        self.rowcount = 0

    def execute(self, sql, params=()):
        self.statements.append((" ".join(sql.split()), params))
        verb = sql.strip().split()[0].upper()
        if verb == "UPDATE":
            self.rowcount = 1 if self.updates_match else 0
        else:
            self.rowcount = 0


# --------------------------------------------------------------------------
# A severity is a claim
# --------------------------------------------------------------------------

@pytest.mark.parametrize("kind", sorted(self_defence.KINDS))
def test_every_kind_has_a_severity_and_an_explanation(kind):
    """An operator seeing FLEET_KEY_ON_CHANNEL for the first time should not
    have to go looking for what it implies."""
    severity, explanation = self_defence.describe(kind)
    assert severity in self_defence.SEVERITY_RANK
    assert len(explanation) > 40, f"{kind} explains nothing"


def test_an_unknown_kind_is_filed_rather_than_dropped():
    """A caller inventing a name is a bug, but losing the event is worse than
    filing it under the wrong heading."""
    severity, _ = self_defence.describe("SOMETHING_NEW")
    assert severity == "MEDIUM"


def test_the_fleet_key_is_the_worst_thing_here():
    """It opens a channel that carries /self_destruct against every endpoint
    at once. Nothing else on this list is in that category."""
    ranks = {k: self_defence.SEVERITY_RANK[self_defence.describe(k)[0]]
             for k in self_defence.KINDS}
    assert ranks["FLEET_KEY_ON_CHANNEL"] == min(ranks.values())


# --------------------------------------------------------------------------
# One attack is one row
# --------------------------------------------------------------------------

def test_a_repeat_folds_into_the_previous_row():
    """A brute-force writing a row per attempt makes the view that is supposed
    to reveal the attack into the thing that buries it."""
    cursor = _FakeCursor(updates_match=True)
    self_defence.record(cursor, "LOGIN_LOCKOUT", subject="admin",
                        source_ip="203.0.113.9", detail="5 in 60s")
    kinds = [sql.split()[0] for sql, _ in cursor.statements]
    assert "INSERT" not in kinds, "a repeat created a second row"
    assert "UPDATE" in kinds


def test_a_first_sighting_creates_a_row():
    cursor = _FakeCursor(updates_match=False)
    self_defence.record(cursor, "LOGIN_LOCKOUT", subject="admin",
                        source_ip="203.0.113.9")
    assert any(sql.startswith("INSERT INTO platform_events")
               for sql, _ in cursor.statements)


def test_the_fold_is_bounded_in_time():
    """Without a window, an attack from a year ago and one happening now are
    the same row and the timestamps say nothing."""
    cursor = _FakeCursor(updates_match=True)
    self_defence.record(cursor, "LOGIN_LOCKOUT", subject="a", source_ip="b")
    update = next(sql for sql, _ in cursor.statements if sql.startswith("UPDATE"))
    assert "INTERVAL" in update and "last_seen >" in update


def test_the_summary_counts_attempts_not_rows():
    """"3 events" where one of them is 400 failed logins is the wrong number
    to put in front of somebody."""
    summary = self_defence.summarise([
        {"severity": "HIGH", "occurrences": 400},
        {"severity": "MEDIUM", "occurrences": 2},
    ])
    assert summary["attempts"] == 402
    assert summary["worst"] == "HIGH"


# --------------------------------------------------------------------------
# Never store a credential
# --------------------------------------------------------------------------

def test_nothing_here_records_a_secret():
    """These records describe attempts on secrets, and the obvious fields to
    include - the password tried, the key presented - are exactly the ones
    that turn an audit trail into a second breach."""
    source = (ROOT / "core" / "self_defence.py").read_text(encoding="utf-8")
    columns = source[source.index("CREATE TABLE"):source.index("ENGINE=InnoDB")]
    for forbidden in ("password", "agent_key", "token", "secret", "hash"):
        assert forbidden not in columns.lower(), \
            f"the platform event table has a `{forbidden}` column"


# --------------------------------------------------------------------------
# Recording must never break what it records
# --------------------------------------------------------------------------

def test_the_writer_swallows_its_own_failure():
    """Every caller is in the middle of refusing something. A server that
    will not reject a bad login because it could not journal the rejection has
    turned a monitoring gap into an outage."""
    fn = next(n for n in ast.walk(ast.parse(APP.read_text(encoding="utf-8")))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_platform_event")
    body = ast.unparse(fn)
    assert "except Exception" in body
    assert "raise" not in body


def test_it_does_not_block_the_event_loop():
    """A synchronous MySQL write inside a request handler stalls every other
    request on the worker - and this one runs on the login path, which is
    exactly where an attacker controls the rate."""
    fn = next(n for n in ast.walk(ast.parse(APP.read_text(encoding="utf-8")))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_platform_event")
    assert "to_thread" in ast.unparse(fn)


# --------------------------------------------------------------------------
# Detected and recorded is only half of it
# --------------------------------------------------------------------------

def _raised_kinds() -> set:
    """Kinds that actually reach `_platform_event`, following variables.

    Reading the call sites rather than searching the file. The first version
    of this test asserted the name appeared *somewhere* in app.py, which a
    mention in a comment satisfies - and three of six kinds sat unwired while
    it passed. Two of the three that were wired pass their kind through a
    variable, so looking only for a literal argument misses those too; the
    assignments are followed.
    """
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    raised = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "_platform_event"
                and node.args):
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant):
            raised.add(first.value)
            continue
        name = getattr(first, "id", "")
        for other in ast.walk(tree):
            if isinstance(other, ast.Assign) and any(
                    getattr(t, "id", "") == name for t in other.targets):
                raised.update(c.value for c in ast.walk(other.value)
                              if isinstance(c, ast.Constant)
                              and isinstance(c.value, str))
    return raised


@pytest.mark.parametrize("kind", sorted(self_defence.KINDS))
def test_every_kind_is_actually_raised(kind):
    """A vocabulary nothing raises is a vocabulary.

    Parametrised over the whole map rather than a hand-written list, so a kind
    added and never wired fails here instead of sitting quietly. That is how
    three of them sat: defined, explained, given a severity, and unreachable.
    """
    assert kind in _raised_kinds(), (
        f"{kind} is defined in self_defence.KINDS and nothing calls "
        f"_platform_event with it"
    )


def test_nothing_raises_a_kind_that_does_not_exist():
    """The other direction. `describe()` files an unknown kind under MEDIUM
    rather than dropping it, which is the right runtime behaviour and would
    hide a typo for ever."""
    invented = sorted(k for k in _raised_kinds()
                      if k.isupper() and "_" in k and k not in self_defence.KINDS)
    assert not invented, f"raised but never defined: {invented}"


def test_there_is_somewhere_to_read_them():
    """Recording without surfacing repeats the original mistake in a new
    table."""
    source = APP.read_text(encoding="utf-8")
    assert "/api/platform/events" in source


# --------------------------------------------------------------------------
# Surfaced, not just stored
# --------------------------------------------------------------------------

FRONTEND = ROOT / "frontend" / "src"


def test_the_console_reads_them():
    """The failure this whole module exists to fix was "detected, recorded
    somewhere nobody looks". Adding a table and stopping there would be the
    same mistake in a new place."""
    api = (FRONTEND / "services" / "api.ts").read_text(encoding="utf-8")
    assert "/api/platform/events" in api, "nothing in the console fetches them"

    page = (FRONTEND / "pages" / "AuditLogs.tsx").read_text(encoding="utf-8")
    assert "getPlatformEvents" in page
    assert "occurrences" in page, \
        "the fold is invisible, so one attack reads as one attempt"


def test_a_role_without_the_permission_is_not_shown_an_error():
    """`manage_users` reaches the audit log and not this. That is not a
    failure for them - the section does not apply - and rendering it as one
    trains people to ignore red."""
    page = (FRONTEND / "pages" / "AuditLogs.tsx").read_text(encoding="utf-8")
    fetch = page[page.index("getPlatformEvents"):]
    fetch = fetch[:fetch.index("}, []);")]
    assert ".catch(" in fetch, "a 403 surfaces as a broken page"


def test_severity_uses_the_semantic_colours():
    """A severity is a claim. Drawing CRITICAL in whatever colour the third
    row happened to get is the chart lying about its own data."""
    page = (FRONTEND / "pages" / "AuditLogs.tsx").read_text(encoding="utf-8")
    assert "SEVERITY_TONE" in page
    assert "CRITICAL: 'critical'" in page


def test_an_empty_result_is_shown_rather_than_hidden():
    """The first version hid the panel when there was nothing in it, and the
    argument for that read well: a permanently empty panel is furniture people
    learn to skip.

    It was wrong, and wrong in exactly the way the rest of this work exists to
    prevent. An operator who never sees the panel cannot tell "nothing has
    attacked us" from "this platform does not watch itself" - the same
    ambiguity as an empty telemetry table, on the one view whose whole job is
    to remove it. On a security view a quiet twenty-four hours is a finding,
    so it is stated.

    `null` stays hidden, and that is a different case: the role cannot read
    this, so it is not an empty result, it is not their question.
    """
    page = (FRONTEND / "pages" / "AuditLogs.tsx").read_text(encoding="utf-8")
    assert "platform !== null" in page,         "the panel is hidden on an empty result again"
    assert "platform?.length &&" not in page,         "the panel still renders only when it has rows"
    assert "not that nothing is watching" in page,         "an empty panel does not say what empty means"
