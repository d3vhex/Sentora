"""Does the telemetry actually arrive? Per table, end to end.

Three bugs in one day had the same shape, and none of them was visible from
either side alone:

  1. `edr_enforcer.main` called five collectors as five bare statements, so the
     first to raise took the four after it. Network and hardware went dark
     together and nothing said so.
  2. Four tables were both snapshot and deduplicated: emptied on every batch,
     then every row skipped as a duplicate. Full once, permanently empty after.
  3. The agent marks rows sent as soon as `sendall` returns. The ingest
     protocol has no reply, so a server that accepts a batch and stores none of
     it is indistinguishable from one that stored all of it.

Every layer reported success. The only symptom was an empty table, which reads
exactly like a host with nothing to report - and on a security console those
two mean opposite things.

The fix is not more logging on either side. It is putting the two numbers next
to each other: the agent says what it holds and believes it shipped, the server
says what it holds, and the difference names the broken link. `sent (50 rows)`
against a server table with zero rows is not ambiguous once somebody compares
them; the whole difficulty was that nobody ever did.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
AGENT_MAIN = ROOT / "Sentora" / "main.py"
HEALTH = ROOT / "Sentora" / "modules" / "telemetry_health.py"


def _classifier():
    """`_classify_link`, compiled without importing app.py."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_classify_link")
    namespace: dict = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<app.py>", "exec"),
         namespace)
    return namespace["_classify_link"]


def _function(path: pathlib.Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


# --------------------------------------------------------------------------
# The states, each of which used to look like an empty table
# --------------------------------------------------------------------------

def test_shipped_but_not_here_is_its_own_state():
    """The bug that was invisible. The agent's log said `sent (50 rows)` every
    cycle for hours while the server held none of them."""
    state, detail = _classifier()(
        {"held": 50, "unsent": 0, "shipped": 50}, 0)
    assert state == "lost in transit"
    assert "not a quiet host" in detail


def test_never_collected_is_not_the_same_as_lost():
    """A collector that never ran and a batch that was discarded need
    different people to do different things, and both showed as a blank
    table."""
    state, _ = _classifier()({"held": 0, "unsent": 0, "shipped": 0}, 0)
    assert state == "not collected"


def test_a_send_failure_carries_its_reason():
    state, detail = _classifier()(
        {"held": 10, "unsent": 10, "shipped": 0,
         "last_error": "OSError: connection refused"}, 0)
    assert state == "send failing"
    assert "connection refused" in detail


def test_collected_but_not_yet_shipped_is_normal():
    """The ordinary state a few seconds after a collector runs. Reporting it
    as broken would train people to ignore this page."""
    state, _ = _classifier()({"held": 10, "unsent": 10, "shipped": 0}, 0)
    assert state == "queued"


def test_flowing_says_so():
    state, _ = _classifier()({"held": 50, "unsent": 0, "shipped": 50}, 50)
    assert state == "flowing"


def test_a_missing_server_table_is_a_state_not_an_error():
    """The agent can be newer than the server. That is worth naming rather
    than failing the whole report over."""
    state, _ = _classifier()({"held": 5, "unsent": 0, "shipped": 5}, None)
    assert state == "no table"


def test_an_empty_but_healthy_table_is_not_flagged():
    """Plenty of tables are legitimately empty on a given host. If those read
    as broken the page is noise and nobody opens it."""
    state, _ = _classifier()({"held": 0, "unsent": 0, "shipped": 0}, 0)
    assert state != "lost in transit"


# --------------------------------------------------------------------------
# The agent's half
# --------------------------------------------------------------------------

def test_the_agent_reads_counts_from_the_database_not_a_counter():
    """A counter resets when the agent restarts and drifts whenever anything
    writes without going through it. The tables are the truth."""
    source = HEALTH.read_text(encoding="utf-8")
    assert "SELECT COUNT(*)" in source
    assert "FILTER (WHERE sent = FALSE)" in source


def test_the_agent_does_not_judge_its_own_delivery():
    """The comparison needs both halves, and the other half is on the server.
    An agent deciding whether its own data arrived is the assumption that
    produced this bug."""
    source = HEALTH.read_text(encoding="utf-8")
    for verdict in ("lost in transit", "flowing", "not collected"):
        assert verdict not in source, \
            f"the agent classifies delivery ({verdict!r}); only the server can"


def test_a_missing_table_does_not_hide_the_others():
    """The agent's schema gains tables over releases. One missing must not
    take the whole report down with it."""
    code = _function(HEALTH, "_counts")
    assert "except Exception" in code
    # `ast.unparse` writes the tuple with parentheses.
    assert "return (0, 0)" in code


def test_the_send_path_records_both_outcomes():
    code = _function(AGENT_MAIN, "send_table")
    assert "telemetry_health.record_send(" in code
    assert "record_send_failure" in code


def test_the_agent_serves_the_report_over_the_channel():
    code = _function(AGENT_MAIN, "dispatch_channel_request")
    assert "/telemetry/health" in code
    assert "telemetry_health.report" in code


def test_the_module_is_bundled_by_both_builds():
    """Reached only from `main.py`'s import block and `dispatch_channel_request`.
    Left out of one build script it produces an agent that installs fine on one
    platform and cannot answer this question."""
    for script in ("build_agent.ps1", "build_agent.sh"):
        text = (ROOT / "Sentora" / script).read_text(encoding="utf-8")
        assert "modules.telemetry_health" in text, script


# --------------------------------------------------------------------------
# The server's half
# --------------------------------------------------------------------------

def test_an_agent_too_old_to_answer_is_told_apart_from_a_broken_one():
    """A 501 from the dispatcher means "this build does not implement it",
    which is a different instruction from "something is wrong"."""
    code = _function(APP, "get_telemetry_health")
    assert "501" in code
    assert "Rebuild and reinstall" in code


def test_the_report_counts_what_is_broken():
    """So the page and, later, an alert can act on one number rather than on
    a table somebody has to read."""
    code = _function(APP, "get_telemetry_health")
    assert "broken_count" in code


def test_the_server_counts_its_own_rows_rather_than_trusting_the_agent():
    """The entire point. Asking the agent whether its data arrived returns
    the same optimistic answer that hid the bug."""
    code = _function(APP, "_server_table_counts")
    assert "SELECT COUNT(*)" in code


# --------------------------------------------------------------------------
# It has to be reachable from the page where the symptom appears
# --------------------------------------------------------------------------

FRONTEND = ROOT / "frontend" / "src"


def test_the_page_is_routed_and_linked():
    """A diagnosis nobody can navigate to is a diagnosis nobody will make.
    The link belongs on the host page, because that is where the empty tab
    that prompts the question is."""
    app_tsx = (FRONTEND / "App.tsx").read_text(encoding="utf-8")
    assert "/agent/:agentName/telemetry" in app_tsx

    detail = (FRONTEND / "pages" / "AgentDetail.tsx").read_text(encoding="utf-8")
    assert "/telemetry" in detail


def test_the_broken_rows_sort_first():
    """A page that needs scrolling to find the problem is a page nobody opens
    twice."""
    page = (FRONTEND / "pages" / "TelemetryHealth.tsx").read_text(encoding="utf-8")
    assert "STATE_RANK" in page
    order = page[page.index("const STATE_RANK"):page.index("const rank")]
    assert order.index("lost in transit") < order.index("flowing")


def test_an_unreachable_agent_does_not_render_as_a_healthy_one():
    """The ambiguity this whole feature exists to remove. If the fetch fails
    and the page shows an empty table, it has reproduced the bug it
    diagnoses."""
    page = (FRONTEND / "pages" / "TelemetryHealth.tsx").read_text(encoding="utf-8")
    assert "ErrorState" in page
    assert "Could not reach this agent" in page
