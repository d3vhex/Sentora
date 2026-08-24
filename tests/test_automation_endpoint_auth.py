"""The automation poll/report pair must prove who it is.

Both endpoints were in `_PUBLIC_HANDLERS` and carried nothing. That gave
anyone who could reach the API two primitives:

    GET  /<agent>/automations/pending
        read the response actions queued for a host. An attacker sees
        ISOLATE_HOST for their own machine before the agent does.

    POST /<agent>/automations/report {"task_id": N, "status": "SUCCESS"}
        walk task_id from 1 upward marking everything done. The real agent
        polls WHERE status='pending' and never sees those rows, so the action
        never runs - and the console shows it green.

The second is worse than a bypass. It switches off every autonomous response
the platform makes while continuing to report that they succeeded.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

APP = pathlib.Path(__file__).resolve().parent.parent / "app.py"
SRC = APP.read_text(encoding="utf-8")
TREE = ast.parse(SRC)

HANDLERS = ("get_pending_automations_for_agent",
            "report_automation_result_by_id",
            "report_automation_result")


def _fn(name):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
                and n.name == name)


@pytest.mark.parametrize("name", HANDLERS)
def test_the_handler_authenticates(name):
    body = ast.unparse(_fn(name))
    assert "_require_agent" in body or "_validate_agent_auth" in body, (
        f"{name} is reachable without a session and does not check a key"
    )


@pytest.mark.parametrize("name", ("report_automation_result_by_id",
                                  "report_automation_result"))
def test_identity_comes_from_the_key_not_the_body(name):
    """`agent` used to be read out of the request body, which makes it a claim
    rather than an identity."""
    body = ast.unparse(_fn(name))
    assert 'data.get("agent")' not in body
    assert 'data.get("metadata", {}).get("agent")' not in body
    assert "_validate_agent_auth" in body


@pytest.mark.parametrize("name", ("report_automation_result_by_id",
                                  "report_automation_result"))
def test_the_fleet_wide_secret_cannot_speak_for_one_host(name):
    """`_validate_agent_auth` returns "*" for the legacy shared secret. It
    names no host, so it cannot report that a specific agent finished a
    task."""
    body = ast.unparse(_fn(name))
    assert "'*'" in body or '"*"' in body


@pytest.mark.parametrize("name", ("report_automation_result_by_id",
                                  "report_automation_result"))
def test_only_an_outstanding_task_can_be_closed(name):
    """The state machine is one-way. Without it the same id can be reported
    repeatedly, and a task that already ran can be rewritten."""
    body = ast.unparse(_fn(name))
    assert "pending" in body and "active" in body
    assert "rowcount" in body


def test_the_status_value_is_constrained():
    """Anything accepted here lands in the ENUM and in the console."""
    body = ast.unparse(_fn("report_automation_result_by_id"))
    assert "_TERMINAL_AUTOMATION_STATES" in body
    assert "_TERMINAL_AUTOMATION_STATES = {" in SRC


def test_a_report_that_matched_nothing_is_not_reported_as_success():
    for name in ("report_automation_result_by_id", "report_automation_result"):
        body = ast.unparse(_fn(name))
        assert "404" in body, f"{name} answers success when it changed nothing"


def test_the_swallowed_exceptions_are_gone():
    """Two `except Exception: pass` blocks meant nobody knew which table had
    been updated, or whether either had."""
    body = ast.unparse(_fn("report_automation_result"))
    assert "except Exception:\n    pass" not in body
    assert "pass" not in body.split("async with agent_conn")[-1][:400] or \
        "doesn't exist" in body


def test_the_public_allowlist_note_is_no_longer_a_lie():
    """The comment said the pair 'currently carries nothing - tracked as
    follow-up work'. It carries a key now."""
    i = SRC.index("_PUBLIC_HANDLERS = {")
    block = SRC[i - 900:i + 500]
    assert "currently carries nothing" not in block
