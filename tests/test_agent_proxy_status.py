"""An agent's 401 is not the operator's 401.

Opening an agent's Config tab logged the operator out of the console. Nothing
was wrong with their session: the server proxies the request to the agent, the
agent rejected the key the *server* presented, and the handler relayed that
status to the browser unchanged -

    return sanic_json(resp.json(), status=resp.status_code)

The browser's response interceptor treats 401 as "your session ended", clears
local storage and redirects to the login page. So two systems failing to
authenticate to each other threw out a third party who was authenticated fine.

The sibling symptom was the tab loading nothing at all: an unreachable agent
raised inside the handler and came back as a bodyless 500.

These are status-translation rules, and translating them wrongly is silent -
the console just behaves strangely - so they are pinned here.
"""

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
SRC = APP.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _function(name: str):
    for node in ast.walk(TREE):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in app.py")


def _source(name: str) -> str:
    return ast.unparse(_function(name))


# --------------------------------------------------------------------------
# The translation itself
# --------------------------------------------------------------------------

def _relayed_status():
    """Execute just this function, without importing app.py and its world."""
    namespace: dict = {}
    exec(compile(ast.Module(body=[_function("_relayed_status")], type_ignores=[]),
                 "<app.py>", "exec"), namespace)
    return namespace["_relayed_status"]


@pytest.mark.parametrize("upstream", [401, 403])
def test_an_upstream_auth_failure_never_reaches_the_browser_as_one(upstream):
    """This is the whole bug: 401 out of this API means one thing only, and it
    is not "the agent did not like our key"."""
    assert _relayed_status()(upstream) == 502


@pytest.mark.parametrize("upstream", [200, 201, 204, 400, 404, 409, 500, 503])
def test_every_other_status_passes_through(upstream):
    """Only the two that the browser acts on globally are translated. A 404
    from the agent is still a 404 - the operator needs to see it."""
    assert _relayed_status()(upstream) == upstream


# --------------------------------------------------------------------------
# The handlers that had the bug
# --------------------------------------------------------------------------

@pytest.mark.parametrize("handler", ["get_agent_config_proxy", "set_agent_config_proxy"])
def test_config_handlers_do_not_relay_a_raw_status(handler):
    code = _source(handler)
    assert "resp.status_code" not in code, (
        f"{handler} relays the agent's status straight to the browser, which "
        f"is how the Config tab logged the operator out")


@pytest.mark.parametrize("handler", ["get_agent_config_proxy", "set_agent_config_proxy"])
def test_config_handlers_go_through_the_shared_proxy(handler):
    """`_agent_proxy` is where the address fallback and the status mapping
    live. A handler that calls the agent directly gets neither."""
    assert "_agent_proxy" in _source(handler)


def test_the_third_party_proxy_translates_too():
    """A playbook node reaching an API that wants credentials must not log the
    operator out of Sentora."""
    code = _source("http_proxy")
    assert "_relayed_status(resp.status_code)" in code
    # The real status is still available to whatever made the call.
    assert "X-Upstream-Status" in code


# --------------------------------------------------------------------------
# Unreachable is a state of the world, not an exception
# --------------------------------------------------------------------------

def test_an_unreachable_agent_produces_a_reason_not_a_500():
    code = _source("_agent_proxy")
    assert "502" in code
    assert "Could not reach" in code
    # The addresses tried are part of the answer: "refused" against an IP that
    # never had a listener is the confusing case this exists for.
    assert "tried" in code


def test_the_proxy_tries_every_known_address():
    """An agent legitimately has two addresses - see `_agent_http_bases`.
    Failing on the first says nothing about the second."""
    code = _source("_agent_proxy")
    assert "_agent_http_bases" in code
    assert "for base in bases" in code


def test_a_rejected_key_explains_what_to_do():
    """The operator can act on this one: restart the agent so it re-fetches."""
    code = _source("_agent_proxy")
    assert "bootstrap" in code


def test_a_non_json_agent_response_is_not_a_crash():
    """`resp.json()` on an HTML error page raises, and that used to become a
    500 whose body was a stack trace."""
    code = _source("_agent_proxy")
    assert "non-JSON" in code


# --------------------------------------------------------------------------
# The audit trail must not claim more than happened
# --------------------------------------------------------------------------

def test_a_failed_push_is_not_audited_as_a_config_change():
    """A push that never reached the sensor is not a reconfiguration, and an
    audit log saying it was is worse than no entry."""
    code = _source("set_agent_config_proxy")
    assert "CONFIG_PUSH_FAILED" in code
