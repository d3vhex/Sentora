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


# --------------------------------------------------------------------------
# Reaching an agent that runs on this machine
# --------------------------------------------------------------------------
#
# The agent was listening on 0.0.0.0:9099 and every address the server knew
# was refused, including the right one. Under Docker Desktop the containers
# live in a Linux VM, so the host's LAN address (192.168.1.26) is reached
# through a NAT that does not forward back - refused against a machine that is
# listening.
#
# The signal for this case already existed and was being thrown away: an agent
# that reaches us from our own bridge gateway is running on the container
# host. `observed_peer_ip` detects exactly that and discards the gateway as an
# address, which is right - it cannot be dialled - but it still says where the
# agent is.


def test_the_container_host_is_a_candidate_address():
    code = _source("_agent_http_bases")
    assert "host.docker.internal" in code
    assert "in_container" in code, \
        "the name is only meaningful from inside a container"


def test_the_recorded_addresses_are_tried_first():
    """On a real deployment - server on its own box, agents on the network -
    the recorded addresses are correct and this name is not."""
    code = _source("_agent_http_bases")
    assert code.index("reported_ip") < code.index("host.docker.internal")


def test_loopback_stays_the_last_resort():
    code = _source("_agent_http_bases")
    assert code.index("host.docker.internal") < code.rindex("127.0.0.1")


def test_compose_defines_the_name_for_plain_docker():
    """Docker Desktop provides it; Linux Docker does not, and without the
    alias the candidate silently never resolves."""
    import yaml
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
    hosts = compose["services"]["app"].get("extra_hosts") or []
    assert any("host.docker.internal:host-gateway" in h for h in hosts), \
        "app cannot resolve host.docker.internal on plain Linux Docker"


# --------------------------------------------------------------------------
# The informative error must not be overwritten by the useless one
# --------------------------------------------------------------------------
#
# `_agent_proxy` kept a single `last_detail` and overwrote it per address, so
# the address that connected and answered 401 - which names the actual
# problem - was buried under "connection refused" from the loopback fallback
# tried after it. The operator read the reason for an address that was never
# going to work, and never saw the one that did.


def test_every_address_reports_its_own_outcome():
    code = _source("_agent_proxy")
    assert "outcomes" in code
    assert "outcomes.append" in code


def test_a_rejected_key_is_not_lost_behind_a_later_refusal():
    """Reaching the agent is a different fact from failing to reach it, and it
    survives whatever the remaining addresses do."""
    code = _source("_agent_proxy")
    assert "reached, but the agent rejected" in code
    # The headline is chosen from what happened, not from the last iteration.
    assert "if reached:" in code


def test_the_headline_distinguishes_the_two_failures():
    code = _source("_agent_proxy")
    assert "rejected this server's key" in code
    assert "Could not reach" in code


# --------------------------------------------------------------------------
# The console does not know the agent's real name
# --------------------------------------------------------------------------
#
# `agent_identities.agent_name` holds what the agent enrolled as -
# `DESKTOP-EVS8H9J`. The console builds its agent list from `SHOW DATABASES`
# and strips `_db`, and `server._sanitize_db_name` has already turned every
# hyphen into an underscore by then, so what reaches these handlers is
# `DESKTOP_EVS8H9J`.
#
# Matching that exactly found no row, so the key lookup fell through to the
# fleet master secret - which the agent rightly refused, because it holds its
# own key and has never seen that one. Every server-to-agent call on any host
# with a hyphen in its name returned 401: config reads, SOAR dispatch, the
# screen stream. The agent was correct at every step and looked broken.

def _name_forms():
    namespace: dict = {"re": __import__("re")}
    exec(compile(ast.Module(body=[_function("_agent_name_forms")], type_ignores=[]),
                 "<app.py>", "exec"), namespace)
    return namespace["_agent_name_forms"]


def test_the_two_spellings_of_one_host():
    hyphen, underscore, _ = _name_forms()("DESKTOP_EVS8H9J")
    assert hyphen == "DESKTOP-EVS8H9J"
    assert underscore == "DESKTOP_EVS8H9J"


@pytest.mark.parametrize("handler", ["_get_agent_keys", "set_agent_display_name",
                                     "_agent_display_names"])
def test_identity_lookups_accept_both_spellings(handler):
    assert "_agent_name_forms" in _source(handler), (
        f"{handler} matches the identity name exactly, so it finds nothing "
        f"for any host whose name contains a hyphen")


def test_the_key_lookup_returns_every_match():
    """Two names can flatten to one spelling. `_try_agent_request` already
    walks candidate keys, so an ambiguity costs one extra request rather than
    a wrong answer."""
    code = _source("_get_agent_keys")
    assert "fetchall" in code
    assert "LIMIT 1" not in code


def test_the_master_secret_is_still_only_a_fallback():
    """It is appended after the per-agent keys, never instead of them - the
    whole failure was reaching for it when the real key existed."""
    code = _source("_get_agent_keys")
    # The per-agent keys are collected before the fallback is appended. Read
    # off the statements, not the docstring, which names both.
    assert code.index("keys.append(row[0])") < code.index("keys.append(AGENT_SHARED_SECRET)")
