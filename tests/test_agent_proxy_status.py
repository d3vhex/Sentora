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
    """`_agent_proxy` is the one place that knows how to reach an agent and
    how to translate what comes back. A handler that goes around it gets
    neither, and gets them wrong in its own way."""
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
    assert "_no_channel_message" in code


def test_the_proxy_has_no_http_fallback_left():
    """It used to dial the endpoint on 9099 when the channel was unavailable.

    Nothing that could rescue is lost: the channel is an outbound connection
    to the same server the agent already posts telemetry to, so any agent
    reporting at all can open one. The fallback needed an *inbound* path,
    which is strictly harder - behind NAT or a host firewall it never worked,
    and making it work meant an authenticated management API with
    /self_destruct on it, exposed on every endpoint in the fleet.
    """
    code = _source("_agent_proxy")
    for gone in ("_agent_http_bases", "for base in bases", "requests.",
                 "_try_agent_request"):
        assert gone not in code, f"{gone} is still in the command path"


def test_a_rejected_key_explains_what_to_do():
    """The operator can act on this one: restart the agent so it re-fetches.

    A stale key now shows up as a channel that never opens - the server logs
    `[agent-link] refused a connection` and the agent simply never appears -
    so the advice moved into the message that explains a missing channel.
    """
    code = _source("_no_channel_message")
    assert "bootstrap" in code
    assert "refused a connection" in code, \
        "nothing points the operator at the line that names the cause"


def test_a_missing_channel_is_not_reported_as_being_offline():
    """Telemetry and commands travel on different connections, so an agent
    can be reporting normally and still be uncommandable. 'Unreachable' was
    true of every cause and useful for none."""
    code = _source("_no_channel_message")
    assert "look online here" in code
    assert "predates the channel" in code, \
        "the most likely cause - an un-upgraded binary - is not named"


# --------------------------------------------------------------------------
# The audit trail must not claim more than happened
# --------------------------------------------------------------------------

def test_a_failed_push_is_not_audited_as_a_config_change():
    """A push that never reached the sensor is not a reconfiguration, and an
    audit log saying it was is worse than no entry."""
    code = _source("set_agent_config_proxy")
    assert "CONFIG_PUSH_FAILED" in code


# --------------------------------------------------------------------------
# host.docker.internal outlived the reason it was added
# --------------------------------------------------------------------------
#
# The alias was added so the server could dial an agent running on the
# container host: under Docker Desktop the containers live in a Linux VM, so
# the host's LAN address is reached through a NAT that does not forward back,
# and every address the server knew was refused - including the right one.
#
# Agents are not dialled any more, but the alias is still how this container
# reaches Ollama on the host, so the compose entry has to stay.


def test_compose_defines_the_name_for_plain_docker():
    """Docker Desktop provides it; Linux Docker does not, and without the
    alias the AI endpoint silently never resolves."""
    import yaml
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
    hosts = compose["services"]["app"].get("extra_hosts") or []
    assert any("host.docker.internal:host-gateway" in h for h in hosts), \
        "app cannot resolve host.docker.internal on plain Linux Docker"


def test_the_alias_is_still_load_bearing():
    """If nothing used it, the compose entry above would be cargo. The AI
    default endpoint is what keeps it honest."""
    assert "host.docker.internal" in (ROOT / "ai" / "utils.py").read_text(encoding="utf-8")


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


@pytest.mark.parametrize("handler", ["_linked_agent", "set_agent_display_name",
                                     "_agent_display_names"])
def test_identity_lookups_accept_both_spellings(handler):
    assert "_agent_name_forms" in _source(handler), (
        f"{handler} matches the identity name exactly, so it finds nothing "
        f"for any host whose name contains a hyphen")


def test_the_channel_is_found_under_either_spelling():
    """The lookup this replaces held candidate keys to present when dialling
    an agent. Nothing dials one now, so the same mismatch turns up one step
    later: a channel that registered as `DESKTOP-EVS8H9J` and a console
    asking for `DESKTOP_EVS8H9J` would find no link, and every command would
    report the agent as having no channel while it sat there connected."""
    code = _source("_linked_agent")
    assert "_agent_name_forms" in code


def test_the_master_secret_cannot_stand_for_an_agent():
    """It used to be a fallback key to try. On the channel it is refused
    outright - `/self_destruct` rides that connection, and one link standing
    for every endpoint is not a thing to have."""
    code = _source("_validate_agent_auth_sync")
    assert "AGENT_SHARED_SECRET" not in code
    assert "agent_identities" in code
