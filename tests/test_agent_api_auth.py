"""The agent has no inbound surface at all, and the channel that replaced it
is authenticated with this agent's own key.

This file used to test the agent's HTTP listener. Three of its routes had no
authentication whatsoever:

    curl -X POST http://<endpoint>:9099/self_destruct

removed the EDR from the host, and `/soar/execute` with
`{"action": "run_cmd", ...}` was remote code execution as SYSTEM, fleet-wide,
because a permissive branch accepted any non-empty key whenever
AGENT_MASTER_SECRET was unset - which nothing in this repository ever set.

Those were fixed by authenticating the routes. The listener is now gone
instead, which is the stronger version of the same fix: there is no port to
knock on, no firewall rule to get right, and no key check that can regress.

What has to be pinned is that it stays gone, and that the properties those
route checks carried now hold on the channel - which is authenticated once,
on the server, when the agent dials in.
"""

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = ROOT / "Sentora" / "main.py"
APP = ROOT / "app.py"
SRC = MAIN.read_text(encoding="utf-8")
TREE = ast.parse(SRC)



def _code_only(path) -> str:
    """A Python file's code, with comments and docstrings removed.

    These assertions are "this construct is gone", and the note left behind
    when something is removed almost always names what it replaced - so
    matching the raw file reads the explanation as the code. That has caught
    us out repeatedly, always the same way.
    """
    tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            del body[0]
    return ast.unparse(tree)


# The notes left where the listener was name every construct removed with it.
CODE = _code_only(MAIN)


# --------------------------------------------------------------------------
# There is nothing listening
# --------------------------------------------------------------------------

def test_the_agent_serves_no_routes():
    routes = []
    for node in ast.walk(TREE):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for dec in node.decorator_list:
            d = ast.unparse(dec)
            if any(m in d for m in (".route(", ".post(", ".get(", ".websocket(")):
                routes.append(node.name)
    assert not routes, (
        f"{sorted(routes)} are reachable on the endpoint; the whole point is "
        f"that nothing is"
    )


def test_the_agent_serves_nothing():
    for gone in ("app.run(", "AGENT_BIND", "Sanic("):
        assert gone not in CODE, f"{gone} is back; the endpoint is listening again"


def test_the_only_socket_left_is_the_instance_mutex():
    """Not "no socket at all" - the claim has to be exact, because it is a
    security claim. `acquire_single_instance_lock` binds 127.0.0.1:9098 and
    never accepts on it: the bind failing is the whole signal, and it exists
    because the installer's watchdog task would otherwise start a second
    agent every fifteen minutes."""
    tree = ast.parse(CODE)
    binds = [n for n in ast.walk(tree)
             if isinstance(n, ast.Attribute) and n.attr == "bind"]
    assert len(binds) == 1, f"{len(binds)} sockets are bound, expected the mutex only"

    lock = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef)
                and n.name == "acquire_single_instance_lock")
    assert "'127.0.0.1'" in lock, "the mutex socket is not confined to loopback"
    assert "accept" not in lock, "a mutex that accepts connections is a service"


def test_the_web_stack_is_out_of_the_binary():
    """A dependency that ships is a dependency that can be reached. Leaving
    sanic in the build would keep the attack surface in the binary even with
    no route pointing at it."""
    for build in ("build_agent.ps1", "build_agent.sh"):
        text = (ROOT / "Sentora" / build).read_text(encoding="utf-8")
        code = "\n".join(l for l in text.splitlines()
                         if not l.strip().startswith("#"))
        assert "sanic" not in code, f"{build} still bundles sanic"
    requirements = (ROOT / "Sentora" / "requirements.txt").read_text(encoding="utf-8")
    assert "sanic" not in requirements


def test_no_inbound_auth_remains_to_regress():
    """These guarded the listener. Keeping them without it would leave a
    check that looks load-bearing and protects nothing."""
    for gone in ("_check_auth_header", "_ws_authorized", "_accepted_auth_tokens"):
        assert f"def {gone}" not in CODE


def test_permissive_auth_is_gone():
    """It accepted any non-empty key and was on by default."""
    assert "_is_permissive_auth" not in CODE


# --------------------------------------------------------------------------
# What the route checks used to carry, the channel carries now
# --------------------------------------------------------------------------

def _app_function(name: str) -> str:
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    return next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


def test_the_channel_refuses_the_fleet_wide_secret():
    """`/self_destruct` rides this channel, so a leaked master key must not be
    able to open one against every endpoint at once. The route this replaces
    said the same thing with `enrolment_key_only=True`."""
    code = _app_function("_validate_agent_auth_sync")
    assert "agent_identities" in code
    assert "agent_key=%s" in code
    assert "revoked_at IS NULL" in code, "a revoked identity could still dial in"


def test_an_unauthenticated_channel_is_closed_not_served():
    code = _app_function("agent_link_socket")
    assert "_validate_agent_auth_sync" in code
    assert code.index("_validate_agent_auth_sync") < code.index("AgentLink("), \
        "the link is registered before the caller is identified"
    assert "1008" in code, "an unauthorised socket should be closed, not left open"


def test_the_master_secret_is_not_accepted_as_an_agent():
    """`*` is what the wider validator returns for the fleet key. Treating it
    as an agent name would register one link standing for every endpoint."""
    code = _app_function("agent_link_socket")
    assert "agent == '*'" in code or 'agent == "*"' in code


@pytest.mark.parametrize("command", ["/self_destruct", "/restart", "/soar/execute"])
def test_the_destructive_commands_only_exist_behind_the_channel(command):
    """They are dispatched, not routed. The dispatcher is only reachable from
    a socket that has already been identified."""
    dispatch = next(
        ast.unparse(n) for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == "dispatch_channel_request")
    assert command in dispatch


def test_health_no_longer_hands_out_a_map_of_the_infrastructure():
    """It used to return the SIEM server address, port and API base to anyone
    on the network without a key. Now the only caller that can ask is one that
    already authenticated to open a channel."""
    dispatch = next(
        ast.unparse(n) for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == "dispatch_channel_request")
    assert "/health" in dispatch
