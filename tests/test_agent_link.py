"""The channel the agent opens, so the server never has to dial it.

Every server-to-agent problem this codebase has fought - the reported address
being wrong behind NAT, the observed one being a router, `host.docker.internal`
as a third guess, a Windows firewall rule the service cannot prompt for, `ufw`
on Linux, and a management API with `/self_destruct` on it listening on every
endpoint - is the same decision seen from different angles: the server dials
the agent.

What is tested here is the half that can be, without a network: the registry,
and what happens to requests in flight when things go wrong. Those are the
paths an operator ends up waiting on.
"""

import asyncio

import pytest

from core.agent_link import (
    MAX_PENDING_PER_AGENT,
    MAX_STREAMS_PER_AGENT,
    STREAM_BACKLOG,
    AgentLink,
    LinkError,
    LinkRegistry,
    decode_stream_frame,
    encode_stream_frame,
)


class Wire:
    """Records what was sent, and can be told to fail.

    Control frames and stream payloads are kept apart, because the socket
    keeps them apart: JSON text for one, binary for the other.
    """

    def __init__(self, fail: Exception | None = None):
        self.sent: list[dict] = []
        self.binary: list[bytes] = []
        self.fail = fail

    async def __call__(self, frame) -> None:
        if self.fail is not None:
            raise self.fail
        if isinstance(frame, (bytes, bytearray)):
            self.binary.append(bytes(frame))
        else:
            self.sent.append(frame)


def _reply(link: AgentLink, wire: Wire, body=None, status=200, index=-1):
    """Answer the request `wire` last carried."""
    request_id = wire.sent[index]["id"]
    return link.deliver({
        "t": "res", "id": request_id,
        "status": status, "body": {"ok": True} if body is None else body,
    })


# --------------------------------------------------------------------------
# The ordinary path
# --------------------------------------------------------------------------

async def test_a_request_reaches_the_agent_and_comes_back():
    wire = Wire()
    link = AgentLink("web-01", wire)

    task = asyncio.create_task(link.request("GET", "/config/rules"))
    await asyncio.sleep(0)

    assert wire.sent[0]["method"] == "GET"
    assert wire.sent[0]["path"] == "/config/rules"
    _reply(link, wire, {"content": "categories: {}"}, 200)

    body, status = await task
    assert status == 200
    assert body["content"] == "categories: {}"


async def test_replies_go_to_the_right_caller():
    """Two requests in flight at once must not be answered by each other's
    reply - the console and a config read overlap routinely."""
    wire = Wire()
    link = AgentLink("web-01", wire)

    first = asyncio.create_task(link.request("GET", "/config/rules"))
    second = asyncio.create_task(link.request("GET", "/config/log_paths"))
    await asyncio.sleep(0)

    _reply(link, wire, {"which": "second"}, index=1)
    _reply(link, wire, {"which": "first"}, index=0)

    assert (await first)[0]["which"] == "first"
    assert (await second)[0]["which"] == "second"


async def test_the_body_shape_matches_what_callers_already_speak():
    """`(body, status)` - the same pair `_agent_proxy` returns, so a caller
    does not have to know which transport carried it."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.request("POST", "/restart"))
    await asyncio.sleep(0)
    _reply(link, wire, {"status": "success"}, 202)
    body, status = await task
    assert (body, status) == ({"status": "success"}, 202)


# --------------------------------------------------------------------------
# When it goes wrong
# --------------------------------------------------------------------------

async def test_an_unanswered_request_times_out():
    """The caller is an HTTP handler with an operator behind it; an agent can
    be killed mid-command."""
    link = AgentLink("web-01", Wire())
    with pytest.raises(LinkError) as excinfo:
        await link.request("GET", "/config/rules", timeout=0.05)
    assert "did not answer" in str(excinfo.value)


async def test_a_timed_out_request_is_forgotten():
    """The entry is what bounds the pending map, so it has to go on every
    path out - including the one nobody returns through."""
    link = AgentLink("web-01", Wire())
    with pytest.raises(LinkError):
        await link.request("GET", "/config/rules", timeout=0.05)
    assert link.pending_count == 0


async def test_a_late_reply_is_reported_not_raised():
    """The agent was slow and the timeout did its job. Not an error, but the
    caller may want to log it."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    with pytest.raises(LinkError):
        await link.request("GET", "/config/rules", timeout=0.05)
    assert _reply(link, wire) is False


async def test_a_disconnect_fails_everything_in_flight():
    """Leaving them to time out means an operator watches a spinner for
    twenty seconds over a fact the server already knows."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.request("GET", "/config/rules", timeout=30))
    await asyncio.sleep(0)

    link.close("the socket dropped")

    with pytest.raises(LinkError) as excinfo:
        await task
    assert "disconnected" in str(excinfo.value)
    assert link.pending_count == 0


async def test_a_request_on_a_closed_link_is_refused_at_once():
    link = AgentLink("web-01", Wire())
    link.close()
    with pytest.raises(LinkError) as excinfo:
        await link.request("GET", "/config/rules")
    assert "not connected" in str(excinfo.value)


async def test_a_send_failure_does_not_leak_a_pending_entry():
    link = AgentLink("web-01", Wire(fail=OSError("socket closed")))
    with pytest.raises(LinkError):
        await link.request("GET", "/config/rules")
    assert link.pending_count == 0


async def test_the_pending_map_is_bounded():
    """An agent that accepts work and never answers would otherwise grow this
    until the server dies - and that agent is exactly the one a compromised
    host would be."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    tasks = [asyncio.create_task(link.request("GET", f"/p/{i}", timeout=30))
             for i in range(MAX_PENDING_PER_AGENT)]
    await asyncio.sleep(0)

    with pytest.raises(LinkError) as excinfo:
        await link.request("GET", "/one-too-many")
    assert "not answering" in str(excinfo.value)

    link.close("done")
    await asyncio.gather(*tasks, return_exceptions=True)


async def test_a_malformed_reply_becomes_an_error_not_a_crash():
    """The peer is an endpoint. A frame that is not the shape we expect must
    not take down the handler waiting on it."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.request("GET", "/config/rules"))
    await asyncio.sleep(0)

    link.deliver({"t": "res", "id": wire.sent[0]["id"], "body": "not a dict"})
    body, status = await task
    assert status == 502
    assert "malformed" in body["message"]


async def test_an_unknown_reply_id_is_ignored():
    link = AgentLink("web-01", Wire())
    assert link.deliver({"t": "res", "id": "never-asked", "body": {}}) is False


# --------------------------------------------------------------------------
# Streams
# --------------------------------------------------------------------------
#
# The console and the screen are long-lived and carry binary at rate. They
# ride the same socket as the commands, as *binary* frames tagged with a
# channel number - not base64 inside the JSON, which would cost a third more
# bandwidth on the connection most likely to be the constrained one.

def test_a_stream_frame_survives_the_round_trip():
    payload = bytes(range(256)) * 4
    assert decode_stream_frame(encode_stream_frame(7, payload)) == (7, payload)


@pytest.mark.parametrize("raw", [
    b"", b"\x01", b"short", "a string", None,
    b"\x99\x00\x00\x00\x01payload",          # wrong version
])
def test_a_frame_we_cannot_read_is_none_not_an_exception(raw):
    """The peer is an endpoint. A frame this cannot parse must not take down
    the channel every other command shares."""
    assert decode_stream_frame(raw) is None


async def test_opening_a_stream_waits_for_the_agent():
    """"the frame was sent" and "the agent has a shell" are different facts,
    and the console spent a while reporting the first as though it were the
    second."""
    wire = Wire()
    link = AgentLink("web-01", wire)

    task = asyncio.create_task(link.open_stream("console", {"cols": 80}))
    await asyncio.sleep(0)

    assert wire.sent[0]["t"] == "open"
    assert wire.sent[0]["kind"] == "console"
    assert not task.done(), "it should still be waiting for the agent"

    link.stream_opened(wire.sent[0]["ch"])
    stream = await task
    assert stream.kind == "console"


async def test_a_stream_the_agent_refuses_raises():
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.open_stream("console"))
    await asyncio.sleep(0)

    link.stream_failed(wire.sent[0]["ch"], "no shell would start")
    with pytest.raises(LinkError) as excinfo:
        await task
    assert "no shell would start" in str(excinfo.value)


async def test_a_stream_that_never_opens_times_out():
    link = AgentLink("web-01", Wire())
    with pytest.raises(LinkError) as excinfo:
        await link.open_stream("console", timeout=0.05)
    assert "did not open" in str(excinfo.value)


async def test_payloads_reach_the_stream_that_asked_for_them():
    wire = Wire()
    link = AgentLink("web-01", wire)

    first = asyncio.create_task(link.open_stream("console"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[0]["ch"])
    console = await first

    second = asyncio.create_task(link.open_stream("screen"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[1]["ch"])
    screen = await second

    link.deliver_stream(console.channel, b"prompt$ ")
    link.deliver_stream(screen.channel, b"\xff\xd8jpeg")

    assert await console.receive(timeout=1) == b"prompt$ "
    assert await screen.receive(timeout=1) == b"\xff\xd8jpeg"


async def test_data_for_an_unknown_stream_is_dropped_quietly():
    link = AgentLink("web-01", Wire())
    assert link.deliver_stream(999, b"nobody wants this") is False


async def test_a_slow_reader_cannot_stall_the_channel():
    """Every other command shares this socket. A browser that stopped reading
    its screen must not be able to hold up a config push - and for a screen,
    the newest frame is the only one worth having."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.open_stream("screen"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[0]["ch"])
    screen = await task

    for i in range(STREAM_BACKLOG + 10):
        link.deliver_stream(screen.channel, bytes([i % 256]))

    # Still accepting, and it is the recent frames that survived.
    assert link.deliver_stream(screen.channel, b"newest") is True


async def test_streams_are_bounded():
    """An endpoint that opens streams and never closes them is the one worth
    being careful of."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    for _ in range(MAX_STREAMS_PER_AGENT):
        task = asyncio.create_task(link.open_stream("console"))
        await asyncio.sleep(0)
        link.stream_opened(wire.sent[-1]["ch"])
        await task

    with pytest.raises(LinkError) as excinfo:
        await link.open_stream("console")
    assert "streams open" in str(excinfo.value)


async def test_ending_a_stream_tells_the_agent():
    """The relay's teardown used `close_stream`, which only forgets it here.

    The agent kept the session open, so the shell stayed running with nobody
    attached - and because a console is one per host, every later request was
    refused as a duplicate of a session no one could reach. The console worked
    exactly once per agent restart.
    """
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.open_stream("console"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[0]["ch"])
    console = await task

    await link.end_stream(console.channel, "the viewer went away")

    assert console.closed
    closing = [f for f in wire.sent if f.get("t") == "close"]
    assert closing, "the agent was never told to close it"
    assert closing[-1]["ch"] == console.channel


async def test_forgetting_a_stream_does_not_echo_back_to_the_agent():
    """`close_stream` is what the agent's own close frame lands on. Telling it
    about a stream it just told us about would be a loop."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.open_stream("console"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[0]["ch"])
    console = await task

    link.close_stream(console.channel, "the agent closed it")
    assert [f for f in wire.sent if f.get("t") == "close"] == []


async def test_a_disconnect_closes_every_stream():
    """A console left open on a link that has gone would sit there accepting
    keystrokes into nothing."""
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.open_stream("console"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[0]["ch"])
    console = await task

    link.close("the socket dropped")

    assert console.closed
    assert await console.receive(timeout=1) is None
    with pytest.raises(LinkError):
        await console.send(b"ls\n")


async def test_stream_data_goes_out_as_binary():
    wire = Wire()
    link = AgentLink("web-01", wire)
    task = asyncio.create_task(link.open_stream("console"))
    await asyncio.sleep(0)
    link.stream_opened(wire.sent[0]["ch"])
    console = await task

    await console.send(b"ls\n")
    assert decode_stream_frame(wire.binary[-1]) == (console.channel, b"ls\n")


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------

def test_an_agent_is_findable_once_connected():
    registry = LinkRegistry()
    link = AgentLink("web-01", Wire())
    assert registry.register(link) is None
    assert registry.get("web-01") is link
    assert registry.connected() == ["web-01"]


def test_a_closed_link_is_not_handed_out():
    registry = LinkRegistry()
    link = AgentLink("web-01", Wire())
    registry.register(link)
    link.close()
    assert registry.get("web-01") is None
    assert registry.connected() == []


def test_a_reconnect_replaces_rather_than_being_refused():
    """The usual cause is a drop the agent noticed before the server did.
    Refusing would lock it out behind a socket that is already dead."""
    registry = LinkRegistry()
    first = AgentLink("web-01", Wire())
    second = AgentLink("web-01", Wire())
    registry.register(first)

    replaced = registry.register(second)
    assert replaced is first
    assert registry.get("web-01") is second


def test_a_late_teardown_does_not_remove_the_replacement():
    """A slow close of the old connection must not unregister the new one, or
    the reconnect looks successful and the agent appears offline."""
    registry = LinkRegistry()
    first = AgentLink("web-01", Wire())
    second = AgentLink("web-01", Wire())
    registry.register(first)
    registry.register(second)

    assert registry.unregister(first) is False
    assert registry.get("web-01") is second

    assert registry.unregister(second) is True
    assert registry.get("web-01") is None


def test_shutting_down_fails_every_link():
    registry = LinkRegistry()
    links = [AgentLink(f"web-{i}", Wire()) for i in range(3)]
    for link in links:
        registry.register(link)

    registry.close_all("server shutting down")
    assert registry.connected() == []
    assert all(link.closed for link in links)
    assert all("shutting down" in link.close_reason for link in links)


# --------------------------------------------------------------------------
# One process
# --------------------------------------------------------------------------
#
# A registry of live sockets cannot span processes, and Sanic runs a worker
# per CPU unless told otherwise. `WORKERS: 1` was in docker-compose.yaml and
# `app.py` never read it, so a deployment whose configuration said one worker
# ran eight - and an agent's channel would have existed in one of them,
# invisible to the rest, taking a different path depending on which worker
# happened to take the request.

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _main_block() -> str:
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    return source[source.index('if __name__ == "__main__":'):]


def test_the_worker_count_is_read_from_the_environment():
    block = _main_block()
    assert 'os.getenv("WORKERS"' in block
    assert "cpu_count()" in block, "the default should still be the old one"


def test_compose_still_asks_for_one_worker():
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
    assert str(compose["services"]["app"]["environment"]["WORKERS"]) == "1"


def test_more_than_one_worker_is_announced():
    """Silently taking a different path per worker is the hardest kind of bug
    to be handed."""
    block = _main_block()
    assert "num_workers > 1" in block
    assert "one worker only" in block


def test_the_constraint_is_written_where_the_registry_is():
    from core import agent_link

    assert "One process" in agent_link.__doc__


# --------------------------------------------------------------------------
# The socket the agent connects to
# --------------------------------------------------------------------------

def _handler(name: str) -> str:
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    raise AssertionError(f"{name} not found in app.py")


def test_the_channel_authenticates_before_registering_anything():
    code = _handler("agent_link_socket")
    assert code.index("_validate_agent_auth_sync") < code.index("register")


def test_the_fleet_secret_cannot_open_a_channel():
    """It carries /self_destruct among other things, and a leaked master key
    should not open one against every endpoint at once."""
    code = _handler("agent_link_socket")
    assert "agent == '*'" in code or 'agent == "*"' in code
    assert "AGENT_SHARED_SECRET" not in _handler("_validate_agent_auth_sync")


def test_the_identity_lookup_runs_off_the_event_loop():
    """A synchronous MySQL connection on a handshake blocks every other
    request on this worker, which is how one reconnecting agent slows the
    console for everyone."""
    assert "to_thread(_validate_agent_auth_sync" in _handler("agent_link_socket")


def test_a_dropped_channel_is_always_unregistered():
    """Leaving a dead link in the registry means every later request picks it,
    fails, and falls back - slowly - instead of going straight to HTTP."""
    code = _handler("agent_link_socket")
    assert "finally:" in code
    assert "unregister" in code


def test_noise_from_an_endpoint_does_not_drop_the_channel():
    """The peer is a host that may be having a bad day. One malformed frame
    should not cost it its channel; the next may be fine."""
    code = _handler("agent_link_socket")
    assert "continue" in code


def test_the_proxy_prefers_the_channel():
    """`_agent_proxy` is the chokepoint every server-to-agent feature already
    goes through, so preferring the channel here moves all of them at once."""
    code = _handler("_agent_proxy")
    assert code.index("_linked_agent") < code.index("_agent_http_bases")


def test_the_channel_is_found_under_either_spelling_of_the_name():
    """The channel registers under `agent_identities.agent_name`; callers
    arrive with the console's name, whose hyphens have been flattened.

    Matching exactly would return None for every hyphenated host, so every
    request would fall back to HTTP with nothing saying why - the feature
    would look implemented and never once fire. Same mismatch as
    `_get_agent_keys`, same fix.
    """
    code = _handler("_linked_agent")
    assert "_agent_name_forms" in code


def test_the_server_only_sends_what_the_agent_implements():
    """The two lists must not drift.

    A path the server routes down the channel but the agent has no case for
    comes back 501 - a perfectly valid answer, so nothing raises and nothing
    falls back to HTTP. That command would simply stop working, quietly, on
    every agent new enough to have a channel. `/soar/execute` is the live
    example: it stays on HTTP precisely because it is not in the dispatcher.
    """
    import re

    server = (ROOT / "app.py").read_text(encoding="utf-8")
    routed = set(re.findall(
        r'"(/[a-z_/]+)"',
        server[server.index("_CHANNEL_PATHS = "):server.index("def _path_moved_to_channel")]))

    agent_tree = ast.parse((ROOT / "Sentora" / "main.py").read_text(encoding="utf-8"))
    dispatch = next(
        ast.unparse(n) for n in ast.walk(agent_tree)
        if isinstance(n, ast.FunctionDef) and n.name == "dispatch_channel_request")

    for path in routed:
        assert path in dispatch, (
            f"the server routes {path} down the channel, but the agent's "
            f"dispatcher has no case for it - it would answer 501 and the "
            f"command would stop working with nothing falling back")


def test_soar_runs_the_same_code_on_both_transports():
    """A hundred lines of per-action validation, and two copies of it would
    drift - with the drifted copy reachable only where the channel is already
    in use, which is where nobody is still watching the old path."""
    agent = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(agent)

    def body(name: str) -> str:
        return next(ast.unparse(n) for n in ast.walk(tree)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name == name)

    assert "cmd_soar_execute" in body("soar_execute")
    assert "cmd_soar_execute" in body("dispatch_channel_request")
    # The command must not be returning Sanic responses down a JSON channel.
    assert "sanic_json" not in body("cmd_soar_execute")


def test_the_console_prefers_the_channel():
    """A console riding the agent's own connection needs no port open on the
    endpoint, which is the entire point of the exercise."""
    code = _handler("console_proxy")
    assert code.index("_linked_agent") < code.index("_console_relay")
    assert "_relay_channel_stream" in code


def test_the_console_still_falls_back_to_a_direct_connection():
    """Agents are upgraded one at a time; an old binary has no channel."""
    code = _handler("console_proxy")
    assert "_console_relay" in code
    assert "falling back" in code


def test_a_channel_stream_is_always_closed_on_the_agent_too():
    """A stream left open on the agent is a shell running with nobody
    attached, and since a console is one per host the next request is then
    refused as a duplicate of a session nobody can reach."""
    code = _handler("_relay_channel_stream")
    assert "finally:" in code
    assert "end_stream" in code, \
        "close_stream only forgets it on this side; the agent keeps the shell"


def test_the_agent_can_open_both_kinds():
    agent = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(agent)
    body = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "open_channel_stream")
    assert "console" in body
    assert "screen" in body


def test_an_unknown_stream_kind_is_refused_by_name():
    """Raising is how a refusal reaches the server's `stream_failed` frame, so
    "no console on this host" arrives as a sentence rather than as a stream
    that opens and never produces a frame."""
    agent = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(agent)
    body = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "open_channel_stream")
    assert "raise ValueError" in body


def test_the_screen_prefers_the_channel_too():
    code = _handler("vnc_proxy")
    assert code.index("_linked_agent") < code.index("_agent_http_bases")
    assert "_relay_channel_stream" in code


def test_a_screen_frame_is_relayed_as_binary():
    """A console is text and a screen is a JPEG. Sending a frame as text
    would corrupt it on the way through, and the browser would render a
    broken image rather than say why."""
    assert "binary=True" in _handler("vnc_proxy")
    relay = _handler("_relay_channel_stream")
    assert "if binary" in relay


def test_the_agent_serves_a_screen_on_either_path():
    """Wiring only the session-0 helper would have made the channel work on
    Windows-as-a-service and silently not on anything else - including the
    headless Linux hosts, which have neither a helper nor a desktop."""
    agent = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(agent)
    body = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == "_ScreenStream")
    assert "in_session_zero" in body
    assert "spawn_helper" in body
    assert "_DirectCapture" in body


def test_a_host_with_no_display_says_so_when_the_stream_opens():
    """Rather than connecting successfully and producing nothing. A stream
    that opens and stays black is the hardest failure here to attribute, and
    the direct websocket path learned that the slow way."""
    agent = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(agent)
    body = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == "_DirectCapture")
    assert "CaptureUnavailable" in body
    assert "describe_unavailable" in body


def test_the_screen_is_paced_by_the_agent():
    """The channel pumps as fast as it can, and the commands share that link:
    an unpaced screen would saturate it."""
    agent = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(agent)
    body = next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == "_DirectCapture")
    assert "self.interval" in body
    assert "sleep" in body


def _agent_class(name: str) -> str:
    tree = ast.parse((ROOT / "Sentora" / "main.py").read_text(encoding="utf-8"))
    return next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == name)


def test_the_console_speaks_the_same_frames_on_both_transports():
    """The direct handler parses what arrives - `decode_input` turns
    `{"t":"i","d":"ls\\n"}` into the two characters the shell should get - and
    frames what it sends back. Handing the raw session to the channel skipped
    both, so every keystroke frame and the resize the browser sends on connect
    went into the shell's stdin as JSON text, and nothing announced the mode.

    The console connected, showed nothing, and eventually died - while the
    screen, which is bytes either way, worked perfectly.
    """
    body = _agent_class("_ConsoleStream")
    assert "decode_input" in body
    assert "encode_output" in body
    assert "encode_mode" in body


def test_the_console_announces_its_mode_first():
    """A pipe-backed shell renders nothing as you type. The browser has to
    know which it is driving before the first keystroke, not after."""
    body = _agent_class("_ConsoleStream")
    assert body.index("encode_mode") < body.index("def read")


def test_the_channel_console_respects_the_one_session_guard():
    """`new_session` skips it; `open_session` is where it lives. Going round
    it would have let the channel open concurrent root shells on one host -
    the thing the guard exists to prevent, reintroduced by a new transport."""
    body = _agent_class("_ConsoleStream")
    assert "console.open_session()" in body
    assert "console.new_session()" not in body
    assert "close_active" in body


def test_a_dead_shell_still_says_why_over_the_channel():
    """Otherwise the browser simply goes quiet, which is the failure this
    module keeps circling."""
    assert "encode_exit" in _agent_class("_ConsoleStream")


def _console_stream_class(fake_console):
    """`_ConsoleStream`, compiled against a stand-in for `modules.console`.

    main.py cannot be imported - it starts collectors and opens sockets - so
    the class is lifted out and given the one name it uses.
    """
    ns = {"console": fake_console}
    exec(_agent_class("_ConsoleStream"), ns)
    return ns["_ConsoleStream"]


class _DeadSession:
    """A shell that has already exited, which is what `read` returning None
    means to `_ConsoleStream`."""
    exit_reason = "the shell exited"

    class proc:
        @staticmethod
        def poll():
            return 0

    def read(self, timeout=0.2):
        return None

    def close(self, why=""):
        pass


def test_a_shell_that_exits_on_its_own_releases_the_one_session_guard():
    """No session type sets `closed` when its shell dies - only `close` does.

    So `_ConsoleStream.read` marking *itself* closed, and `close` then
    returning early on that flag, left the module-level session registered
    and pointing at a dead shell. `open_session` saw it as still open and
    refused every later console on the host as a duplicate, until the 15
    minute idle timeout eventually released it.

    The operator saw none of that. The server fell back to the direct
    addresses and reported *those* as unreachable, so a latched guard read as
    `Connection refused`, and the console worked exactly once per agent
    restart.

    The direct `/console/ws` handler always got this right - it calls
    `close_active` from a `finally`. Two transports, two behaviours, which is
    the thing `_ConsoleStream` exists to stop.
    """
    calls = []

    class FakeConsole:
        @staticmethod
        def open_session():
            return _DeadSession()

        @staticmethod
        def encode_mode(session):
            return "{}"

        @staticmethod
        def encode_exit(code, reason):
            return "{}"

        @staticmethod
        def close_active(why=""):
            calls.append(why)

    stream = _console_stream_class(FakeConsole)()
    stream.read()                 # the mode frame
    assert stream.read() is not None, "the exit frame should still be sent"
    stream.close("the viewer went away")

    assert calls, (
        "the shell had already exited, so close() returned early and the "
        "module-level session was never cleared"
    )


def test_closing_twice_is_harmless():
    """Removing the early return means `close` no longer guards itself, so
    nothing may break if it is called again.

    `_close_stream` pops the stream before closing it, so link.py calls this
    once - but the guard that used to make a second call free is gone, and
    that is worth pinning rather than assuming.
    """
    calls = []

    class FakeConsole:
        @staticmethod
        def open_session():
            return _DeadSession()

        @staticmethod
        def encode_mode(session):
            return "{}"

        @staticmethod
        def encode_exit(code, reason):
            return "{}"

        @staticmethod
        def close_active(why=""):
            calls.append(why)

    stream = _console_stream_class(FakeConsole)()
    stream.close("first")
    stream.close("second")
    # close_active is itself idempotent - it clears `_active` - so calling it
    # again is harmless. What must not happen is it never being called at all.
    assert calls and calls[0] == "first"


def test_the_socket_sends_stream_payloads_as_binary():
    """It serialised everything, so `json.dumps` was handed raw bytes the
    moment anything wrote *to* a stream and raised - which the relay caught as
    "the browser hung up".

    The screen hid it: frames only travel agent-to-server there, so nothing
    ever wrote to a stream. The console did, and looked alive while no
    keystroke had left the server - the browser echoes its own line in pipe
    mode, so the evidence of the failure was invisible.
    """
    code = _handler("agent_link_socket")
    send = code[code.index("async def send"):]
    send = send[:send.index("link = agent_link.AgentLink")]
    assert "bytes" in send
    assert send.index("isinstance") < send.index("pyjson.dumps")


def test_the_http_fallback_is_still_there():
    """Agents are upgraded one at a time. An old binary that cannot open a
    channel has to keep working while the fleet catches up."""
    code = _handler("_agent_proxy")
    assert "_agent_http_bases" in code
    assert "falling back to HTTP" in code
