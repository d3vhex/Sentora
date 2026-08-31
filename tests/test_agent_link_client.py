"""The agent's end of the channel it opens to the server.

The transport changes; the commands do not. Requests arriving on the channel
are dispatched to the same paths the HTTP listener already serves, because two
implementations would drift - and the one that drifted would be the one only
reachable in the deployments that had already moved.

Connecting needs a server, so what is exercised here is everything around it:
the URL it derives, the frames it answers with, and what it does when things
go wrong. Those are the parts that decide whether an agent comes back.
"""

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "Sentora" / "modules" / "link.py"


def _load():
    spec = importlib.util.spec_from_file_location("_link_under_test", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def link():
    return _load()


class Wire:
    """A stand-in for the socket, recording what was sent.

    Text and binary are kept apart because the socket keeps them apart: JSON
    for control, binary for stream payloads.
    """

    def __init__(self):
        self.sent: list[dict] = []
        self.binary: list[bytes] = []

    def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))

    def send_binary(self, payload: bytes) -> None:
        self.binary.append(payload)

    def close(self) -> None:
        pass


def _client(link, dispatch=None, server="http://sentora.example:8000"):
    client = link.AgentLinkClient(
        server, "k" * 64,
        dispatch or (lambda method, path, body: ({"ok": True}, 200)),
        agent_name="web-01")
    client._ws = Wire()
    return client


# --------------------------------------------------------------------------
# Where it connects
# --------------------------------------------------------------------------

@pytest.mark.parametrize("base,expected", [
    ("http://sentora.example:8000", "ws://sentora.example:8000/agent-link"),
    ("https://sentora.example", "wss://sentora.example/agent-link"),
    ("http://10.0.0.5:8000/", "ws://10.0.0.5:8000/agent-link"),
    ("sentora.example:8000", "ws://sentora.example:8000/agent-link"),
])
def test_the_channel_url_comes_from_the_server_url(link, base, expected):
    """Derived, not configured. A second setting is a second thing to get
    wrong, and it would be wrong in exactly the deployments where the first
    one was right."""
    client = link.AgentLinkClient(base, "key", lambda *a: ({}, 200))
    assert client.channel_url() == expected


def test_https_becomes_wss(link):
    """Downgrading a TLS server to an unencrypted channel would hand the
    agent key to anything on the path."""
    client = link.AgentLinkClient("https://sentora.example", "key", lambda *a: ({}, 200))
    assert client.channel_url().startswith("wss://")


# --------------------------------------------------------------------------
# Answering
# --------------------------------------------------------------------------

def test_a_request_is_dispatched_and_answered(link):
    seen = {}

    def dispatch(method, path, body):
        seen.update(method=method, path=path, body=body)
        return {"content": "categories: {}"}, 200

    client = _client(link, dispatch)
    client._answer({"t": "req", "id": "abc", "method": "GET",
                    "path": "/config/rules", "body": None})

    assert seen == {"method": "GET", "path": "/config/rules", "body": None}
    reply = client._ws.sent[0]
    assert reply["t"] == "res"
    assert reply["id"] == "abc"
    assert reply["status"] == 200
    assert reply["body"]["content"] == "categories: {}"


def test_the_reply_carries_the_request_id(link):
    """Two commands can be in flight at once; without the id the server has no
    way to tell which answer belongs to which."""
    client = _client(link)
    client._answer({"t": "req", "id": "first", "method": "GET", "path": "/health"})
    client._answer({"t": "req", "id": "second", "method": "GET", "path": "/health"})
    assert [f["id"] for f in client._ws.sent] == ["first", "second"]


def test_a_handler_that_raises_becomes_a_500_not_a_dropped_channel(link):
    """A command failing is ordinary. Losing the channel over it means the
    agent goes dark until it reconnects, for a bad config push."""
    def explode(method, path, body):
        raise RuntimeError("disk full")

    client = _client(link, explode)
    client._answer({"t": "req", "id": "x", "method": "POST", "path": "/config/rules"})

    reply = client._ws.sent[0]
    assert reply["status"] == 500
    assert "disk full" in reply["body"]["message"]


def test_a_missing_method_defaults_rather_than_failing(link):
    client = _client(link, lambda method, path, body: ({"m": method}, 200))
    client._answer({"t": "req", "id": "x", "path": "/health"})
    assert client._ws.sent[0]["body"]["m"] == "GET"


# --------------------------------------------------------------------------
# Frames it should not act on
# --------------------------------------------------------------------------

def test_noise_is_ignored_rather_than_fatal(link):
    """The other end of this is a network. One bad frame should not cost the
    agent its channel."""
    client = _client(link)
    for raw in ["not json", "[]", json.dumps({"t": "surprise"}),
                json.dumps({"t": "pong"})]:
        client._handle(raw)
    assert client._ws.sent == []


def test_a_request_is_answered_off_the_reader_thread(link):
    """A config write that takes a second must not stop the channel reading,
    or one slow command makes the agent look disconnected while it runs."""
    import inspect

    source = inspect.getsource(link.AgentLinkClient._handle)
    assert "threading.Thread" in source


# --------------------------------------------------------------------------
# Coming back
# --------------------------------------------------------------------------

def test_reconnection_backs_off_with_jitter(link):
    """A fleet upgraded in one push would otherwise reconnect in lockstep,
    against a server that has only just come back up."""
    import inspect

    source = inspect.getsource(link.AgentLinkClient.run_forever)
    assert "random" in source
    assert "RECONNECT_MAX_S" in source


def test_a_clean_session_resets_the_backoff(link):
    """An agent that stayed connected for an hour and then dropped should try
    again in seconds, not in the minute it had backed off to a week ago."""
    import inspect

    source = inspect.getsource(link.AgentLinkClient.run_forever)
    assert "delay = RECONNECT_MIN_S" in source


def test_sending_is_serialised(link):
    """Replies are produced on worker threads, and two frames interleaved on
    one socket is a protocol error rather than a slow response."""
    import inspect

    source = inspect.getsource(link.AgentLinkClient._send)
    assert "_send_lock" in source


def test_the_channel_pings_inside_the_idle_window(link):
    """A NAT in the middle drops an idle socket without telling either end,
    and both then believe the agent is reachable."""
    assert link.PING_INTERVAL_S <= 60


def test_stopping_closes_the_socket(link):
    client = _client(link)
    client.stop()
    assert client._stop.is_set()


def test_an_idle_read_is_matched_by_type_not_by_message(link):
    """The first version looked for "timed out" in the exception text. The day
    that wording changed, an ordinary idle moment would have been read as a
    broken channel - and the symptom would have been an agent reconnecting
    every thirty seconds for no visible reason."""
    import ast
    import inspect
    import textwrap

    # Unparsed, so the comment explaining the old bug - which naturally quotes
    # the string the code must no longer contain - is not what gets matched.
    body = ast.unparse(ast.parse(
        textwrap.dedent(inspect.getsource(link.AgentLinkClient._serve_once))))
    assert "idle_timeouts" in body
    assert "WebSocketTimeoutException" in body
    assert "timed out" not in body


# --------------------------------------------------------------------------
# Streams
# --------------------------------------------------------------------------

def test_the_framing_matches_the_servers(link):
    """Duplicated rather than imported - the agent ships standalone and
    `core/` is optional in it - so the two definitions have to be kept equal
    here, the way `test_encrypt_fields_map.py` does for the field list.

    A version or header that drifted would mean every stream frame silently
    failing to parse on one side, which reads as "the console is broken".
    """
    from core import agent_link as server

    assert link.STREAM_VERSION == server.STREAM_VERSION
    assert link.STREAM_HEADER.format == server.STREAM_HEADER.format
    assert link.MAX_STREAM_FRAME == server.MAX_STREAM_FRAME

    payload = b"\x00\xff round trip"
    assert server.decode_stream_frame(link.encode_stream_frame(3, payload)) == (3, payload)
    assert link.decode_stream_frame(server.encode_stream_frame(3, payload)) == (3, payload)


class FakeStream:
    """Enough of a console for the pump to drive."""

    def __init__(self):
        self.written: list[bytes] = []
        self.chunks = [b"prompt$ ", b"output\n", None]
        self.closed_with = None

    def read(self, timeout=0.2):
        return self.chunks.pop(0) if self.chunks else None

    def write(self, data):
        self.written.append(data)

    def close(self, why=""):
        self.closed_with = why


def test_a_stream_is_opened_and_pumped(link):
    stream = FakeStream()
    client = _client(link)
    client.open_stream = lambda kind, args: stream

    client._open_stream({"t": "open", "ch": 5, "kind": "console", "args": {}})

    kinds = [f.get("t") for f in client._ws.sent]
    assert "stream_opened" in kinds, "the server waits for this before using it"
    assert [link.decode_stream_frame(b) for b in client._ws.binary] == \
        [(5, b"prompt$ "), (5, b"output\n")]
    assert kinds[-1] == "close"


def test_a_stream_that_will_not_open_is_reported(link):
    client = _client(link)

    def refuse(kind, args):
        raise RuntimeError("no shell would start")

    client.open_stream = refuse
    client._open_stream({"t": "open", "ch": 5, "kind": "console"})

    frame = client._ws.sent[-1]
    assert frame["t"] == "stream_failed"
    assert "no shell would start" in frame["why"]


def test_a_build_without_stream_support_says_so(link):
    """Rather than silently accepting an open it will never serve, which the
    server would then wait out as a timeout."""
    client = _client(link)
    client.open_stream = None
    client._open_stream({"t": "open", "ch": 5, "kind": "console"})
    assert client._ws.sent[-1]["t"] == "stream_failed"
    assert "does not serve streams" in client._ws.sent[-1]["why"]


def test_inbound_payloads_reach_the_stream(link):
    stream = FakeStream()
    client = _client(link)
    with client._streams_lock:
        client._streams[7] = stream

    client._handle(link.encode_stream_frame(7, b"ls\n"))
    assert stream.written == [b"ls\n"]


def test_a_payload_for_a_closed_stream_is_dropped(link):
    client = _client(link)
    client._handle(link.encode_stream_frame(99, b"nobody wants this"))
    assert client._ws.sent == []


def test_closing_a_stream_tears_down_the_local_session(link):
    stream = FakeStream()
    client = _client(link)
    with client._streams_lock:
        client._streams[7] = stream

    client._handle(json.dumps({"t": "close", "ch": 7, "why": "viewer left"}))
    assert stream.closed_with == "viewer left"
    with client._streams_lock:
        assert 7 not in client._streams


def test_a_dropped_channel_closes_every_stream(link):
    """A channel number belongs to one connection.

    The server allocates them per link and builds a fresh registry when the
    agent reconnects, so a stream left running produced into the new socket
    under a number nobody had opened:

        [agent-link] DESKTOP-EVS8H9J-3: data for a stream that is gone (ch 1)

    That is the visible half. The costly half is that whatever sat behind the
    stream kept running - a screen capture went on capturing, and a console
    went on holding the one shell this host allows, so every later console
    request was refused as a duplicate of a session nobody was attached to.
    """
    console, screen = FakeStream(), FakeStream()
    client = _client(link)
    with client._streams_lock:
        client._streams[1] = console
        client._streams[2] = screen

    client._close_all_streams("the channel dropped")

    assert console.closed_with == "the channel dropped"
    assert screen.closed_with == "the channel dropped"
    with client._streams_lock:
        assert not client._streams


def test_the_session_teardown_is_what_closes_them(link):
    """In the `finally`, so it runs whether the socket closed cleanly, timed
    out, or raised - a reconnect happens on all three."""
    import ast
    import inspect

    source = inspect.getsource(link.AgentLinkClient._serve_once)
    tree = ast.parse(source.lstrip())
    handler = next(n for n in ast.walk(tree) if isinstance(n, ast.Try) and n.finalbody)
    body = "\n".join(ast.unparse(n) for n in handler.finalbody)
    assert "_close_all_streams" in body
    assert body.index("_close_all_streams") < body.index("ws.close"), \
        "a pump mid-write should find no channel rather than a reconnected one"


def test_a_stream_already_torn_down_is_not_announced(link):
    """The pump's own `finally` tells the server it closed. After
    `_close_all_streams` there is nothing to tell it about, and saying so on
    the next connection names a channel that server has never heard of."""
    client = _client(link)
    client._close_stream(4, "gone already", tell_server=True)
    assert client._ws.sent == []


def test_the_client_library_is_declared():
    """`import websocket` at runtime with nothing in requirements is a crash
    on the endpoint, found by an operator rather than by a build."""
    reqs = (ROOT / "Sentora" / "requirements.txt").read_text(encoding="utf-8")
    assert "websocket-client" in reqs
