"""A screen frame must not be able to starve a config reply.

Symptom, from a real host: the Config tab returned

    DESKTOP-EVS8H9J-3 did not answer GET /config/rules within 5s

while the agent was connected, healthy, and shipping telemetry the whole time.
`cmd_get_config` opens a small YAML file and reads it — microseconds. The
agent's own log had no record of the request, because a reply that is never
sent logs nothing.

Both sides were behaving. The channel multiplexes two very different kinds of
traffic down one websocket:

    control    a request and its reply, small, and something is waiting on it
    stream     console output and screen frames, large, and continuous

and one `_send_lock` serialises them, because two frames interleaved on one
socket is a protocol error. So a screen pump sending a full screenshot every
200ms competed for the same lock as every config read, restart and health
check — and it never stopped competing, because a screen capture has no
natural end and nothing told it to stop when the viewer went away.

Worse, `PING_INTERVAL_S` was doing two unrelated jobs: the ping cadence *and*
the socket timeout handed to `create_connection`. One `send_binary` the
network was slow to accept could hold the only send lock for thirty seconds,
against control requests whose deadline is five.

The asymmetry the fix rests on: **a stream frame is stale the moment it is
delayed, and a control reply is not.** The next capture supersedes the frame
that could not get onto the wire; nothing supersedes the answer somebody is
waiting for.
"""
from __future__ import annotations

import pathlib
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = ROOT / "Sentora" / "modules" / "link.py"

FRAME = b"\x00\x00\x00\x01payload"


@pytest.fixture
def client():
    """A real `AgentLinkClient` with no network under it."""
    import sys

    sys.path.insert(0, str(ROOT / "Sentora"))
    from modules.link import AgentLinkClient

    return AgentLinkClient("http://server:8000", "key", lambda *a: ({}, 200))


class _SlowSocket:
    """A websocket whose binary sends block, the way a saturated one does.

    Only `send_binary` stalls. Text frames carry the control traffic whose
    latency is under test, and making those slow too would measure the fake
    socket rather than the lock discipline.
    """

    def __init__(self, delay: float):
        self.delay = delay
        self.sent: list = []
        self.releasing = threading.Event()

    def send(self, payload):          # control frames
        self.sent.append(("text", payload))

    def send_binary(self, payload):   # stream payloads
        self.releasing.wait(self.delay)
        self.sent.append(("binary", payload))


def test_a_reply_waits_for_at_most_one_stream_frame(client):
    """The guarantee, stated honestly.

    A frame already on the wire cannot be recalled, so a reply can always be
    delayed by that one. What it must never wait behind is a *queue* of them —
    and it used to, because a capture that never ends produces frames faster
    than a slow link drains them and every one took the same lock.

    So: two stream frames and a reply, the first frame stalled. The reply has
    to go out when that frame completes, not after both.
    """
    sock = _SlowSocket(delay=1.0)
    client._ws = sock

    threading.Thread(target=lambda: client._send(FRAME, droppable=True),
                     daemon=True).start()
    time.sleep(0.2)                     # let it take the lock and stall

    # A second frame arrives while the first is still going, the way a 200ms
    # capture loop produces them.
    threading.Thread(target=lambda: client._send(FRAME, droppable=True),
                     daemon=True).start()
    time.sleep(0.05)

    started = time.monotonic()
    client._send({"t": "res", "id": "abc", "status": 200, "body": {"ok": True}})
    waited = time.monotonic() - started

    assert waited < 1.8, (
        f"the reply waited {waited:.1f}s - long enough to have queued behind "
        f"more than the one frame already on the wire"
    )
    assert [k for k, _ in sock.sent].count("text") == 1, "the reply never went out"


def test_a_stream_frame_yields_while_a_reply_is_waiting(client):
    """Python locks are not fair. A pump producing a frame every 200ms wins
    the race often enough to push a reply past the server's five seconds, so
    the pump stands down rather than competing on equal terms."""
    sock = _SlowSocket(delay=2.0)
    client._ws = sock

    threading.Thread(target=lambda: client._send(FRAME, droppable=True),
                     daemon=True).start()
    time.sleep(0.2)

    reply = threading.Thread(
        target=lambda: client._send({"t": "res", "id": "a", "status": 200, "body": {}}),
        daemon=True)
    reply.start()
    time.sleep(0.1)                     # the reply is now queued for the wire

    before = client._dropped_frames
    client._send(FRAME, droppable=True)
    assert client._dropped_frames == before + 1, \
        "a stream frame queued ahead of a reply that was already waiting"

    sock.releasing.set()
    reply.join(timeout=5)


def test_a_control_frame_is_never_dropped(client):
    """The other half. Dropping a reply would produce the same timeout by a
    quieter route, with nothing logged either."""
    sock = _SlowSocket(delay=0.0)
    sock.releasing.set()
    client._ws = sock

    client._send({"t": "res", "id": "abc", "status": 200, "body": {}})
    assert [kind for kind, _ in sock.sent] == ["text"]


def test_the_socket_deadline_is_not_the_ping_cadence():
    """`PING_INTERVAL_S` was passed as `create_connection(timeout=...)`, so
    "ping every 30s" silently also meant "any single send may block for 30
    seconds" — six times the deadline of the requests behind it."""
    source = LINK.read_text(encoding="utf-8")
    assert "SOCKET_TIMEOUT_S" in source, \
        "the socket deadline and the ping cadence are still the same number"

    connect = source[source.index("websocket.create_connection("):]
    connect = connect[:connect.index(")")]
    assert "PING_INTERVAL_S" not in connect, \
        "the connection still takes its deadline from the ping interval"


def test_the_pump_stops_when_its_stream_is_gone():
    """An orphaned pump is what made any of this reachable.

    The server printed "data for a stream that is gone" and did nothing else,
    so an agent whose viewer had closed kept capturing and sending for the
    life of the connection — competing for the send lock with every control
    request, for ever, on behalf of nobody.
    """
    source = LINK.read_text(encoding="utf-8")
    pump = source[source.index("    def _open_stream"):]
    pump = pump[:pump.index("    def _close_stream")]
    assert "_streams.get(channel) is stream" in pump, \
        "the pump does not notice that its own stream was closed under it"


def test_the_server_tells_the_agent_about_an_orphaned_stream():
    """Printing it locally leaves the agent pumping. The close has to travel."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    loop = app_py[app_py.index("async def agent_link_socket"):]
    loop = loop[:loop.index("def _validate_agent_auth_sync")]

    orphan = loop[loop.index("deliver_stream("):]
    orphan = orphan[:orphan.index("continue")]
    assert '"t": "close"' in orphan, \
        "the agent is never told its stream is gone, so it keeps sending"


def test_the_orphan_notice_is_sent_once_per_channel():
    """Frames already in flight arrive after the close. One line and one
    close each would be the noisiest thing in the log at exactly the moment
    somebody is reading it."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    loop = app_py[app_py.index("async def agent_link_socket"):]
    loop = loop[:loop.index("def _validate_agent_auth_sync")]
    assert "orphaned" in loop
    assert "orphaned.add(channel)" in loop
