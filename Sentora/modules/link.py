"""The agent's end of the channel it opens to the server.

The server never dials this host. It asks over a socket opened from here, so
there is no port to open on the endpoint, no address for the server to guess,
and eventually nothing listening at all. `core/agent_link.py` on the server
side has the full list of what that removes.

Shape
-----
One websocket, held open, reconnecting on its own. The server sends

    {"t": "req", "id": "...", "method": "GET", "path": "/config/rules",
     "body": {...}}

and this answers

    {"t": "res", "id": "...", "status": 200, "body": {...}}

`path` is deliberately the same path the HTTP listener already serves, and
requests are dispatched to the same handlers. That is what makes this a change
of transport rather than a second implementation of every command - two
implementations would drift, and the one that drifted would be the one only
reachable in the deployments that had already moved.

What it does not do
-------------------
Streams - the console and the screen - still use their own sockets. They are
long-lived and carry binary at rate, and multiplexing them onto this channel
is a separate piece of work rather than something to fold in quietly.

Reconnecting
------------
Backoff, capped, with jitter. A fleet restarted at once would otherwise
reconnect in lockstep and arrive as a thundering herd on a server that has
just come up - and the agents most likely to be restarted together are the
ones a single push just upgraded.
"""

from __future__ import annotations

import json
import random
import struct
import threading
import time

# Stream framing, duplicated from `core/agent_link.py` rather than imported.
#
# The agent ships as a standalone binary and `core/` is optional in it -
# `log_extractor` already guards its own core imports for exactly that reason.
# A transport that only works when an optional package happens to be bundled
# is a transport that fails on the deployments least able to diagnose it.
#
# `tests/test_agent_link_client.py` keeps the two definitions equal, the same
# way `test_encrypt_fields_map.py` does for the encrypted-field list.
STREAM_HEADER = struct.Struct("!BI")     # version, channel
STREAM_VERSION = 1
MAX_STREAM_FRAME = 32 * 1024 * 1024


def encode_stream_frame(channel: int, payload: bytes) -> bytes:
    """One stream payload, tagged with the channel it belongs to."""
    return STREAM_HEADER.pack(STREAM_VERSION, int(channel)) + payload


def decode_stream_frame(raw: bytes):
    """`(channel, payload)`, or None when this is not one of ours."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < STREAM_HEADER.size:
        return None
    version, channel = STREAM_HEADER.unpack(raw[:STREAM_HEADER.size])
    if version != STREAM_VERSION:
        return None
    payload = bytes(raw[STREAM_HEADER.size:])
    if len(payload) > MAX_STREAM_FRAME:
        return None
    return channel, payload

# The server closes an idle socket eventually, and a NAT in between will do it
# sooner and without saying so. A ping well inside both keeps the channel from
# dying quietly while both ends believe it is up.
PING_INTERVAL_S = 30.0

RECONNECT_MIN_S = 2.0
RECONNECT_MAX_S = 60.0

# Long enough for a config write on a slow disk; short enough that a wedged
# handler does not hold the channel's reader thread forever.
HANDLER_TIMEOUT_S = 30.0


class AgentLinkClient:
    """Holds one channel open and answers what arrives on it.

    `dispatch(method, path, body) -> (body, status)` is supplied by the
    caller, so this module knows nothing about what the commands mean.
    """

    def __init__(self, server_url: str, agent_key: str, dispatch,
                 *, agent_name: str = "", open_stream=None):
        self.server_url = (server_url or "").rstrip("/")
        self.agent_key = agent_key
        self.dispatch = dispatch
        # `open_stream(kind, args) -> object with read/write/close`, supplied
        # by the caller so this module stays ignorant of what a console or a
        # screen actually is.
        self.open_stream = open_stream
        self.agent_name = agent_name
        self._stop = threading.Event()
        self._ws = None
        self._send_lock = threading.Lock()
        self._streams: dict[int, object] = {}
        self._streams_lock = threading.Lock()
        self.connected = False
        self.last_error = ""

    # -- addressing --------------------------------------------------------

    def channel_url(self) -> str:
        """The websocket URL, derived from the server's HTTP base.

        Derived rather than configured: a second setting is a second thing to
        get wrong, and it would be wrong in exactly the deployments where the
        first one was right.
        """
        base = self.server_url
        if base.startswith("https://"):
            return "wss://" + base[len("https://"):] + "/agent-link"
        if base.startswith("http://"):
            return "ws://" + base[len("http://"):] + "/agent-link"
        return "ws://" + base + "/agent-link"

    # -- lifecycle ---------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                ws.close()
            except Exception as e:
                print(f"[link] could not close the channel: {e}", flush=True)

    def run_forever(self) -> None:
        """Connect, serve, reconnect. Returns only when `stop` is called."""
        delay = RECONNECT_MIN_S
        while not self._stop.is_set():
            try:
                self._serve_once()
                delay = RECONNECT_MIN_S      # a clean session resets the backoff
            except Exception as e:
                self.last_error = str(e)
                print(f"[link] channel closed: {e}", flush=True)

            if self._stop.is_set():
                return

            # Jittered, so a fleet upgraded in one push does not reconnect in
            # lockstep against a server that has only just come back.
            wait = min(delay, RECONNECT_MAX_S)
            self._stop.wait(wait * (0.5 + random.random()))
            delay = min(delay * 2, RECONNECT_MAX_S)

    # -- one session -------------------------------------------------------

    def _serve_once(self) -> None:
        import socket
        import websocket          # websocket-client, sync

        # The exceptions an idle read raises, by type. `WebSocketTimeoutException`
        # is what the library raises; `socket.timeout` is what it wraps and
        # what some versions let through.
        idle_timeouts = (websocket.WebSocketTimeoutException, socket.timeout)

        url = self.channel_url()
        ws = websocket.create_connection(
            url, header=[f"X-Agent-Key: {self.agent_key}"],
            timeout=PING_INTERVAL_S)
        self._ws = ws
        self.connected = True
        self.last_error = ""
        print(f"[link] connected to {url}", flush=True)

        last_ping = time.monotonic()
        try:
            while not self._stop.is_set():
                try:
                    raw = ws.recv()
                except idle_timeouts:
                    # The quiet case, not a failure: an idle read is how this
                    # loop gets its chance to send a ping.
                    #
                    # Matched on the exception type, not on the message. The
                    # first version looked for "timed out" in the text, which
                    # would have treated an ordinary idle moment as a broken
                    # channel the day that wording changed - and the symptom
                    # would have been an agent reconnecting every thirty
                    # seconds for no visible reason.
                    raw = None

                if raw:
                    self._handle(raw)

                now = time.monotonic()
                if now - last_ping >= PING_INTERVAL_S:
                    self._send({"t": "ping"})
                    last_ping = now
        finally:
            self.connected = False
            self._ws = None
            # Before the socket, so a pump that is mid-write finds no channel
            # rather than a reconnected one.
            self._close_all_streams("the channel dropped")
            try:
                ws.close()
            except Exception as e:
                # The session is over either way and the reconnect does not
                # depend on this, but a socket that will not close is a file
                # descriptor the agent keeps for the rest of its life.
                print(f"[link] socket would not close: {e}", flush=True)

    def _send(self, frame) -> None:
        ws = self._ws
        if ws is None:
            return
        # Serialised: replies and stream payloads are produced on worker
        # threads, and two frames interleaved on one socket is a protocol
        # error rather than a slow response.
        with self._send_lock:
            if isinstance(frame, (bytes, bytearray)):
                ws.send_binary(bytes(frame))
            else:
                ws.send(json.dumps(frame))

    def _handle(self, raw) -> None:
        # Binary means stream payload; the socket keeps the two apart so
        # nothing has to be inspected to tell them apart.
        if isinstance(raw, (bytes, bytearray)):
            self._handle_stream_payload(bytes(raw))
            return

        try:
            frame = json.loads(raw)
        except Exception:
            print("[link] ignoring a frame that is not JSON", flush=True)
            return
        if not isinstance(frame, dict):
            return

        kind = frame.get("t")
        if kind == "pong":
            return
        if kind == "open":
            threading.Thread(target=self._open_stream, args=(frame,),
                             daemon=True).start()
            return
        if kind == "close":
            self._close_stream(frame.get("ch"), frame.get("why") or "closed")
            return
        if kind != "req":
            print(f"[link] ignoring an unknown frame type {kind!r}", flush=True)
            return

        # On its own thread. A config write that takes a second must not stop
        # this channel reading, or one slow command makes the agent look
        # disconnected for as long as it runs.
        threading.Thread(target=self._answer, args=(frame,), daemon=True).start()

    # -- streams -----------------------------------------------------------

    def _handle_stream_payload(self, raw: bytes) -> None:
        parsed = decode_stream_frame(raw)
        if parsed is None:
            print("[link] ignoring a stream frame this build cannot read",
                  flush=True)
            return
        channel, payload = parsed
        with self._streams_lock:
            stream = self._streams.get(channel)
        if stream is None:
            # The server is sending to a stream this end has already torn
            # down. Dropping is right - the close is already on its way - but
            # it is worth one line, because a flood of these means the two
            # sides disagree about what is open.
            print(f"[link] payload for a stream that is gone (ch {channel})",
                  flush=True)
            return
        try:
            stream.write(payload)
        except Exception as e:
            self._close_stream(channel, f"writing to the stream failed: {e}")

    def _open_stream(self, frame: dict) -> None:
        """Start a console or a screen and pump it back down the channel."""
        channel = frame.get("ch")
        kind = str(frame.get("kind") or "")
        args = frame.get("args") if isinstance(frame.get("args"), dict) else {}

        if self.open_stream is None:
            self._send({"t": "stream_failed", "ch": channel,
                        "why": "this agent build does not serve streams over "
                               "the channel"})
            return

        try:
            stream = self.open_stream(kind, args)
        except Exception as e:
            print(f"[link] could not open a {kind}: {e}", flush=True)
            self._send({"t": "stream_failed", "ch": channel, "why": str(e)})
            return

        with self._streams_lock:
            self._streams[channel] = stream
        # Opened, not merely asked for. The server waits on this, because "the
        # frame was sent" and "the agent has a shell" are different facts.
        self._send({"t": "stream_opened", "ch": channel})

        why = "the stream ended"
        try:
            while not self._stop.is_set():
                chunk = stream.read(0.2)
                if chunk is None:
                    why = getattr(stream, "exit_reason", "") or why
                    break
                if chunk:
                    self._send(encode_stream_frame(channel, chunk))
        except Exception as e:
            why = f"the stream failed: {e}"
            print(f"[link] {kind} stream failed: {e}", flush=True)
        finally:
            self._close_stream(channel, why, tell_server=True)

    def _close_stream(self, channel, why: str = "", *, tell_server: bool = False) -> None:
        with self._streams_lock:
            stream = self._streams.pop(channel, None)
        if stream is not None:
            try:
                stream.close(why)
            except Exception as e:
                print(f"[link] could not close stream {channel}: {e}", flush=True)
        # Only announce a stream this end actually had. A pump whose stream
        # was already torn down by `_close_all_streams` would otherwise send a
        # close for it on the *next* connection, where the number means
        # nothing to a server that has built a fresh registry.
        if tell_server and stream is not None:
            self._send({"t": "close", "ch": channel, "why": why})

    def _close_all_streams(self, why: str) -> None:
        """End every stream when the session does.

        A channel number belongs to one connection: the server allocates it
        per link and builds a fresh registry when the agent reconnects.
        Leaving streams running across a reconnect meant their pumps went on
        producing into the new socket under numbers nobody had opened -

            [agent-link] DESKTOP-EVS8H9J-3: data for a stream that is gone (ch 1)

        - which is the visible half. The costly half is that whatever was
        behind them kept running: a screen capture went on capturing, and a
        console went on holding the one shell this host allows, so every later
        console request was refused as a duplicate of a session nobody was
        attached to.
        """
        with self._streams_lock:
            channels = list(self._streams)
        for channel in channels:
            self._close_stream(channel, why)
        if channels:
            print(f"[link] closed {len(channels)} stream(s): {why}", flush=True)

    def _answer(self, frame: dict) -> None:
        request_id = frame.get("id")
        method = str(frame.get("method") or "GET").upper()
        path = str(frame.get("path") or "")
        try:
            body, status = self.dispatch(method, path, frame.get("body"))
        except Exception as e:
            print(f"[link] {method} {path} failed: {e}", flush=True)
            body, status = {"status": "error", "message": str(e)}, 500

        try:
            self._send({"t": "res", "id": request_id,
                        "status": int(status), "body": body})
        except Exception as e:
            # The channel went while this was being answered. The server has
            # already failed the request on its side, so there is nothing to
            # retry - the reconnect will bring a fresh one.
            print(f"[link] could not answer {method} {path}: {e}", flush=True)
