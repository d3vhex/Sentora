"""A channel the agent opens, so the server never has to dial it.

Why
---
Every server-to-agent feature used to work by the server making an HTTP
connection *to* the endpoint: config reads, SOAR dispatch, the screen stream,
the console. That was one design decision, and this is the list of things it
cost:

  - the agent's own reported address was wrong behind NAT, so we preferred
    the observed one
  - the observed one is a *router* when the server is containerised on the
    agent's machine, so we had to detect our own gateway and fall back
  - neither is reachable from a container under Docker Desktop, so
    `host.docker.internal` became a third candidate
  - Windows blocks the inbound port and cannot prompt for it, because the
    agent is a service in session 0, so the installer added a firewall rule
  - `ufw` on Linux needed the same
  - and every endpoint ran a management API on 0.0.0.0:9099 with
    `/self_destruct` on it, which is a thing an EDR adds to a host rather
    than removes

None of those are bugs in each other. They are the same bug, once, in the
direction of the connection.

All of it is gone with the dialling. A host that can reach the server can be
managed, and one that cannot was never reachable anyway - so there is no port
to open, no address to guess, and, since the agent's listener was removed
along with the fallback that needed it, nothing on the endpoint listening at
all.

What this module is
-------------------
The server half: a registry of connected agents and the request/response
plumbing over their channels. It knows nothing about websockets - it is given
a `send` callable - so it can be tested without a network, which is most of
what is worth testing here.

One process
-----------
A registry of live sockets cannot span processes, and Sanic runs a worker per
CPU unless told otherwise. An agent's channel therefore exists in exactly one
worker, and a request handled by another would find nothing - intermittently,
depending on which worker happened to take it.

`WORKERS=1` is what docker-compose.yaml has always said, and `app.py` now
actually reads it. Sharing the registry between workers means putting the
frames on the broker instead, which is a different design and not one to slip
in unannounced; until then the server warns when it starts with more than one.

Three properties are load-bearing:

**A request that is never answered must not wait forever.** An agent can be
killed mid-command; the caller is an HTTP handler with an operator behind it.

**A disconnect must fail every request in flight.** Leaving them pending is
how a console spins forever on an agent that has gone.

**Pending requests are bounded.** The reply is what removes an entry, so an
agent that accepts work and never answers would otherwise grow the map until
the server dies - and that agent is exactly the one a compromised host would
be.
"""

from __future__ import annotations

import asyncio
import struct
import time
import uuid

# Long enough for a config read on a busy endpoint, short enough that an
# operator is not left watching a spinner over a host that has gone quiet.
DEFAULT_TIMEOUT_S = 20.0

# Refused rather than queued past this. A caller that cannot be served now is
# better told so: the alternative is an unbounded map fed by whatever the
# agent chooses not to answer.
MAX_PENDING_PER_AGENT = 64

# One console and one screen is the honest ceiling; a few more leaves room for
# a reconnecting viewer whose old stream has not been reaped yet. Bounded for
# the same reason as the pending map: the peer is an endpoint, and an endpoint
# that opens streams and never closes them is the one worth being careful of.
MAX_STREAMS_PER_AGENT = 8

# Frames held for a reader that is not keeping up. Small on purpose: for a
# screen the newest frame is the only one worth having, and a deep queue turns
# a slow viewer into latency nobody can explain.
STREAM_BACKLOG = 32


#: Stream payloads travel as *binary* websocket frames on the same socket,
#: tagged with a four-byte channel number. Control - open, close, and the
#: request/response traffic above - stays as JSON text frames.
#:
#: The obvious alternative was base64 inside the JSON, and it is the wrong one
#: for the thing that actually moves: a screen stream at ten frames a second
#: would pay a third more bandwidth for the encoding, on the connection most
#: likely to be the constrained one. A websocket already distinguishes text
#: from binary, so the receiver can tell them apart without inspecting
#: anything.
STREAM_HEADER = struct.Struct("!BI")     # version, channel
STREAM_VERSION = 1

# A single stream frame larger than this is a desynchronised sender, not a
# screenshot. Believing the number would mean allocating whatever it said.
MAX_STREAM_FRAME = 32 * 1024 * 1024


class LinkError(Exception):
    """The channel could not carry this, with a reason fit for an operator."""


def encode_stream_frame(channel: int, payload: bytes) -> bytes:
    """One stream payload, tagged with the channel it belongs to."""
    return STREAM_HEADER.pack(STREAM_VERSION, int(channel)) + payload


def decode_stream_frame(raw: bytes) -> tuple[int, bytes] | None:
    """`(channel, payload)`, or None when this is not one of ours.

    None rather than an exception: the peer is an endpoint, and a frame this
    cannot read must not take down the channel every other command shares.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < STREAM_HEADER.size:
        return None
    version, channel = STREAM_HEADER.unpack(raw[:STREAM_HEADER.size])
    if version != STREAM_VERSION:
        return None
    payload = bytes(raw[STREAM_HEADER.size:])
    if len(payload) > MAX_STREAM_FRAME:
        return None
    return channel, payload


class AgentLink:
    """One connected agent, and the requests in flight to it."""

    def __init__(self, agent: str, send, *, now=time.monotonic):
        self.agent = agent
        self._send = send
        self._now = now
        self.connected_at = now()
        self.last_seen = self.connected_at
        self._pending: dict[str, asyncio.Future] = {}
        self._streams: dict[int, StreamChannel] = {}
        self._next_channel = 0
        self._closed = False
        self.close_reason = ""

    # -- state -------------------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def touch(self) -> None:
        """Note that the agent said something. Any frame counts as liveness."""
        self.last_seen = self._now()

    # -- requests ----------------------------------------------------------

    async def request(self, method: str, path: str, body=None,
                      timeout: float = DEFAULT_TIMEOUT_S) -> tuple[dict, int]:
        """Ask the agent for something and wait for its answer.

        Returns `(body, status)` in the shape `_agent_proxy` already speaks,
        so callers do not have to care which transport carried it.
        """
        if self._closed:
            raise LinkError(f"{self.agent} is not connected")
        if len(self._pending) >= MAX_PENDING_PER_AGENT:
            raise LinkError(
                f"{self.agent} has {len(self._pending)} requests already "
                f"waiting and is not answering; refusing to queue more")

        request_id = uuid.uuid4().hex
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future

        try:
            await self._send({
                "t": "req", "id": request_id,
                "method": method, "path": path, "body": body,
            })
        except Exception as e:
            self._pending.pop(request_id, None)
            raise LinkError(f"could not reach {self.agent}: {e}")

        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            raise LinkError(
                f"{self.agent} did not answer {method} {path} within "
                f"{timeout:g}s")
        finally:
            # Always, including the timeout path: the entry is what bounds
            # this map, and a request nobody is waiting for any more is one
            # the agent's late reply should simply be dropped for.
            self._pending.pop(request_id, None)

    def deliver(self, frame: dict) -> bool:
        """Hand a `res` frame to whoever is waiting. False if nobody is.

        A reply that arrives after its caller gave up is not an error - the
        agent was slow, the timeout did its job - so this reports rather than
        raises, and the caller logs it if it wants to.
        """
        self.touch()
        request_id = str(frame.get("id") or "")
        future = self._pending.pop(request_id, None)
        if future is None or future.done():
            return False

        body = frame.get("body")
        if not isinstance(body, dict):
            body = {"status": "error", "message": "agent sent a malformed body"}
            status = 502
        else:
            try:
                status = int(frame.get("status", 200))
            except (TypeError, ValueError):
                status = 502
        future.set_result((body, status))
        return True

    # -- streams -----------------------------------------------------------

    async def open_stream(self, kind: str, args: dict | None = None,
                          timeout: float = 15.0) -> StreamChannel:
        """Ask the agent to start a console or a screen, and wait for it.

        Waiting matters: "the frame was sent" and "the agent has a shell" are
        different facts, and the console spent a while reporting the first as
        though it were the second.
        """
        if self._closed:
            raise LinkError(f"{self.agent} is not connected")
        if len(self._streams) >= MAX_STREAMS_PER_AGENT:
            raise LinkError(
                f"{self.agent} already has {len(self._streams)} streams open")

        self._next_channel += 1
        channel = self._next_channel
        stream = StreamChannel(self, channel, kind)
        self._streams[channel] = stream

        try:
            await self._send({"t": "open", "ch": channel, "kind": kind,
                              "args": args or {}})
        except Exception as e:
            self._streams.pop(channel, None)
            raise LinkError(f"could not ask {self.agent} for a {kind}: {e}")

        try:
            await asyncio.wait_for(stream.opened, timeout)
        except asyncio.TimeoutError:
            self.close_stream(channel, f"the agent did not open a {kind} "
                                       f"within {timeout:g}s")
            raise LinkError(f"{self.agent} did not open a {kind} within "
                            f"{timeout:g}s")
        return stream

    async def send_stream(self, channel: int, payload: bytes) -> None:
        await self._send(encode_stream_frame(channel, payload))

    def deliver_stream(self, channel: int, payload: bytes) -> bool:
        """Route an inbound stream payload. False if nothing wants it."""
        self.touch()
        stream = self._streams.get(channel)
        if stream is None or stream.closed:
            return False
        stream.deliver(payload)
        return True

    def stream_opened(self, channel: int) -> None:
        stream = self._streams.get(channel)
        if stream is not None and not stream.opened.done():
            stream.opened.set_result(True)

    def stream_failed(self, channel: int, reason: str) -> None:
        stream = self._streams.get(channel)
        if stream is not None and not stream.opened.done():
            stream.opened.set_exception(LinkError(reason))
        self.close_stream(channel, reason)

    def close_stream(self, channel: int, reason: str = "") -> None:
        """Forget a stream this end already knows is over.

        Local only, deliberately: this is what the agent's own `close` frame
        and a dropped link both land on, and telling the agent about a stream
        it just told us about would be a loop.

        A viewer going away is the other case, and it needs `end_stream`.
        """
        stream = self._streams.pop(channel, None)
        if stream is not None:
            stream.close(reason)

    async def end_stream(self, channel: int, reason: str = "") -> None:
        """Close a stream *and tell the agent*.

        The relay's teardown used `close_stream`, which only forgot it here.
        The agent kept the session open, so the shell stayed running with
        nobody attached - and because a console is one-per-host, every later
        request was refused as a duplicate of a session no one could reach.
        The console worked exactly once per agent restart.
        """
        self.close_stream(channel, reason)
        if self._closed:
            return
        try:
            await self._send({"t": "close", "ch": channel, "why": reason})
        except Exception as e:
            # The link went with the viewer. The agent notices the socket drop
            # and tears its side down on its own, so nothing is leaked - but
            # it is worth a line, because the tidy path did not run.
            print(f"[agent-link] could not tell {self.agent} to close stream "
                  f"{channel}: {e}", flush=True)

    # -- teardown ----------------------------------------------------------

    def close(self, reason: str = "") -> None:
        """Mark the channel gone and fail everything waiting on it.

        Failing them is the point. A pending request whose agent has
        disconnected will never be answered, and leaving it to time out means
        an operator watches a spinner for twenty seconds over a fact the
        server already knows.
        """
        if self._closed:
            return
        self._closed = True
        self.close_reason = reason or "the agent disconnected"

        for request_id, future in list(self._pending.items()):
            self._pending.pop(request_id, None)
            if not future.done():
                future.set_exception(LinkError(
                    f"{self.agent} disconnected while the request was in "
                    f"flight ({self.close_reason})"))

        # Streams too. A console left open on a link that has gone would sit
        # there accepting keystrokes into nothing.
        for channel in list(self._streams):
            self.close_stream(channel, self.close_reason)


class StreamChannel:
    """One long-lived stream - a console or a screen - inside the channel.

    Reading is a queue rather than a callback so a relay can `await` it the
    same way it awaits a websocket, which is what lets the console and screen
    proxies keep the shape they already have.
    """

    def __init__(self, link: "AgentLink", channel: int, kind: str):
        self.link = link
        self.channel = channel
        self.kind = kind
        self.opened = asyncio.get_running_loop().create_future()
        self._inbox: asyncio.Queue = asyncio.Queue(maxsize=STREAM_BACKLOG)
        self._closed = False
        self.close_reason = ""

    @property
    def closed(self) -> bool:
        return self._closed

    async def send(self, payload: bytes) -> None:
        """Push data to the agent's end of this stream."""
        if self._closed:
            raise LinkError(f"the {self.kind} stream is closed")
        await self.link.send_stream(self.channel, payload)

    async def receive(self, timeout: float | None = None) -> bytes | None:
        """The next payload, or None once the stream has ended."""
        if self._closed and self._inbox.empty():
            return None
        try:
            if timeout is None:
                item = await self._inbox.get()
            else:
                item = await asyncio.wait_for(self._inbox.get(), timeout)
        except asyncio.TimeoutError:
            return b""
        return item

    def deliver(self, payload: bytes) -> None:
        """Called by the link when data arrives for this stream.

        A full inbox drops the oldest frame rather than blocking the channel.
        Every other command shares this socket, and a browser that has stopped
        reading its screen stream must not be able to stall a config push -
        for a screen, the newest frame is the only one worth having anyway.
        """
        if self._closed:
            return
        if self._inbox.full():
            # `full()` and `get_nowait()` are not one operation, but this is
            # the only consumer of the drop path and both run on the event
            # loop, so nothing can empty the queue in between. Written as a
            # condition rather than a swallowed exception because there is no
            # failure here to hide - if it were somehow empty, there would be
            # room, which is what we were after.
            if not self._inbox.empty():
                self._inbox.get_nowait()
        self._inbox.put_nowait(payload)

    def close(self, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        self.close_reason = reason or "the stream ended"
        if not self.opened.done():
            self.opened.set_exception(LinkError(self.close_reason))
        # Wake a reader waiting on an empty queue. A full queue needs no
        # sentinel: the reader has frames to work through and will see
        # `closed` when it drains them, so there is nothing being swallowed by
        # not forcing one in.
        if not self._inbox.full():
            self._inbox.put_nowait(None)


class LinkRegistry:
    """Which agents are connected right now."""

    def __init__(self):
        self._links: dict[str, AgentLink] = {}

    def register(self, link: AgentLink) -> AgentLink | None:
        """Add a link, returning the one it replaced.

        A second connection for the same agent replaces the first rather than
        being refused: the usual cause is a network drop the agent noticed
        before the server did, and refusing would leave it locked out behind a
        socket that is already dead. The caller closes what comes back.
        """
        previous = self._links.get(link.agent)
        self._links[link.agent] = link
        return previous

    def unregister(self, link: AgentLink) -> bool:
        """Remove this link, if it is still the current one for its agent.

        Identity-checked, because a slow teardown of a replaced connection
        must not remove the replacement - the reconnect would look successful
        and the agent would appear offline.
        """
        current = self._links.get(link.agent)
        if current is not link:
            return False
        del self._links[link.agent]
        return True

    def get(self, agent: str) -> AgentLink | None:
        link = self._links.get(agent)
        if link is not None and link.closed:
            return None
        return link

    def connected(self) -> list[str]:
        return sorted(a for a, link in self._links.items() if not link.closed)

    def close_all(self, reason: str = "server shutting down") -> None:
        for link in list(self._links.values()):
            link.close(reason)
        self._links.clear()
