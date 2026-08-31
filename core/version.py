"""What this server is, and what it will work with.

The agent and the server ship separately - one is a PyInstaller binary that
lands on an endpoint and stays there, the other is a container someone
redeploys - so they are versioned separately and drift on purpose. Nothing in
this repository recorded either, which meant the platform could not answer the
first question anyone asks about a misbehaving fleet: what is actually
installed out there.

It showed most sharply when the server stopped dialling agents. An agent that
cannot be commanded is now told so in a message that has to *guess* why -
"the usual cause is an agent binary older than the channel" - because the
server had no way to know. With a version on the handshake that stops being a
guess.

`STREAM_VERSION` in `core.agent_link` is deliberately not this. That is the
wire format of a stream frame and it changes when the bytes change; this is
the product, and it changes when a release ships. Conflating them would mean
a UI-only release forcing a protocol bump, or a frame change hiding inside a
patch number.
"""

from __future__ import annotations

import re

#: This server. Bump on release.
SERVER_VERSION = "1.0.0"

#: The oldest agent this server knows how to talk to.
#:
#: Advisory, never enforced. See `agent_support` for why refusing a connection
#: on version would be the wrong move now that there is no second route to an
#: endpoint.
MIN_AGENT_VERSION = "1.0.0"

#: Agents at or above this are current; below it they still work, and the
#: console says they are behind.
CURRENT_AGENT_VERSION = SERVER_VERSION

# A version arrives over the network from an endpoint, so it is untrusted
# text. Bounded and validated before it reaches a log line or a database.
_VERSION_RE = re.compile(r"^\d{1,4}(\.\d{1,4}){0,3}([-+][0-9A-Za-z.\-]{1,32})?$")
MAX_VERSION_LEN = 48


def is_valid_version(value: str | None) -> bool:
    """Whether this is a version we are willing to record and compare."""
    if not value or len(value) > MAX_VERSION_LEN:
        return False
    return bool(_VERSION_RE.match(value))


def parse_version(value: str | None) -> tuple[int, ...]:
    """`"1.2.3"` -> `(1, 2, 3)`, and anything unusable -> `()`.

    Total by design: a malformed version from an endpoint is a thing to
    notice, not a thing to raise on inside a websocket handshake.

    Build metadata and pre-release suffixes are dropped rather than ordered.
    Ordering them correctly is a spec of its own, and this comparison exists
    to answer "is that agent behind", which suffixes do not change.
    """
    if not is_valid_version(value):
        return ()
    core = re.split(r"[-+]", value, maxsplit=1)[0]
    try:
        return tuple(int(part) for part in core.split("."))
    except ValueError:
        return ()


def _padded(a: tuple[int, ...], b: tuple[int, ...]):
    """Compare `1.2` against `1.2.0` as equal rather than as shorter."""
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def compare(left: str | None, right: str | None) -> int:
    """-1, 0 or 1. An unparseable version sorts below every real one."""
    a, b = parse_version(left), parse_version(right)
    if not a and not b:
        return 0
    if not a:
        return -1
    if not b:
        return 1
    a, b = _padded(a, b)
    return (a > b) - (a < b)


def agent_support(reported: str | None) -> tuple[str, str]:
    """Classify an agent by the version it reported. Returns (state, detail).

    States:
      current      at or above what this server ships with
      behind       older, and still fully supported
      unsupported  below MIN_AGENT_VERSION - expect things not to work
      unknown      it did not report one, so it predates versioning entirely

    Nothing here refuses a connection, and that is deliberate. The server no
    longer has a second route to an endpoint: turning an old agent away would
    make it permanently unreachable *and* unupgradeable, which is a worse
    outcome than talking to it and saying so. Version is a diagnosis, not an
    access control - the access control is the key it presented.
    """
    if not is_valid_version(reported):
        return ("unknown", "reported no version; it predates version reporting")
    if compare(reported, MIN_AGENT_VERSION) < 0:
        return ("unsupported",
                f"{reported} is below the minimum this server supports "
                f"({MIN_AGENT_VERSION}); it will connect, but expect gaps")
    if compare(reported, CURRENT_AGENT_VERSION) < 0:
        return ("behind", f"{reported}, current is {CURRENT_AGENT_VERSION}")
    return ("current", reported)
