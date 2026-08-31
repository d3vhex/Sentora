"""What this agent is.

Deliberately its own file, and deliberately not imported from the server's
`core.version`. The agent ships as a standalone PyInstaller binary that lands
on an endpoint and stays there for months; the server is a container someone
redeploys on a Tuesday. They drift on purpose, so they carry their own numbers
and neither can quietly become the other's.

The agent presents this on the channel handshake as `X-Agent-Version`. The
server records it and answers the first question anyone asks about a
misbehaving fleet - what is actually installed out there - which until now it
could only guess at.

`STREAM_VERSION` in `modules.link` is not this. That is the wire format of a
stream frame; this is the product.
"""

#: This agent. Bump on release, in step with the server only when a release
#: genuinely ships both.
AGENT_VERSION = "1.0.0"
