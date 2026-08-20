"""Destination validation for the operator-facing HTTP proxy.

`POST /_proxy/http` exists so playbook nodes can reach third-party endpoints
that do not send CORS headers. That makes it a server-side request forgery
primitive by construction: the caller supplies the URL and gets the response
body back. Session auth and the `manage_system` permission narrow *who* can
use it; this module narrows *where* it can go.

Three layers, in order:

1. Scheme allowlist — `file://`, `gopher://` and friends never reach requests.
2. Host allowlist — `PROXY_ALLOWED_HOSTS`, empty by default, so the endpoint
   is inert until an operator names the destinations they actually integrate
   with.
3. Address check — the resolved IPs are rejected if they land on loopback or
   link-local, regardless of the allowlist. Cloud metadata (169.254.169.254)
   and the container's own listeners are never a legitimate destination, and
   an allowlisted name that resolves there is the textbook DNS-rebinding
   bypass of layer 2.

Other private ranges (10/8, 172.16/12, 192.168/16) are deliberately allowed:
an internal ticketing system on `jira.internal` is exactly the case this proxy
is for, and the operator naming it in the allowlist is the decision point.

Kept separate from app.py so the rules are unit-testable without a running
server — see tests/test_ssrf.py.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})

ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})

# Never reachable, allowlist or not.
BLOCKED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),      # this container
    ipaddress.ip_network("169.254.0.0/16"),   # cloud instance metadata
    ipaddress.ip_network("0.0.0.0/8"),        # "this host" per RFC 1122
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
)

# Request headers the caller may not set. `Host` enables virtual-host
# confusion against the destination; the rest are either connection-scoped or
# would forward this server's own credentials to a third party.
STRIPPED_REQUEST_HEADERS = frozenset({
    "host", "content-length", "connection", "transfer-encoding",
    "upgrade", "cookie", "x-agent-key", "x-user-id",
})

# Response headers echoed back to the browser. Everything else is dropped:
# `Set-Cookie` would let a proxied third party set cookies on this origin, and
# the framing headers describe a body that has already been decoded.
SAFE_RESPONSE_HEADERS = frozenset({
    "content-language", "date", "etag", "last-modified", "cache-control",
})


def allowed_hosts() -> frozenset[str]:
    """Destinations the operator has opted into.

    Read per call rather than cached at import so tests (and a future config
    reload) can change it without re-importing the module.
    """
    raw = os.getenv("PROXY_ALLOWED_HOSTS", "")
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def max_response_bytes() -> int:
    return int(os.getenv("PROXY_MAX_BYTES", str(5 * 1024 * 1024)))


def timeout_cap() -> int:
    return int(os.getenv("PROXY_TIMEOUT_CAP", "15"))


def _resolve(host: str, port: int) -> list[ipaddress._BaseAddress]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def check_target(url: str, *, resolver=_resolve) -> str | None:
    """Validate a proxy destination. Returns an error string, or None if allowed.

    `resolver` is injectable so tests can exercise the address rules without
    depending on DNS.
    """
    if not url or not isinstance(url, str):
        return "URL required"

    try:
        parsed = urlparse(url)
    except Exception:
        return "Malformed URL"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return f"Scheme not allowed: {scheme or '(none)'}"

    try:
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        # urlparse defers port parsing, so a bad port only raises here.
        return "Malformed URL (invalid port)"

    if not host:
        return "URL has no host"

    permitted = allowed_hosts()
    if not permitted:
        return "HTTP proxy is disabled (PROXY_ALLOWED_HOSTS is empty)"

    if host not in permitted and (port is None or f"{host}:{port}" not in permitted):
        return f"Host not allowed: {host}"

    resolve_port = port or (443 if scheme == "https" else 80)
    try:
        addresses = resolver(host, resolve_port)
    except socket.gaierror as e:
        return f"Cannot resolve {host}: {e}"
    except Exception as e:
        return f"Resolution failed for {host}: {e}"

    if not addresses:
        return f"Cannot resolve {host}"

    for addr in addresses:
        for net in BLOCKED_NETWORKS:
            if addr.version == net.version and addr in net:
                return f"{host} resolves to a blocked address ({addr})"

    return None


def clean_request_headers(headers) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    return {
        str(k): str(v) for k, v in headers.items()
        if str(k).lower() not in STRIPPED_REQUEST_HEADERS
    }


def clean_response_headers(headers) -> dict[str, str]:
    return {
        k: v for k, v in dict(headers).items()
        if k.lower() in SAFE_RESPONSE_HEADERS
    }


def clamp_timeout(value) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        seconds = 15
    return max(1, min(seconds, timeout_cap()))
