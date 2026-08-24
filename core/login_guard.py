"""Client address resolution and login lockout.

Two separate holes with one thing in common: the platform was recording what
happened and doing nothing about it.

**Failed logins were counted and never acted on.** `login_logs` has a row for
every failure, `audit_logs` has another, and nothing read either. bcrypt at
cost 12 was the only brake on an online guessing attack - roughly 3 attempts a
second per connection, and nothing stopped a thousand connections. Detection
without response.

**X-Forwarded-For was trusted unconditionally.** With no reverse proxy in
front, the header is attacker-supplied, so the address written into the audit
trail is whatever they chose. That is log injection into the SIEM's own audit
log, and it also defeats any per-IP limit built on top of it: change the
header, get a fresh budget.

The counters live in `login_logs` rather than in memory. The table is already
written on every attempt, the rows survive a restart, and Sanic runs several
workers - an in-process dict would divide the limit by the worker count and
reset whenever the server did.
"""

from __future__ import annotations

import ipaddress
import os

# Hosts whose X-Forwarded-For may be believed. Empty means "no proxy in front
# of us", which is the safe default: the peer address is then the only thing
# used, and a spoofed header changes nothing.
#
# Set TRUSTED_PROXIES to a comma-separated list of addresses or CIDRs when
# deploying behind nginx, a load balancer or an ingress controller.
TRUSTED_PROXIES = os.getenv("TRUSTED_PROXIES", "").strip()

# Attempts allowed per window, counted separately for the account and for the
# source address. The account limit stops guessing one password everywhere;
# the address limit stops spraying many accounts from one host.
MAX_FAILURES_PER_USER = int(os.getenv("LOGIN_MAX_FAILURES_USER", "5"))
MAX_FAILURES_PER_IP = int(os.getenv("LOGIN_MAX_FAILURES_IP", "20"))
LOCKOUT_WINDOW_MIN = int(os.getenv("LOGIN_LOCKOUT_WINDOW_MIN", "15"))


def _trusted_networks():
    nets = []
    for raw in TRUSTED_PROXIES.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            print(f"[!] TRUSTED_PROXIES: {raw!r} is not an address or CIDR, ignored",
                  flush=True)
    return nets


_TRUSTED = _trusted_networks()


def peer_address(request) -> str:
    """The address we are actually talking to, ignoring any header."""
    info = getattr(request, "conn_info", None)
    peer = getattr(info, "peername", None) if info else None
    if peer:
        return str(peer[0])
    return getattr(request, "ip", None) or "unknown"


def client_ip(request) -> str:
    """The client's address, believing X-Forwarded-For only from a trusted peer.

    Returns the peer address when there is no trusted proxy configured, which
    is what makes the value usable both as an audit record and as a rate-limit
    key. Taking the header unconditionally - which is what this replaced -
    means an attacker writes their own entry in the audit log and resets their
    own rate limit in the same request.
    """
    peer = peer_address(request)
    if not _TRUSTED:
        return peer

    try:
        peer_addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(peer_addr in net for net in _TRUSTED):
        return peer

    forwarded = request.headers.get("X-Forwarded-For", "")
    if not forwarded:
        return peer
    # Left-most entry is the original client. Everything after it was added by
    # intermediaries and is only as trustworthy as they are.
    candidate = forwarded.split(",")[0].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return peer
    return candidate


LOCKOUT_SQL = """
SELECT
    SUM(username = %s)   AS by_user,
    SUM(ip_address = %s) AS by_ip
FROM login_logs
WHERE status = 'failure'
  AND `timestamp` > (NOW() - INTERVAL %s MINUTE)
  AND (username = %s OR ip_address = %s)
"""


def lockout_reason(by_user: int, by_ip: int) -> str | None:
    """Which limit was exceeded, or None. Split out so it can be tested
    without a database."""
    if by_user >= MAX_FAILURES_PER_USER:
        return (f"{by_user} failed attempts for this account in the last "
                f"{LOCKOUT_WINDOW_MIN} minutes")
    if by_ip >= MAX_FAILURES_PER_IP:
        return (f"{by_ip} failed attempts from this address in the last "
                f"{LOCKOUT_WINDOW_MIN} minutes")
    return None


async def check(cursor, username: str, ip: str) -> str | None:
    """Return a lockout reason, or None to let the attempt proceed.

    Fails open on a database error. A login page that cannot be reached
    because the audit table is unavailable is its own outage, and the password
    check still stands behind this.
    """
    try:
        await cursor.execute(
            LOCKOUT_SQL,
            (username, ip, LOCKOUT_WINDOW_MIN, username, ip),
        )
        row = await cursor.fetchone()
    except Exception as e:
        print(f"[!] login lockout check unavailable, allowing attempt: {e}",
              flush=True)
        return None
    if not row:
        return None
    by_user = int(row[0] or 0)
    by_ip = int(row[1] or 0)
    return lockout_reason(by_user, by_ip)
