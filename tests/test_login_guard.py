"""Client address resolution and login lockout.

Two holes with the same shape: the platform recorded what happened and did
nothing with it.

`login_logs` held a row for every failed login and nothing read it. bcrypt at
cost 12 was the only brake on online guessing - detection without response.

X-Forwarded-For was believed unconditionally. With no reverse proxy in front
the header is attacker-supplied, so the address in the audit trail was
whatever they chose: log injection into the SIEM's own audit log, and a
per-address limit that resets itself on request.
"""
from __future__ import annotations

import types

import pytest

from core import login_guard


def req(peer="203.0.113.9", forwarded=None):
    headers = {"X-Forwarded-For": forwarded} if forwarded else {}
    return types.SimpleNamespace(
        conn_info=types.SimpleNamespace(peername=(peer, 51234)),
        headers=types.SimpleNamespace(get=lambda k, d="": headers.get(k, d)),
        ip=peer,
    )


# --------------------------------------------------------------------------
# Address resolution
# --------------------------------------------------------------------------

def test_a_spoofed_header_is_ignored_with_no_proxy_configured(monkeypatch):
    """The default. Nothing in front of us, so the peer is the client."""
    monkeypatch.setattr(login_guard, "_TRUSTED", [])
    assert login_guard.client_ip(req(peer="198.51.100.7",
                                     forwarded="1.2.3.4")) == "198.51.100.7"


def test_a_trusted_proxy_is_believed(monkeypatch):
    import ipaddress
    monkeypatch.setattr(login_guard, "_TRUSTED",
                        [ipaddress.ip_network("10.0.0.0/8")])
    assert login_guard.client_ip(req(peer="10.0.0.5",
                                     forwarded="1.2.3.4")) == "1.2.3.4"


def test_an_untrusted_peer_is_not_believed_even_when_a_proxy_exists(monkeypatch):
    import ipaddress
    monkeypatch.setattr(login_guard, "_TRUSTED",
                        [ipaddress.ip_network("10.0.0.0/8")])
    assert login_guard.client_ip(req(peer="198.51.100.7",
                                     forwarded="1.2.3.4")) == "198.51.100.7"


def test_only_the_leftmost_entry_is_taken(monkeypatch):
    import ipaddress
    monkeypatch.setattr(login_guard, "_TRUSTED",
                        [ipaddress.ip_network("10.0.0.0/8")])
    assert login_guard.client_ip(
        req(peer="10.0.0.5", forwarded="1.2.3.4, 10.0.0.5")) == "1.2.3.4"


def test_a_header_that_is_not_an_address_falls_back_to_the_peer(monkeypatch):
    """Otherwise the audit log takes arbitrary text as an IP."""
    import ipaddress
    monkeypatch.setattr(login_guard, "_TRUSTED",
                        [ipaddress.ip_network("10.0.0.0/8")])
    for junk in ("not-an-ip", "'; DROP TABLE login_logs--", ""):
        assert login_guard.client_ip(
            req(peer="10.0.0.5", forwarded=junk)) == "10.0.0.5"


def test_a_bad_trusted_proxies_value_does_not_trust_everything(monkeypatch):
    monkeypatch.setattr(login_guard, "TRUSTED_PROXIES", "not-a-cidr")
    assert login_guard._trusted_networks() == []


# --------------------------------------------------------------------------
# Lockout
# --------------------------------------------------------------------------

def test_below_the_limits_nothing_happens():
    assert login_guard.lockout_reason(by_user=1, by_ip=1) is None


def test_the_account_limit_locks():
    reason = login_guard.lockout_reason(
        by_user=login_guard.MAX_FAILURES_PER_USER, by_ip=0)
    assert reason and "account" in reason


def test_the_address_limit_locks():
    """Spraying many accounts from one host never trips the per-account limit."""
    reason = login_guard.lockout_reason(
        by_user=1, by_ip=login_guard.MAX_FAILURES_PER_IP)
    assert reason and "address" in reason


def test_the_account_limit_is_tighter_than_the_address_limit():
    """One office behind one NAT address must not lock itself out as fast as
    a single account under attack."""
    assert login_guard.MAX_FAILURES_PER_USER < login_guard.MAX_FAILURES_PER_IP


class _Cursor:
    def __init__(self, row=None, raises=False):
        self.row, self.raises, self.sql = row, raises, None

    async def execute(self, sql, params=()):
        if self.raises:
            raise RuntimeError("login_logs is gone")
        self.sql = " ".join(sql.split())

    async def fetchone(self):
        return self.row


@pytest.mark.asyncio
async def test_check_counts_only_failures_in_the_window():
    cur = _Cursor(row=(0, 0))
    await login_guard.check(cur, "alice", "203.0.113.9")
    assert "status = 'failure'" in cur.sql
    assert "INTERVAL %s MINUTE" in cur.sql


@pytest.mark.asyncio
async def test_check_fails_open_when_the_table_is_unavailable():
    """A login page that cannot be reached because the audit table is down is
    its own outage, and the password check still stands behind this."""
    assert await login_guard.check(_Cursor(raises=True), "alice", "1.2.3.4") is None


@pytest.mark.asyncio
async def test_check_locks_on_the_counted_failures():
    cur = _Cursor(row=(login_guard.MAX_FAILURES_PER_USER, 0))
    assert await login_guard.check(cur, "alice", "1.2.3.4") is not None
