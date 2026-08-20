"""Unit tests for the proxy destination rules.

DNS is injected, so these exercise the real decision logic without touching
the network or needing PROXY_ALLOWED_HOSTS to resolve to anything.
"""
from __future__ import annotations

import ipaddress
import socket

import pytest

from security import ssrf


@pytest.fixture
def allow(monkeypatch):
    """Set PROXY_ALLOWED_HOSTS for one test."""
    def _set(*hosts: str):
        monkeypatch.setenv("PROXY_ALLOWED_HOSTS", ",".join(hosts))
    return _set


def resolving_to(*addresses: str):
    """A resolver stub that maps every host to the given addresses."""
    def _resolver(host, port):
        return [ipaddress.ip_address(a) for a in addresses]
    return _resolver


PUBLIC = resolving_to("93.184.216.34")


def test_proxy_is_disabled_until_hosts_are_configured(monkeypatch):
    """The endpoint must be inert on a default install — an SSRF primitive
    that is on by default is one nobody decided to accept."""
    monkeypatch.setenv("PROXY_ALLOWED_HOSTS", "")
    err = ssrf.check_target("https://example.com/x", resolver=PUBLIC)
    assert err is not None and "disabled" in err


def test_allowlisted_public_host_passes(allow):
    allow("example.com")
    assert ssrf.check_target("https://example.com/hook", resolver=PUBLIC) is None


def test_host_not_on_the_allowlist_is_refused(allow):
    allow("example.com")
    err = ssrf.check_target("https://evil.com/", resolver=PUBLIC)
    assert err == "Host not allowed: evil.com"


def test_allowlist_match_is_case_insensitive(allow):
    allow("Example.COM")
    assert ssrf.check_target("https://EXAMPLE.com/", resolver=PUBLIC) is None


def test_subdomain_does_not_inherit_the_parent_entry(allow):
    """`example.com` must not implicitly permit `evil.example.com`."""
    allow("example.com")
    err = ssrf.check_target("https://evil.example.com/", resolver=PUBLIC)
    assert err == "Host not allowed: evil.example.com"


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://example.com/",
    "ftp://example.com/",
    "//example.com/",
])
def test_non_http_schemes_are_refused(allow, url):
    allow("example.com")
    err = ssrf.check_target(url, resolver=PUBLIC)
    assert err is not None and ("Scheme not allowed" in err or "no host" in err)


@pytest.mark.parametrize("addr,label", [
    ("169.254.169.254", "cloud metadata"),
    ("127.0.0.1", "loopback"),
    ("0.0.0.0", "this host"),
    ("::1", "ipv6 loopback"),
    ("fe80::1", "ipv6 link-local"),
])
def test_blocked_addresses_win_over_the_allowlist(allow, addr, label):
    """The DNS-rebinding case: the name is allowlisted, the address is not.

    An allowlist alone cannot stop this, which is why the address check runs
    after resolution rather than trusting the hostname.
    """
    allow("metadata.evil.com")
    err = ssrf.check_target("http://metadata.evil.com/", resolver=resolving_to(addr))
    assert err is not None, f"{label} ({addr}) was allowed through"
    assert "blocked address" in err


def test_any_resolved_address_being_blocked_refuses_the_request(allow):
    """A host resolving to both a public and a blocked address is refused —
    otherwise the connection races into the blocked one."""
    allow("dual.example.com")
    err = ssrf.check_target(
        "http://dual.example.com/",
        resolver=resolving_to("93.184.216.34", "169.254.169.254"),
    )
    assert err is not None and "blocked address" in err


def test_ordinary_private_ranges_stay_reachable(allow):
    """`jira.internal` on 10/8 is the case this proxy exists for."""
    allow("jira.internal")
    assert ssrf.check_target("http://jira.internal/api", resolver=resolving_to("10.1.2.3")) is None


def test_port_scoped_allowlist_entry(allow):
    allow("jira.internal:8080")
    ok = ssrf.check_target("http://jira.internal:8080/", resolver=resolving_to("10.1.2.3"))
    assert ok is None

    # The bare host was never allowed, so the default port must not sneak in.
    err = ssrf.check_target("http://jira.internal/", resolver=resolving_to("10.1.2.3"))
    assert err == "Host not allowed: jira.internal"


def test_unresolvable_host_is_reported_not_raised(allow):
    allow("example.com")

    def boom(host, port):
        raise socket.gaierror("no such host")

    err = ssrf.check_target("https://example.com/", resolver=boom)
    assert err is not None and "Cannot resolve" in err


@pytest.mark.parametrize("url", [None, "", 123, "not-a-url"])
def test_malformed_input_is_refused(allow, url):
    allow("example.com")
    assert ssrf.check_target(url, resolver=PUBLIC) is not None


def test_request_headers_that_could_leak_credentials_are_stripped():
    cleaned = ssrf.clean_request_headers({
        "Authorization": "Bearer third-party-token",
        "Host": "internal-vhost",
        "Cookie": "sentora_session=stolen",
        "X-Agent-Key": "agent-secret",
        "X-User-ID": "1",
        "Content-Type": "application/json",
    })

    assert "Content-Type" in cleaned
    # An explicit Authorization for the destination is the point of the proxy.
    assert "Authorization" in cleaned
    for banned in ("Host", "Cookie", "X-Agent-Key", "X-User-ID"):
        assert banned not in cleaned


def test_set_cookie_is_never_relayed_back_to_the_browser():
    """A proxied third party must not be able to set cookies on this origin."""
    cleaned = ssrf.clean_response_headers({
        "Set-Cookie": "evil=1; Path=/",
        "Content-Encoding": "gzip",
        "Transfer-Encoding": "chunked",
        "ETag": 'W/"abc"',
        "Date": "Wed, 20 Aug 2026 00:00:00 GMT",
    })

    assert cleaned == {"ETag": 'W/"abc"', "Date": "Wed, 20 Aug 2026 00:00:00 GMT"}


def test_timeout_is_clamped_into_range(monkeypatch):
    monkeypatch.setenv("PROXY_TIMEOUT_CAP", "15")
    assert ssrf.clamp_timeout(600) == 15
    assert ssrf.clamp_timeout(0) == 1
    assert ssrf.clamp_timeout(-5) == 1
    assert ssrf.clamp_timeout(10) == 10
    assert ssrf.clamp_timeout("garbage") == 15
    assert ssrf.clamp_timeout(None) == 15
