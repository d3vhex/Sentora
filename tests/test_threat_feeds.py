"""Tests for threat-intel feed parsing.

Parsing is tested without the network because that is where the risk is: a
feed that changes shape must yield fewer indicators, never an exception that
kills the hourly refresh loop, and never a malformed indicator that becomes a
false positive on every endpoint.
"""
from __future__ import annotations

import pytest

from core import threat_feeds as tf


# --------------------------------------------------------------------------
# Feodo — botnet C2 IPs
# --------------------------------------------------------------------------

def test_feodo_extracts_ips_with_malware_family():
    payload = [
        {"ip_address": "1.2.3.4", "malware": "Emotet", "port": 443},
        {"ip_address": "5.6.7.8", "malware": "Dridex"},
    ]
    out = tf.parse_feodo(payload)

    assert [i.value for i in out] == ["1.2.3.4", "5.6.7.8"]
    assert all(i.type == "ip" and i.severity == "CRITICAL" for i in out)
    assert "Emotet" in out[0].description and "443" in out[0].description


def test_feodo_skips_rows_without_an_address():
    assert tf.parse_feodo([{"malware": "Emotet"}, {"ip_address": ""}]) == []


# --------------------------------------------------------------------------
# ThreatFox — mixed IoCs
# --------------------------------------------------------------------------

def test_threatfox_handles_the_dict_of_lists_shape():
    """Some abuse.ch exports key by id with single-element array values."""
    payload = {
        "12345": [{"ioc_value": "9.9.9.9", "ioc_type": "ip:port", "confidence_level": 100,
                   "malware_printable": "Cobalt Strike"}],
    }
    out = tf.parse_threatfox(payload)
    assert len(out) == 1
    assert out[0].value == "9.9.9.9"


def test_threatfox_strips_the_port_from_an_ip_indicator():
    """We match on addresses; "1.2.3.4:443" would never equal an observed IP."""
    out = tf.parse_threatfox([{"ioc_value": "1.2.3.4:8080", "ioc_type": "ip:port",
                               "confidence_level": 100}])
    assert out[0].value == "1.2.3.4"
    assert out[0].type == "ip"


@pytest.mark.parametrize("confidence,expected", [(100, "CRITICAL"), (90, "CRITICAL"),
                                                 (75, "HIGH"), (50, "HIGH"), (10, "MEDIUM")])
def test_threatfox_maps_confidence_to_severity(confidence, expected):
    out = tf.parse_threatfox([{"ioc_value": "evil.test", "ioc_type": "domain",
                               "confidence_level": confidence}])
    assert out[0].severity == expected


def test_threatfox_ignores_unknown_indicator_types():
    out = tf.parse_threatfox([{"ioc_value": "x", "ioc_type": "something_new"}])
    assert out == []


# --------------------------------------------------------------------------
# URLhaus
# --------------------------------------------------------------------------

def test_urlhaus_skips_offline_urls():
    """An offline URL is history, not a live indicator."""
    payload = [
        {"url": "http://live.test/x.exe", "threat": "malware_download", "url_status": "online"},
        {"url": "http://dead.test/y.exe", "threat": "malware_download", "url_status": "offline"},
    ]
    out = tf.parse_urlhaus(payload)
    assert [i.value for i in out] == ["http://live.test/x.exe"]


# --------------------------------------------------------------------------
# Robustness — the property that keeps the refresh loop alive
# --------------------------------------------------------------------------

@pytest.mark.parametrize("parser", [tf.parse_feodo, tf.parse_threatfox, tf.parse_urlhaus])
@pytest.mark.parametrize("junk", [
    None, [], {}, "", 0, [None], [[]], [{"unexpected": "shape"}],
    {"k": None}, {"k": "not-a-dict"}, [{"ip_address": None}],
])
def test_parsers_never_raise_on_malformed_input(parser, junk):
    """A feed changing its schema must degrade, not crash the hourly loop."""
    assert isinstance(parser(junk), list)


@pytest.mark.parametrize("parser,key,type_key", [
    (tf.parse_feodo, "ip_address", None),
    (tf.parse_urlhaus, "url", None),
])
def test_per_feed_cap_is_enforced(parser, key, type_key, monkeypatch):
    """These lists run to tens of thousands and the table is read on the
    alert path."""
    monkeypatch.setattr(tf, "MAX_PER_FEED", 10)
    payload = [{key: f"10.0.0.{i}", "malware": "x", "url_status": "online"} for i in range(200)]
    assert len(parser(payload)) <= 10


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def test_mode_off_short_circuits_the_fetch(monkeypatch):
    """Air-gap installs must make no outbound request at all."""
    monkeypatch.setenv("THREAT_INTEL_MODE", "off")

    def explode(*a, **k):
        raise AssertionError("fetch_all made a request while disabled")

    monkeypatch.setattr(tf.requests, "get", explode)
    assert tf.fetch_all() == ([], [])


def test_enabled_feeds_defaults_to_all(monkeypatch):
    monkeypatch.delenv("THREAT_INTEL_FEEDS", raising=False)
    assert set(tf.enabled_feeds()) == set(tf.FEEDS)


def test_enabled_feeds_honours_the_allow_list(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "feodo, nonexistent")
    assert tf.enabled_feeds() == ["feodo"]


def test_fetch_all_reports_auth_failures_without_raising(monkeypatch):
    """A key requirement should tell the operator what to do, not vanish."""
    monkeypatch.setenv("THREAT_INTEL_MODE", "auto")
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "feodo")

    class Resp:
        status_code = 403
        def json(self): return {}

    monkeypatch.setattr(tf.requests, "get", lambda *a, **k: Resp())
    indicators, errors = tf.fetch_all()

    assert indicators == []
    assert len(errors) == 1
    assert "THREAT_INTEL_AUTH_KEY" in errors[0]


def test_one_failing_feed_does_not_stop_the_others(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_MODE", "auto")
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "feodo,urlhaus")

    class Ok:
        status_code = 200
        def json(self): return [{"url": "http://x.test/a", "url_status": "online"}]

    def get(url, **k):
        if "feodo" in url:
            raise ConnectionError("unreachable")
        return Ok()

    monkeypatch.setattr(tf.requests, "get", get)
    indicators, errors = tf.fetch_all()

    assert len(indicators) == 1
    assert len(errors) == 1


def test_duplicate_indicators_across_feeds_are_collapsed(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_MODE", "auto")
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "feodo,threatfox")

    class Resp:
        def __init__(self, body): self._b = body
        status_code = 200
        def json(self): return self._b

    def get(url, **k):
        if "feodo" in url:
            return Resp([{"ip_address": "1.1.1.1", "malware": "Emotet"}])
        return Resp([{"ioc_value": "1.1.1.1", "ioc_type": "ip", "confidence_level": 100}])

    monkeypatch.setattr(tf.requests, "get", get)
    indicators, _ = tf.fetch_all()

    assert len(indicators) == 1, "the same address was stored twice"
