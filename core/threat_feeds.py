"""Threat-intel indicator feeds.

`periodic_threat_intel_update` used to insert three hardcoded rows every hour
and its own docstring admitted it: "fetch IoCs from a mock threat intel
source. In production, this would call actual APIs." One of those rows was
the SHA-256 of the empty string, marked CRITICAL malware — had anything ever
matched against that table, every empty file on every endpoint would have
been flagged.

This fetches real indicators instead. Parsing is kept separate from the HTTP
call so the feed shapes can be tested without a network, and every parser is
defensive: a feed that changes its schema yields fewer indicators, never an
exception that kills the refresh loop.

Air-gap follows the same shape as the OSV scanner: THREAT_INTEL_MODE=off
disables the fetch entirely, and each feed URL is overridable so an internal
mirror can serve it.

Note on access: abuse.ch has been moving its downloads behind a free account
key. Set THREAT_INTEL_AUTH_KEY if a feed returns 401/403 — the fetcher reports
the failure per feed rather than silently returning nothing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable

import requests

DEFAULT_TIMEOUT = 30

# Indicators not re-seen in a refresh for this long are pruned. Threat intel
# goes stale: an IP that hosted a C2 last quarter is usually someone else's
# now, and keeping it produces false positives forever.
STALE_AFTER_DAYS = int(os.getenv("THREAT_INTEL_STALE_DAYS", "30"))

# Cap per feed. These lists can run to tens of thousands of entries and this
# table is queried on the alert path.
MAX_PER_FEED = int(os.getenv("THREAT_INTEL_MAX_PER_FEED", "2000"))


@dataclass(frozen=True)
class Indicator:
    type: str          # ip | domain | url | hash
    value: str
    source: str
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW
    description: str


def mode() -> str:
    """off | auto | mirror — mirrors OSV_MODE's shape."""
    return os.getenv("THREAT_INTEL_MODE", "auto").strip().lower()


def _feed_url(name: str, default: str) -> str:
    return os.getenv(f"THREAT_INTEL_{name.upper()}_URL", default).strip()


def _rows(payload: Any) -> Iterable[dict]:
    """Yield dicts from either a list or a dict-of-lists.

    abuse.ch exports are inconsistent: some endpoints return a flat array,
    others an object keyed by id whose values are single-element arrays.
    """
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
    elif isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, dict):
                yield value
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item


def parse_feodo(payload: Any) -> list[Indicator]:
    """Feodo Tracker — botnet C2 IP addresses."""
    out: list[Indicator] = []
    for row in _rows(payload):
        ip = str(row.get("ip_address") or "").strip()
        if not ip:
            continue
        malware = str(row.get("malware") or "unknown").strip()
        port = row.get("port")
        detail = f"{malware} C2" + (f" on port {port}" if port else "")
        out.append(Indicator("ip", ip, "abuse.ch/Feodo", "CRITICAL", detail))
        if len(out) >= MAX_PER_FEED:
            break
    return out


def parse_threatfox(payload: Any) -> list[Indicator]:
    """ThreatFox — mixed IoCs with a confidence score."""
    type_map = {
        "ip:port": "ip", "ip": "ip", "domain": "domain", "url": "url",
        "md5_hash": "hash", "sha256_hash": "hash", "sha1_hash": "hash",
    }
    out: list[Indicator] = []
    for row in _rows(payload):
        raw_value = str(row.get("ioc_value") or row.get("ioc") or "").strip()
        raw_type = str(row.get("ioc_type") or "").strip().lower()
        if not raw_value or raw_type not in type_map:
            continue

        kind = type_map[raw_type]
        # "1.2.3.4:443" — the port is not part of the indicator we match on.
        if kind == "ip" and ":" in raw_value:
            raw_value = raw_value.split(":", 1)[0]

        try:
            confidence = int(row.get("confidence_level") or 0)
        except (TypeError, ValueError):
            confidence = 0
        severity = "CRITICAL" if confidence >= 90 else "HIGH" if confidence >= 50 else "MEDIUM"

        malware = str(row.get("malware_printable") or row.get("threat_type") or "unknown").strip()
        out.append(Indicator(
            kind, raw_value, "abuse.ch/ThreatFox", severity,
            f"{malware} (confidence {confidence}%)",
        ))
        if len(out) >= MAX_PER_FEED:
            break
    return out


def parse_urlhaus(payload: Any) -> list[Indicator]:
    """URLhaus — URLs distributing malware."""
    out: list[Indicator] = []
    for row in _rows(payload):
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        threat = str(row.get("threat") or "malware_download").strip()
        status = str(row.get("url_status") or "").strip().lower()
        # Offline URLs are history, not a live indicator.
        if status == "offline":
            continue
        out.append(Indicator("url", url, "abuse.ch/URLhaus", "HIGH", threat.replace("_", " ")))
        if len(out) >= MAX_PER_FEED:
            break
    return out


FEEDS = {
    "feodo": (
        _feed_url("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.json"),
        parse_feodo,
    ),
    "threatfox": (
        _feed_url("threatfox", "https://threatfox.abuse.ch/export/json/recent/"),
        parse_threatfox,
    ),
    "urlhaus": (
        _feed_url("urlhaus", "https://urlhaus.abuse.ch/downloads/json_recent/"),
        parse_urlhaus,
    ),
}


def enabled_feeds() -> list[str]:
    """Feeds to pull, from THREAT_INTEL_FEEDS or all of them."""
    raw = os.getenv("THREAT_INTEL_FEEDS", "").strip()
    if not raw:
        return list(FEEDS)
    wanted = [f.strip().lower() for f in raw.split(",") if f.strip()]
    return [f for f in wanted if f in FEEDS]


def fetch_all() -> tuple[list[Indicator], list[str]]:
    """Pull every enabled feed.

    Returns (indicators, errors). A failing feed contributes an error string
    and no indicators — it never raises, because one unreachable feed must not
    stop the others or kill the refresh loop.
    """
    if mode() == "off":
        return [], []

    headers = {"User-Agent": "Sentora-ThreatIntel/1.0"}
    auth_key = os.getenv("THREAT_INTEL_AUTH_KEY", "").strip()
    if auth_key:
        headers["Auth-Key"] = auth_key

    indicators: list[Indicator] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()

    for name in enabled_feeds():
        url, parser = FEEDS[name]
        try:
            resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if resp.status_code in (401, 403):
                errors.append(
                    f"{name}: {resp.status_code} — this feed now requires a key. "
                    f"Set THREAT_INTEL_AUTH_KEY (free account at abuse.ch)."
                )
                continue
            if resp.status_code != 200:
                errors.append(f"{name}: HTTP {resp.status_code}")
                continue
            parsed = parser(resp.json())
        except Exception as e:
            errors.append(f"{name}: {e}")
            continue

        for ind in parsed:
            key = (ind.type, ind.value)
            if key in seen:
                continue
            seen.add(key)
            indicators.append(ind)

    return indicators, errors
