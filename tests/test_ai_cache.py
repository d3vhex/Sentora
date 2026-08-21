"""Tests for the AI verdict cache key and timeout handling.

The cache had no TTL and no notion of a prompt version, so a single bad answer
was served forever and the only way to clear one was to drop the table. These
pin the properties that fix, and — more importantly — the property that must
NOT change: the key stays tied to the exact prompt, because a cache hit from a
different event is a missed detection.
"""
from __future__ import annotations

import pytest

from ai import utils


class FakeResp:
    status_code = 200

    def __init__(self, body="verdict"):
        self._body = body

    def json(self):
        return {"response": self._body}


@pytest.fixture
def captured(monkeypatch):
    """Record what gets written to the cache instead of touching MySQL."""
    writes: dict[str, str] = {}
    reads: list[str] = []

    monkeypatch.setattr(utils, "set_ai_cache",
                        lambda agent, h, r: writes.__setitem__(h, r))

    def _get(agent, h):
        reads.append(h)
        return None

    monkeypatch.setattr(utils, "get_ai_cache", _get)
    monkeypatch.setattr(utils.requests, "post", lambda *a, **k: FakeResp())
    return writes, reads


def _run(**kwargs):
    defaults = dict(
        api_key="x", text="a log line", prompt_template="analyse: {log_text}",
        endpoint="http://127.0.0.1:11434/api", agent="AGENT1", model="llama3.2:3b",
    )
    defaults.update(kwargs)
    return utils.analyze_with_ai(**defaults)


def test_identical_input_produces_one_key(captured):
    writes, _ = captured
    _run()
    _run()
    assert len(writes) == 1


def test_different_log_text_does_not_share_a_key(captured):
    """The property that keeps a cache hit from becoming a missed detection.

    "failed login from 10.0.0.5" must not be answered by the verdict for
    "failed login from 10.0.0.7".
    """
    writes, _ = captured
    _run(text="failed login from 10.0.0.5")
    _run(text="failed login from 10.0.0.7")
    assert len(writes) == 2


def test_changing_the_model_changes_the_key(captured):
    writes, _ = captured
    _run(model="llama3.2:3b")
    _run(model="qwen2.5:7b")
    assert len(writes) == 2


def test_changing_the_prompt_template_changes_the_key(captured):
    writes, _ = captured
    _run(prompt_template="analyse: {log_text}")
    _run(prompt_template="triage strictly: {log_text}")
    assert len(writes) == 2


def test_prompt_version_invalidates_the_cache(captured, monkeypatch):
    """Bumping AI_PROMPT_VERSION must retire every stored verdict."""
    writes, _ = captured
    monkeypatch.setattr(utils, "PROMPT_VERSION", "v1")
    _run()
    monkeypatch.setattr(utils, "PROMPT_VERSION", "v2")
    _run()
    assert len(writes) == 2


def test_key_is_sha256_hex(captured):
    writes, _ = captured
    _run()
    key = next(iter(writes))
    assert len(key) == 64
    int(key, 16)


def test_no_cache_lookup_without_an_agent(captured):
    """The cache is per-agent; a call with no agent must not read or write."""
    writes, reads = captured
    _run(agent=None)
    assert reads == []
    assert writes == {}


def test_timeout_returns_a_diagnostic_instead_of_raising(monkeypatch):
    """The worker must never crash on a slow model — it has to persist a row
    saying what happened."""
    import requests

    def boom(*a, **k):
        raise requests.Timeout()

    monkeypatch.setattr(utils.requests, "post", boom)
    monkeypatch.setattr(utils, "get_ai_cache", lambda *a: None)

    out = _run()
    assert isinstance(out, str)
    assert "timed out" in out.lower()


def test_timeout_is_passed_to_requests(monkeypatch):
    """A ten-minute timeout is a hang, not a timeout. Pin that the configured
    value actually reaches the HTTP call."""
    seen = {}

    def capture(url, **kwargs):
        seen.update(kwargs)
        return FakeResp()

    monkeypatch.setattr(utils.requests, "post", capture)
    monkeypatch.setattr(utils, "get_ai_cache", lambda *a: None)
    monkeypatch.setattr(utils, "set_ai_cache", lambda *a: None)
    monkeypatch.setattr(utils, "AI_TIMEOUT_SEC", 42)

    _run()
    assert seen.get("timeout") == 42


def test_a_cache_hit_skips_the_model_entirely(monkeypatch):
    monkeypatch.setattr(utils, "get_ai_cache", lambda agent, h: "cached verdict")

    def explode(*a, **k):
        raise AssertionError("called the model despite a cache hit")

    monkeypatch.setattr(utils.requests, "post", explode)
    assert _run() == "cached verdict"
