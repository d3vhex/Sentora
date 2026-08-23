"""Tests for compose-service address translation.

The bug this prevents cost two debugging sessions in different scripts:
`.env` is written for containers, so host-side tooling inherits `DB_HOST=db`
and `OLLAMA_BASE_URL=http://ollama:11434/api` and then reports a DNS failure
that reads as "the service is down".

The risk in the fix is the opposite one - rewriting too eagerly. A service
with no published port is genuinely unreachable from the host, and turning
its clear "cannot resolve" into a confusing "connection refused on localhost"
would be a worse error, not a better one. Most of what is pinned here is that
boundary.
"""
from __future__ import annotations

import pytest

from core import netloc


@pytest.fixture
def on_host(monkeypatch):
    monkeypatch.setattr(netloc, "in_container", lambda: False)


@pytest.fixture
def in_container(monkeypatch):
    monkeypatch.setattr(netloc, "in_container", lambda: True)


# --------------------------------------------------------------------------
# The failures that prompted this
# --------------------------------------------------------------------------

def test_db_maps_to_the_published_port(on_host):
    assert netloc.resolve_host("db", 3306) == ("127.0.0.1", 3307)


def test_ollama_url_maps_to_the_published_port(on_host):
    assert netloc.resolve_url("http://ollama:11434/api") == \
        "http://127.0.0.1:11434/api"


def test_the_env_port_is_replaced_not_kept(on_host):
    """DB_PORT=3306 is the in-network port; on the host it is 3307.

    Carrying the env port through would connect to nothing - the first
    version of this logic in build_eval_corpus.py got the host right and the
    port wrong, which fails identically to getting both wrong.
    """
    _, port = netloc.resolve_host("db", 3306)
    assert port == 3307


# --------------------------------------------------------------------------
# Where it must NOT rewrite
# --------------------------------------------------------------------------

def test_inside_a_container_nothing_is_rewritten(in_container):
    """The worker resolves `ollama` correctly and must keep using it."""
    assert netloc.resolve_host("db", 3306) == ("db", 3306)
    assert netloc.resolve_url("http://ollama:11434/api") == \
        "http://ollama:11434/api"


def test_an_unpublished_service_is_left_alone(on_host):
    """Not in PUBLISHED means not reachable from here.

    Silently pointing it at localhost swaps an accurate DNS error for a
    misleading connection-refused, and sends the reader looking at the wrong
    machine.
    """
    assert netloc.resolve_host("redis", 6379) == ("redis", 6379)
    assert netloc.resolve_url("http://redis:6379") == "http://redis:6379"


def test_a_real_hostname_is_left_alone(on_host):
    assert netloc.resolve_host("db.internal.example", 3306) == \
        ("db.internal.example", 3306)
    assert netloc.resolve_url("https://ollama.example.com/api") == \
        "https://ollama.example.com/api"


@pytest.mark.parametrize("value", ["", None])
def test_empty_input_survives(on_host, value):
    assert netloc.resolve_url(value) == value


# --------------------------------------------------------------------------
# URL parts that must not be lost
# --------------------------------------------------------------------------

def test_credentials_and_path_survive_the_rewrite(on_host):
    """RABBITMQ_URL carries them, and dropping either breaks the connection."""
    out = netloc.resolve_url("amqp://guest:guest@rabbitmq:5672/vhost")
    assert out == "amqp://guest:guest@127.0.0.1:5672/vhost"


def test_query_and_fragment_survive(on_host):
    assert netloc.resolve_url("http://ollama:11434/api?x=1#f") == \
        "http://127.0.0.1:11434/api?x=1#f"


def test_published_ports_match_the_compose_file():
    """A drift guard.

    If a published port changes in docker-compose.yaml and not here, every
    host-side script starts failing with a connection error that points at
    the service rather than at this table.
    """
    import pathlib
    import re

    compose = pathlib.Path(__file__).resolve().parent.parent / "docker-compose.yaml"
    text = compose.read_text(encoding="utf-8")
    for service, (_host, port) in netloc.PUBLISHED.items():
        block = re.search(rf"^  {service}:\n(.*?)(?=^  \S|\Z)",
                          text, re.S | re.M)
        assert block, f"{service} is in PUBLISHED but not in docker-compose.yaml"
        assert re.search(rf":{port}:\d+\"?", block.group(1)), (
            f"{service} is mapped to host port {port} in core/netloc.py, "
            f"but docker-compose.yaml does not publish that port"
        )
