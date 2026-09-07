"""The TLS guide has to describe the code, not a plan for it.

This suite exists because the previous version of that guide described three
settings the code did not read. It was not careless writing - it was written
first, the implementation slipped, and nothing tied the two together. An
operator who set `TLS_ENABLED=1` got a console on plain HTTP and no reason to
doubt it.

So these tests pin the load-bearing claims in `docs/production-deployment.md`
to the code that has to make them true. They are deliberately about
*existence*, not prose: a doc test that checks wording becomes a chore that
gets deleted, while one that checks a documented setting is still read catches
the failure that actually happened.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "production-deployment.md"
ENV_EXAMPLE = ROOT / ".env.example"
TLS = ROOT / "core" / "tls.py"
SERVER = ROOT / "server.py"
COMPOSE = ROOT / "docker-compose.yaml"


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _tls_section() -> str:
    text = _guide()
    start = text.index("## 3. TLS / Certificate Handling")
    return text[start:text.index("\n## 4.", start)]


# --------------------------------------------------------------------------
# Every setting the guide names is a setting something reads
# --------------------------------------------------------------------------

DOCUMENTED_SETTINGS = [
    ("TLS_ENABLED", TLS), ("TLS_CERT", TLS), ("TLS_KEY", TLS),
    ("TLS_CN", TLS), ("TLS_DIR", TLS),
    ("INGEST_TLS_REQUIRED", SERVER), ("INGEST_TLS_PORT", SERVER),
]


@pytest.mark.parametrize("name,module", DOCUMENTED_SETTINGS,
                         ids=[n for n, _ in DOCUMENTED_SETTINGS])
def test_a_documented_setting_is_read_somewhere(name, module):
    """The exact failure this file exists for: three variables in the guide,
    in `.env.example`, and in the generator's closing output - and read by no
    line of code."""
    assert name in _tls_section(), f"{name} is implemented but undocumented"
    assert name in module.read_text(encoding="utf-8"), (
        f"the guide documents {name} and {module.name} never reads it"
    )


@pytest.mark.parametrize("name,_module", DOCUMENTED_SETTINGS,
                         ids=[n for n, _ in DOCUMENTED_SETTINGS])
def test_the_example_env_agrees_with_the_guide(name, _module):
    """Two places an operator looks for the same answer."""
    assert name in ENV_EXAMPLE.read_text(encoding="utf-8"), \
        f"{name} is in the guide and not in .env.example"


# --------------------------------------------------------------------------
# Claims that would send somebody to the wrong place
# --------------------------------------------------------------------------

def test_the_guide_does_not_send_anyone_to_the_old_certificate_path():
    """`/app/certs` is the path that failed with EACCES and restart-looped the
    container. It survives in the guide only inside the warning about it."""
    section = _tls_section()
    outside_the_warning = [
        line for line in section.splitlines()
        if "/app/certs" in line and not line.lstrip().startswith(">")
    ]
    assert not outside_the_warning, (
        "the guide still points at /app/certs outside the warning: "
        + "; ".join(outside_the_warning)
    )


def test_no_stale_volume_is_referenced():
    """A `sentora_certs` volume existed for about an hour. A guide naming a
    volume compose does not declare sends the reader to look for something
    that was never created."""
    import yaml

    declared = set(yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["volumes"])
    for named in re.findall(r"`(sentora_\w+)`", _guide()):
        assert named in declared, f"the guide names {named}, compose does not declare it"


def test_the_documented_tls_dir_is_the_one_compose_sets():
    """A path written out in prose and again in compose is a path that drifts."""
    import yaml

    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    configured = compose["services"]["app"]["environment"]["TLS_DIR"]
    assert configured in _tls_section(), (
        f"compose sets TLS_DIR={configured} and the guide documents a "
        f"different path"
    )


def test_the_ports_table_covers_the_tls_listener():
    """5011 exists; a ports table without it is a firewall rule nobody opens."""
    ports = _guide()[_guide().index("### 2.2 Ports"):]
    ports = ports[:ports.index("###", 10)]
    assert "5011" in ports
    assert "5001" in ports


# --------------------------------------------------------------------------
# The two-part step, because half of it silently loses data
# --------------------------------------------------------------------------

def test_closing_the_plaintext_path_documents_both_halves():
    """`INGEST_TLS_REQUIRED=1` closes the listener inside the container while
    Docker goes on publishing the port. A connection is then accepted by the
    proxy and the batch written into a socket nobody reads - so the port has
    to be unpublished too, and the guide has to say both.

    Asserted as the property rather than the mechanism. The first version
    checked for the literal `"5001:5001"`, because the instruction then was to
    delete that line from a tracked compose file - which is a bad thing to ask
    an operator to do, and the moment it became an environment variable this
    test failed against a guide that had just got better.
    """
    section = _tls_section()
    assert "INGEST_TLS_REQUIRED=1" in section, \
        "the guide never says how to stop the listener"
    assert "INGEST_PLAINTEXT_BIND" in section, (
        "the guide tells the operator to require TLS without telling them to "
        "stop publishing the plaintext port"
    )


def test_unpublishing_the_port_is_something_compose_can_actually_do():
    """A documented setting that no file reads is what this whole suite exists
    for."""
    import yaml

    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    published = compose["services"]["ingest"]["ports"]
    plaintext = [p for p in published if str(p).endswith("5001:5001")]
    assert plaintext, "the plaintext port is no longer published at all"
    assert "INGEST_PLAINTEXT_BIND" in str(plaintext[0]), (
        "the guide names INGEST_PLAINTEXT_BIND and compose ignores it, so "
        "following the migration leaves the port open"
    )

    # And the default still publishes, because a fresh install that is not on
    # TLS yet needs 5001 to work without editing a tracked file.
    assert ":-0.0.0.0}" in str(plaintext[0]), \
        "the default now hides the plaintext port from every new deployment"


def test_the_agent_side_of_that_trap_is_implemented():
    """The guide claims the agent will not be fooled by an accepted-and-
    discarded batch. That claim depends on it remembering that this server has
    acknowledged before."""
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    assert "_SERVER_ACKNOWLEDGES" in main


# --------------------------------------------------------------------------
# The verification steps have to be runnable
# --------------------------------------------------------------------------

def test_the_verification_section_exists_and_is_concrete():
    """"Verify TLS is working" without commands is a step everybody skips."""
    section = _tls_section()
    verify = section[section.index("Verifying it, rather than assuming it"):]
    assert "/api/agent/ca" in verify
    assert "create_default_context" in verify, \
        "the check that matters - does the CA verify the served cert - is missing"
    assert "in the clear on port" in verify, \
        "nothing tells the operator how to know the fleet has finished migrating"


def test_the_windows_curl_caveat_is_recorded():
    """`curl --cacert` on Windows reports CERT_TRUST_REVOCATION_STATUS_UNKNOWN
    against a perfectly valid private chain. Without this note the first
    verification step looks like a failure and somebody 'fixes' a working
    deployment."""
    assert "schannel" in _tls_section()
