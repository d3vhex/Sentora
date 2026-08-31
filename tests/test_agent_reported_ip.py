"""The address the server observed beats the one the agent claimed.

An EC2 host reported `172.31.42.49` and the console labelled it "Primary IP",
while the world saw `16.171.42.197`.

The agent is not doing anything wrong. `get_public_ip()` works its address out
from a UDP route lookup - it contacts nothing, works air-gapped, and cannot
leak the host's existence. Behind NAT that returns the private address, which
is the correct answer to the question it can actually ask.

The server has a better one and was throwing it away: the peer address of an
established TCP connection. It is also the only one here that an agent cannot
forge, which matters for a field the console presents as fact.

Also covered: why the vulnerability scan finds nothing. "no_packages" reads as
"this host has no software", which is never true - and on the host that
prompted this, the real answer was that the agent had sent no telemetry at all
because its local database was unreachable, while still showing ONLINE with an
IP, a MAC and a hostname. Those come from the connection header and need no
database.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = (ROOT / "server.py").read_text(encoding="utf-8")
VULN = (ROOT / "scanners" / "vuln.py").read_text(encoding="utf-8")


def _fn(source: str, name: str):
    tree = ast.parse(source)
    return next(n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


class _Writer:
    def __init__(self, peer):
        self._peer = peer

    def get_extra_info(self, key):
        assert key == "peername"
        if isinstance(self._peer, Exception):
            raise self._peer
        return self._peer


def _peer_module(gateways: set[str] | None = None):
    """server.py's peer helpers, without importing its dependencies.

    `_own_gateways` reads the kernel routing table, which on the test machine
    is the test machine's - not the deployment's. It is stubbed so the callers
    can be exercised against a known set.
    """
    import types

    module = types.ModuleType("_peer")
    body = [_fn(SERVER, name) for name in
            ("_own_gateways", "peer_is_a_local_router", "observed_peer_ip")]
    exec(compile(ast.Module(body=body, type_ignores=[]), "<peer>", "exec"),
         module.__dict__)
    if gateways is not None:
        module._own_gateways = lambda: gateways
    else:
        module._own_gateways = lambda: set()
    return module


@pytest.fixture(scope="module")
def observed():
    """Import just the helper, without importing server.py's dependencies."""
    return _peer_module().observed_peer_ip


# --------------------------------------------------------------------------

def test_a_public_peer_is_used(observed):
    assert observed(_Writer(("16.171.42.197", 51234))) == "16.171.42.197"


def test_a_private_peer_is_kept(observed):
    """On a flat corporate LAN 10.x *is* the machine's address, and there is
    nothing more public to have. Discarding it would leave the console with
    the agent's guess when the observed value was just as good."""
    assert observed(_Writer(("10.20.30.41", 5001))) == "10.20.30.41"


@pytest.mark.parametrize("peer", ["127.0.0.1", "::1", "169.254.1.1", "0.0.0.0"])
def test_addresses_that_say_nothing_fall_back(observed, peer):
    """Loopback means the agent is on this host; link-local means it never
    got an address. In both cases the agent's own idea is the better one."""
    assert observed(_Writer((peer, 5001))) is None


def test_ipv4_mapped_ipv6_is_unwrapped(observed):
    """A dual-stack listener reports `::ffff:1.2.3.4`, which would otherwise
    be stored verbatim and never match anything else in the database."""
    assert observed(_Writer(("::ffff:16.171.42.197", 51234))) == "16.171.42.197"


def test_a_missing_or_broken_peer_falls_back(observed):
    assert observed(_Writer(None)) is None
    assert observed(_Writer(("not-an-address", 1))) is None
    assert observed(_Writer(OSError("closed"))) is None


def test_the_ingest_path_prefers_the_observed_address():
    """The claim is still read off the wire - the protocol did not change -
    but it is now the fallback rather than the answer."""
    assert "public_ip = observed_peer_ip(writer) or claimed_ip" in SERVER


def test_the_agents_claim_is_no_longer_stored_directly():
    """If this reverts, the console goes back to showing whatever the agent
    said, which on any NATed host is the wrong address."""
    body = ast.unparse(_fn(SERVER, "handle_client"))
    assert "claimed_ip" in body
    assert "observed_peer_ip" in body


# --------------------------------------------------------------------------
# Why the vulnerability scan found nothing
# --------------------------------------------------------------------------

def test_an_empty_scan_says_which_kind_of_empty():
    """"no_packages" sends an operator into the OSV scanner looking for a
    fault that is on the endpoint."""
    body = ast.unparse(_fn(VULN, "scan_agent"))
    assert "_agent_has_no_telemetry" in body
    assert "no telemetry at all" in body


def test_the_reason_names_the_next_command():
    body = ast.unparse(_fn(VULN, "scan_agent"))
    assert "docker ps" in body
    assert "journalctl" in body


def test_a_silent_agent_is_distinguished_from_a_slow_one():
    """An agent that started a minute ago has no packages yet either, and
    telling that operator to go and read journalctl wastes their time."""
    body = ast.unparse(_fn(VULN, "scan_agent"))
    assert "inventory runs on a timer" in body


def test_the_check_cannot_itself_break_the_scan():
    """It runs inside the answer to "why did this find nothing". Raising there
    would replace a useful message with a stack trace."""
    body = ast.unparse(_fn(VULN, "_agent_has_no_telemetry"))
    assert "except Exception" in body
    assert "return False" in body, \
        "an unreachable database must not be reported as an empty one"


def test_it_checks_more_than_packages():
    """Packages alone are collected on a timer, so an agent that has sent
    SIEM events but no inventory yet is not silent."""
    assert "_TELEMETRY_TABLES" in VULN
    for table in ("siem_events", "process_events"):
        assert table in VULN


# --------------------------------------------------------------------------
# The scan that never worked
# --------------------------------------------------------------------------

def test_the_decrypt_prefix_matches_what_the_agent_writes():
    """The scanner spelled it `ENC::`; the agent writes `enc::`.

    Nothing matched, so every value came back as ciphertext and the scanner
    asked OSV about a package literally named `enc::gAAAAABq...`. That returns
    no vulnerabilities, for every agent, forever - and looks exactly like a
    clean estate. `packages` is encrypted on every agent, so this scan had
    never produced a finding.
    """
    agent = (ROOT / "Sentora" / "modules" / "enc_db.py").read_text(encoding="utf-8")
    agent_prefix = next(l for l in agent.splitlines()
                        if l.startswith("ENC_PREFIX")).split("=", 1)[1].strip().strip('"')
    scanner_prefix = next(l for l in VULN.splitlines()
                          if l.startswith("ENC_PREFIX")).split("=", 1)[1].strip().strip('"')
    assert agent_prefix.lower() == scanner_prefix.lower(), \
        f"agent writes {agent_prefix!r}, scanner looks for {scanner_prefix!r}"


def test_the_comparison_is_case_insensitive():
    """Belt and braces: the two constants live in different files and one of
    them has already drifted once."""
    body = ast.unparse(_fn(VULN, "_decrypt_field"))
    assert ".lower()" in body


def test_a_fully_encrypted_package_list_is_reported_not_scanned():
    """Zero findings from a list of Fernet blobs is the most dangerous way for
    this to fail: it reads as a clean host."""
    body = ast.unparse(_fn(VULN, "scan_agent"))
    assert "still encrypted" in body
    assert "undecrypted == len(pkgs)" in body


def test_that_reason_says_what_to_do():
    body = ast.unparse(_fn(VULN, "scan_agent"))
    assert "bootstrap" in body


def test_decryption_round_trips_the_way_the_agent_writes_it():
    """Exercised rather than asserted about. The agent json-encodes before
    encrypting, so a consumer that skips that layer gets a quoted string."""
    import json
    import sys
    from cryptography.fernet import Fernet

    sys.path.insert(0, str(ROOT))
    from scanners.vuln import _decrypt_field

    key = Fernet.generate_key()
    fernet = Fernet(key)
    stored = "enc::" + fernet.encrypt(json.dumps("openssl").encode()).decode()

    assert _decrypt_field(stored, fernet) == "openssl"


def test_plaintext_and_wrong_key_both_come_back_unchanged():
    import sys
    from cryptography.fernet import Fernet

    sys.path.insert(0, str(ROOT))
    from scanners.vuln import _decrypt_field

    fernet = Fernet(Fernet.generate_key())
    other = Fernet(Fernet.generate_key())

    assert _decrypt_field("openssl", fernet) == "openssl"
    stored = "enc::" + other.encrypt(b'"openssl"').decode()
    assert _decrypt_field(stored, fernet) == stored


# --------------------------------------------------------------------------
# Our own router is not an agent
# --------------------------------------------------------------------------
#
# "What we observed beats what we were told" assumes the address translation
# happens on the *agent's* side - the cloud-VM case it was written for, where
# the agent reports 172.31.x and we see the elastic IP.
#
# With the server in a container on the agent's own machine it is the other
# way round: the connection is NAT'd on the way in and arrives from the Docker
# bridge gateway. The console showed 172.18.0.1 as a Windows host's Primary
# IP - a router's address given as the identity of a machine.
#
# Back when the server dialled agents this was also why config, SOAR dispatch
# and the screen stream all landed on `Connection refused`. It no longer
# reaches anything, but the record is still wrong, and a fleet where several
# hosts share one "Primary IP" is a fleet an operator cannot reason about.

DOCKER_GATEWAY = "172.18.0.1"


def test_the_docker_gateway_is_not_taken_for_the_agent():
    observed = _peer_module({DOCKER_GATEWAY}).observed_peer_ip
    assert observed(_Writer((DOCKER_GATEWAY, 51234))) is None, (
        "the bridge gateway was recorded as the agent's address")


def test_a_lan_peer_that_is_not_our_gateway_is_still_used():
    """The fix must not swallow the ordinary case. On a flat corporate LAN the
    agent's 192.168.x is its real address and there is nothing more public."""
    observed = _peer_module({DOCKER_GATEWAY}).observed_peer_ip
    assert observed(_Writer(("192.168.1.26", 51234))) == "192.168.1.26"


def test_the_nat_case_this_rule_exists_for_still_works():
    """A cloud VM's elastic IP is not one of our gateways, so it survives."""
    observed = _peer_module({DOCKER_GATEWAY}).observed_peer_ip
    assert observed(_Writer(("16.171.42.197", 51234))) == "16.171.42.197"


def test_the_router_check_is_exact_not_a_prefix():
    """172.18.0.1 being a gateway says nothing about 172.18.0.5, which is an
    ordinary host on that network."""
    module = _peer_module({DOCKER_GATEWAY})
    assert module.peer_is_a_local_router("172.18.0.1", {DOCKER_GATEWAY}) is True
    assert module.peer_is_a_local_router("172.18.0.5", {DOCKER_GATEWAY}) is False
    assert module.peer_is_a_local_router("", {DOCKER_GATEWAY}) is False


def test_no_routing_table_leaves_the_old_behaviour():
    """Off Linux, or with no procfs, the check simply does not fire. Losing a
    refinement is acceptable; refusing telemetry over it is not."""
    observed = _peer_module(set()).observed_peer_ip
    assert observed(_Writer((DOCKER_GATEWAY, 51234))) == DOCKER_GATEWAY


def test_own_gateways_survives_a_missing_routing_table(tmp_path, monkeypatch):
    """`_own_gateways` runs on the ingest path for every connection. It has to
    return an empty set rather than raise."""
    module = _peer_module()
    real = _fn(SERVER, "_own_gateways")
    import types
    fresh = types.ModuleType("_gw")
    exec(compile(ast.Module(body=[real], type_ignores=[]), "<gw>", "exec"),
         fresh.__dict__)
    monkeypatch.chdir(tmp_path)
    assert isinstance(fresh._own_gateways(), set)
