"""Every route on the agent's listener requires a key, and self-destruct
requires this agent's own key.

The agent binds 0.0.0.0:9099 and runs as SYSTEM or root. Three routes had no
authentication at all:

    curl -X POST http://<endpoint>:9099/self_destruct

removed the EDR from the host. Tamper resistance is the property a security
agent exists to have, and this was the first step of any intrusion reduced to
one request from anywhere on the network.

Every other route was reachable too. `_is_permissive_auth` accepted any
non-empty `X-Agent-Key` whenever `AGENT_MASTER_SECRET` was unset on the host,
and nothing in this repository ever set it - not the installer, not the
scheduled task, not the systemd unit. So `/soar/execute` with
`{"action":"run_cmd"}` was fleet-wide unauthenticated RCE, and `/config`
could switch detection off first.

These parse main.py rather than importing it: the module starts collectors and
opens a database on import.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

MAIN = pathlib.Path(__file__).resolve().parent.parent / "Sentora" / "main.py"
SRC = MAIN.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _routes():
    out = {}
    for node in ast.walk(TREE):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for dec in node.decorator_list:
            d = ast.unparse(dec)
            if ".route(" in d or ".post(" in d or ".get(" in d or ".websocket(" in d:
                out[node.name] = (d, node)
                break
    return out


ROUTES = _routes()

# /health answers liveness without a key and discloses nothing without one.
UNAUTHENTICATED_BY_DESIGN = {"health"}


def test_the_scan_sees_the_routes():
    assert len(ROUTES) >= 7, f"only found {sorted(ROUTES)}; the scan is broken"


@pytest.mark.parametrize("name", sorted(set(ROUTES) - UNAUTHENTICATED_BY_DESIGN))
def test_every_route_authenticates(name):
    _decorator, node = ROUTES[name]
    body = ast.unparse(node)
    assert "_check_auth_header" in body or "_ws_authorized" in body, (
        f"{name} serves on 0.0.0.0:9099 with no authentication"
    )


def test_self_destruct_requires_this_agents_own_key():
    """Not the fleet-wide master secret.

    The server holds the per-agent key and sends it first, so nothing
    legitimate breaks - but a leaked master secret can no longer uninstall
    every endpoint at once.
    """
    body = ast.unparse(ROUTES["self_destruct"][1])
    assert "enrolment_key_only=True" in body


def test_permissive_auth_is_gone():
    """It accepted any non-empty key and was on by default."""
    assert "def _is_permissive_auth" not in SRC
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.FunctionDef) and n.name == "_check_auth_header")
    body = ast.unparse(fn)
    assert "permissive" not in body.lower()


def test_auth_comparison_is_timing_safe():
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.FunctionDef) and n.name == "_timing_safe_in")
    assert "compare_digest" in ast.unparse(fn)


def test_an_empty_key_is_never_accepted():
    """`accepted` can legitimately be empty before enrolment completes; an
    empty header must not match an empty set."""
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.FunctionDef) and n.name == "_check_auth_header")
    body = ast.unparse(fn)
    assert "if srv_key and accepted" in body


def test_health_discloses_nothing_without_a_key():
    """It used to hand out the SIEM server address, port and API base to
    anyone on the network - a map of the security infrastructure."""
    body = ast.unparse(ROUTES["health"][1])
    assert "_check_auth_header" in body
    # the unauthenticated branch returns before the detail dict
    assert body.index("_check_auth_header") < body.index("SERVER_IP")
