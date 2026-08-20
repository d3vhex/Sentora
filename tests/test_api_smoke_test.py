"""Tests for the smoke-test harness itself.

A broken enumerator would report "all routes passed" while exercising none of
them, which is worse than not having the script — so the parsing and the
parameter substitution are checked here, without a server.
"""
from __future__ import annotations

import re

import pytest

from scripts import api_smoke_test as smoke


@pytest.fixture(scope="module")
def routes():
    return smoke.enumerate_routes()


def test_enumerates_a_realistic_number_of_routes(routes):
    # app.py declares well over a hundred route/method pairs. A handful means
    # the decorator matching silently stopped working.
    assert len(routes) > 100, f"only {len(routes)} routes parsed — enumerator is broken"


def test_every_entry_is_a_method_and_an_absolute_path(routes):
    verbs = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
    for method, path in routes:
        assert method in verbs, f"unexpected verb {method} for {path}"
        assert path.startswith("/"), f"path is not absolute: {path}"


def test_known_routes_are_present(routes):
    paths = {p for _, p in routes}
    for expected in ("/login", "/health", "/devices", "/users", "/_proxy/http"):
        assert expected in paths, f"{expected} missing from the enumerated routes"


def test_route_methods_come_from_the_decorator(routes):
    """`/login` declares GET and POST; picking up only the default would mean
    the methods= keyword is being ignored."""
    login = {m for m, p in routes if p == "/login"}
    assert login == {"GET", "POST"}, f"got {login}"


def test_fill_params_leaves_no_placeholders(routes):
    for _, path in routes:
        filled = smoke.fill_params(path, "TEST-AGENT")
        assert "<" not in filled and ">" not in filled, (
            f"{path} still contains a placeholder after substitution: {filled}"
        )


def test_fill_params_substitutes_the_agent_name():
    assert smoke.fill_params("/<agent>/siem-events", "WIN-01") == "/WIN-01/siem-events"
    assert smoke.fill_params("/<agent_name>/create_playbooks", "WIN-01") == "/WIN-01/create_playbooks"


def test_ids_are_out_of_range_so_no_real_row_is_touched():
    """A real id would make the smoke test depend on — and potentially
    disturb — live data."""
    filled = smoke.fill_params("/<agent>/automations/<auto_id:int>/run", "a")
    assert "999999999" in filled


def test_destructive_and_expensive_routes_are_skipped():
    for path in ("/api/agent/download/<os_type>", "/vnc-proxy/<agent>", "/logout"):
        assert path in smoke.SKIP, f"{path} should not be called automatically"


def test_only_read_only_verbs_are_exercised_with_a_session():
    """Pass 2 must never send a write verb. The guard is `method not in
    READ_ONLY -> skip`, so READ_ONLY containing a write verb would be enough
    to have the smoke test fire SOAR actions."""
    assert smoke.READ_ONLY == {"GET", "HEAD"}


def test_safe_write_probes_only_name_real_routes(routes):
    paths = {p for _, p in routes}
    unknown = {p for p in smoke.SAFE_WRITE_PROBES if p not in paths}
    assert not unknown, f"SAFE_WRITE_PROBES names routes that no longer exist: {sorted(unknown)}"


def test_safe_write_probes_exclude_destructive_paths():
    """The allow list must never grow to include something that acts.

    A single wrong entry here turns the smoke test into the thing that
    isolates a host or drops the user database.
    """
    forbidden = ("self_destruct", "/soar/", "/databases/", "restart", "clear",
                 "/execute", "/run", "/approve", "/reject", "automations/report")
    for path in smoke.SAFE_WRITE_PROBES:
        for token in forbidden:
            assert token not in path, f"{path} looks side-effecting; do not probe it"


def test_public_list_only_names_real_routes(routes):
    """A stale entry here would silently exclude a protected route from the
    anonymous-access check — the one thing this script exists to catch."""
    paths = {p for _, p in routes}
    unknown = {p for p in smoke.PUBLIC if p not in paths}
    assert not unknown, f"PUBLIC names routes that no longer exist: {sorted(unknown)}"
