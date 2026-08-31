"""Static guards on app.py's auth wiring.

These parse the source rather than importing it, so they run without MySQL,
RabbitMQ or a built frontend — which means they run in CI on every push, which
is the whole point: the bug these protect against (85 routes whose
`@require_permission` never executed because it sat above `@app.route`) was
invisible at runtime and would have stayed invisible.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

APP_PY = Path(__file__).resolve().parent.parent / "app.py"

ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "websocket"}


@pytest.fixture(scope="module")
def tree() -> ast.Module:
    return ast.parse(APP_PY.read_text(encoding="utf-8", errors="replace"))


def _decorator_names(fn: ast.AST) -> list[str]:
    """Flatten a function's decorators to comparable names.

    `@app.route(...)` -> "app.route", `@require_permission(...)` ->
    "require_permission", `@app.on_request` -> "app.on_request".
    """
    names = []
    for dec in getattr(fn, "decorator_list", []):
        node = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            names.append(f"{node.value.id}.{node.attr}")
        elif isinstance(node, ast.Name):
            names.append(node.id)
    return names


def _functions(tree: ast.Module) -> list[ast.AST]:
    return [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _literal_set(tree: ast.Module, name: str) -> set[str]:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == name:
                return set(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found as a module-level assignment in app.py")


def test_public_handler_names_all_exist(tree):
    """A typo in _PUBLIC_HANDLERS fails open or closed, and both are bad.

    A name that matches nothing silently drops a route's exemption (login page
    stops working); a handler renamed without updating the set does the same.
    Neither shows up until someone tries to log in.
    """
    declared = _literal_set(tree, "_PUBLIC_HANDLERS")
    defined = {fn.name for fn in _functions(tree)}

    missing = declared - defined
    assert not missing, f"_PUBLIC_HANDLERS names no such function: {sorted(missing)}"


def test_public_handlers_are_actually_routed(tree):
    """Every exemption should correspond to a real route, or it is dead weight
    hiding the fact that the endpoint it was written for has moved."""
    declared = _literal_set(tree, "_PUBLIC_HANDLERS")
    routed = {
        fn.name for fn in _functions(tree)
        if any(d.startswith("app.") and d.split(".")[1] in ROUTE_DECORATORS
               for d in _decorator_names(fn))
    }

    orphans = declared - routed
    assert not orphans, f"_PUBLIC_HANDLERS entries that are not routes: {sorted(orphans)}"


def test_require_permission_is_always_paired_with_a_route(tree):
    """`@require_permission` on a non-route is a no-op nobody would notice."""
    for fn in _functions(tree):
        decs = _decorator_names(fn)
        if "require_permission" not in decs:
            continue
        assert any(d.startswith("app.") and d.split(".")[1] in ROUTE_DECORATORS for d in decs), (
            f"{fn.name} is decorated with require_permission but is not a route"
        )


def test_no_route_reads_identity_from_the_x_user_id_header(tree):
    """The header is an assertion checked by middleware, not a source of
    identity. A handler reading it directly is reintroducing the original
    authentication bypass."""
    source = APP_PY.read_text(encoding="utf-8", errors="replace")
    offenders = [
        line.strip()
        for line in source.splitlines()
        if 'headers.get("X-User-ID"' in line or "headers.get('X-User-ID'" in line
    ]

    # The middleware itself is the one legitimate reader.
    assert len(offenders) == 1, (
        "X-User-ID must only be read by the authenticate middleware; "
        f"found {len(offenders)} readers: {offenders}"
    )


def test_permission_registry_is_keyed_before_the_wrapper_is_built(tree):
    """Guards the fix itself: `require_permission` must record its requirement
    against the *undecorated* function, because that is the object Sanic holds
    when the decorators are stacked in the order this file uses."""
    fn = next((f for f in _functions(tree) if f.name == "require_permission"), None)
    assert fn is not None, "require_permission disappeared from app.py"

    body = ast.dump(fn)
    assert "_PERMISSION_REQUIREMENTS" in body, (
        "require_permission no longer populates the registry — the middleware "
        "would silently stop enforcing every stacked-decorator route"
    )


# --------------------------------------------------------------------------
# Every route is accounted for
# --------------------------------------------------------------------------
#
# The checks above catch a route whose permission is misspelled, or one that
# lost its decorator to the ordering bug. None of them noticed a route that
# never had a decorator at all: 143 routes carried 103 declarations, and the
# forty in between were nobody's job to explain.
#
# Most were fine. `run_playbook`, `delete_soar_action`, `patch_automation_status`
# and `test_ldap_connection` were not - any account that could log in could
# execute a playbook, close a response action, or point the server's LDAP
# client at a host of its choosing.
#
# This is the assertion that makes the gap impossible to reopen quietly. A new
# route is permission-gated, publicly declared, or named here with a reason.

# Reachable with a session and no further authorisation. Each is either about
# the caller themselves, or a static catalogue the UI needs before it knows
# what the user may do.
SESSION_ONLY_HANDLERS = {
    # Acts on the calling session only, and binds to it rather than to a
    # username in the body.
    "change_password",
    # Answers "what may I do" - gating it on a permission would be circular.
    "fetch_my_permissions",
    # Static SOAR builder catalogues. No tenant data, no state.
    "get_node_palette",
    "get_playbook_examples",
    # Enrolment: these check manage_agent inside the handler, before doing
    # anything, because they also serve token-authenticated callers.
    "enroll_agent",
    "list_enrollments",
    "revoke_enrollment",
    # Not an operator route at all: the peer is an agent, and it authenticates
    # with `X-Agent-Key` in the first statement of the handler, closing the
    # socket before anything is registered. An operator permission would be
    # the wrong check - there is no session here to have one. It also refuses
    # the fleet-wide secret, which the ordinary agent routes accept, because
    # this channel carries /self_destruct.
    "agent_link_socket",
}

# Named individually so a bulk edit to the list above cannot quietly reopen
# the ones that mattered.
MUST_STAY_GATED = [
    "clear_playbook_runs", "delete_soar_action", "get_soar_actions_api",
    "patch_automation_status", "resolve_soar_action", "run_automation_alias",
    "run_playbook", "test_ldap_connection",
]


def _route_functions(tree: ast.Module) -> dict:
    out = {}
    for fn in _functions(tree):
        names = _decorator_names(fn)
        if any(n.split(".")[-1] in ROUTE_DECORATORS and n.startswith("app.")
               for n in names):
            out[fn.name] = (names, fn)
    return out


def test_the_route_scan_finds_them_all(tree):
    """Guard against a green run caused by matching nothing."""
    found = _route_functions(tree)
    assert len(found) > 100, f"only {len(found)} routes found; the scan is broken"


def test_every_route_is_public_permissioned_or_explicitly_session_only(tree):
    public = _literal_set(tree, "_PUBLIC_HANDLERS")
    ungoverned = []
    for name, (names, fn) in sorted(_route_functions(tree).items()):
        if "require_permission" in names:
            continue
        if name in public or name in SESSION_ONLY_HANDLERS:
            continue
        if "user_has_permission" in ast.unparse(fn):
            continue          # checked inline, before doing the work
        ungoverned.append(name)

    assert not ungoverned, (
        "these routes are reachable by any authenticated account with no "
        "authorisation check:\n  "
        + "\n  ".join(ungoverned)
        + "\n\nAdd @require_permission(...), or add the handler to "
          "SESSION_ONLY_HANDLERS with a comment saying why that is safe."
    )


def test_the_session_only_list_does_not_name_gated_routes(tree):
    """Otherwise the list grows stale and stops meaning anything."""
    routes = _route_functions(tree)
    contradictions = sorted(
        name for name in SESSION_ONLY_HANDLERS
        if name in routes and "require_permission" in routes[name][0]
    )
    assert not contradictions, (
        f"listed as session-only but actually gated: {contradictions}"
    )


def test_the_session_only_list_has_no_dead_entries(tree):
    missing = sorted(SESSION_ONLY_HANDLERS - set(_route_functions(tree)))
    assert not missing, (
        f"SESSION_ONLY_HANDLERS names handlers that are not routes: {missing}"
    )


@pytest.mark.parametrize("name", MUST_STAY_GATED)
def test_the_routes_that_prompted_this_stay_gated(name, tree):
    routes = _route_functions(tree)
    assert name in routes, f"{name} is no longer a route; update this test"
    names, fn = routes[name]
    assert ("require_permission" in names
            or "user_has_permission" in ast.unparse(fn)), name


# --------------------------------------------------------------------------
# The audit has to be able to see the routes it audits
# --------------------------------------------------------------------------
#
# `verify_auth_wiring` reads `route.handler.__qualname__`. Sanic wraps a
# websocket handler in a `functools.partial`, which has no `__qualname__`, so
# every websocket route fell into the "unresolvable" bucket and the boot-time
# audit did not cover them:
#
#     [Auth] WARNING: 3 route(s) with an unresolvable handler:
#     ['/agent-link', '/console-proxy/<agent:str>', '/vnc-proxy/<agent:str>']
#
# Those three are the agent channel, a root shell on an endpoint, and a live
# view of its screen. The one category the audit could not see was the one
# worth seeing, and it announced that in a line which reads like a formatting
# complaint.


def _resolver(tree: ast.Module):
    """`_handler_qualname`, compiled on its own."""
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "_handler_qualname")
    namespace: dict = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<app.py>", "exec"),
         namespace)
    return namespace["_handler_qualname"]


def test_the_audit_still_runs_at_boot(tree):
    """It reports the auth posture of every route, and an audit that is not
    registered reports nothing while looking exactly like one that is.

    Worth its own assertion because the failure is silent and easy to cause:
    inserting a helper between `@app.before_server_start` and this function
    hands the decorator to the helper, and both keep parsing fine.
    """
    fn = next(n for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "verify_auth_wiring")
    assert "app.before_server_start" in _decorator_names(fn), \
        "verify_auth_wiring is defined but never registered, so no route is audited"


def _console_proxy(request, ws, agent):
    """Stands in for a route handler; only its name is under test."""
    return None


def test_a_partial_wrapped_handler_still_resolves(tree):
    """Which is exactly how Sanic registers a websocket route."""
    import functools

    wrapped = functools.partial(_console_proxy, None)
    assert _resolver(tree)(wrapped).endswith("_console_proxy")


def test_a_handler_behind_a_wrapper_still_resolves(tree):
    """`__wrapped__` is the other convention a decorator leaves behind."""
    class Wrapper:
        __wrapped__ = staticmethod(_console_proxy)

    assert _resolver(tree)(Wrapper()).endswith("_console_proxy")


def test_an_unresolvable_handler_is_still_reported(tree):
    """The bucket has to keep working. The point was to empty it honestly,
    not to stop counting."""
    assert _resolver(tree)(object()) == ""
    assert _resolver(tree)(None) == ""


def test_the_resolver_cannot_loop_forever(tree):
    """A handler whose `func` points back at itself would hang the boot
    audit, which runs before anything is served."""
    class SelfReferential:
        pass

    node = SelfReferential()
    node.func = node
    assert _resolver(tree)(node) == ""


def test_the_agent_channel_is_declared_rather_than_counted_as_session_only(tree):
    """It is not gated by an operator session and must not be: it is the
    channel every agent opens, authenticated by agent key against
    `agent_identities`. Letting it fall into the session-only tally would be
    a false reassurance in the opposite direction from the one this file
    exists to prevent."""
    assert "agent_link_socket" in _literal_set(tree, "_PUBLIC_HANDLERS")
