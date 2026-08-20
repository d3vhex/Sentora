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
