"""Failures that must not be swallowed.

84 handlers across the repository swallow an exception with `pass`. Most are
correct - closing a connection that is already gone, a websocket relay ending
because the peer hung up, a JSON field that falls back to its raw string.
Converting all of them would be a large diff over code with no tests, and
most of it would change nothing.

Three did matter, and they share a shape: a control that reports success
whether or not it worked.

- `ensure_permissions` chmods a secret file. Swallowed, a failure leaves the
  file at whatever the umask gave it - commonly 0644 in a container - so the
  secret is readable by every process there and nothing says so. It is used
  on `.env` and on the Fernet key every agent's telemetry is encrypted with.
- The threat-intel migration swallowed every DDL error as "already present".
  A lock timeout or a missing table then meant the column never appeared, and
  the failure surfaced later as a broken query somewhere else.

The rest are capped by a count so the number cannot quietly grow.
"""
from __future__ import annotations

import ast
import pathlib
import re
import stat

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
SRC = APP.read_text(encoding="utf-8")
TREE = ast.parse(SRC)

# Bare `except: pass` handlers across the repo. Lower this as they are
# examined; it must never rise.
# 85: the screen stream's "tell the browser why there is no display" send.
# The socket is closed on the next line and the reason is already in the
# agent log, so a browser that has gone away cannot be told anything and
# nothing is lost by the failure.
KNOWN_SWALLOWED_MAX = 85


def _bare_pass_handlers():
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        s = str(path)
        if "node_modules" in s or ".venv" in s or "\tests\\" in s or "/tests/" in s:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.ExceptHandler) and len(node.body) == 1
                    and isinstance(node.body[0], ast.Pass)):
                out.append((path.relative_to(ROOT), node.lineno))
    return out


def test_the_scan_finds_handlers():
    assert len(_bare_pass_handlers()) > 40, "the scan is broken"


def test_the_count_does_not_grow():
    found = _bare_pass_handlers()
    assert len(found) <= KNOWN_SWALLOWED_MAX, (
        f"{len(found)} bare `except: pass` handlers, up from "
        f"{KNOWN_SWALLOWED_MAX}. Swallow a failure only where the failure "
        f"genuinely changes nothing, and say so in a comment."
    )


# --------------------------------------------------------------------------
# The permission control
# --------------------------------------------------------------------------

def _fn(name):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


def _code(name: str) -> str:
    """A function's source without its docstring.

    These docstrings describe the behaviour ("Never raises"), so matching
    against them tests the prose rather than the code.
    """
    fn = _fn(name)
    body = list(fn.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return "\n".join(ast.unparse(n) for n in body)


def test_a_failed_chmod_is_reported():
    code = _code("ensure_permissions")
    assert "pass" not in code.split("except")[-1][:40]
    assert "Could not restrict permissions" in code


def test_the_resulting_mode_is_verified_not_assumed():
    """chmod can return without error and still not produce the mode asked
    for, on Windows and on some mounted filesystems."""
    code = _code("ensure_permissions")
    assert "os.stat" in code
    assert "S_IRWXG" in code
    assert "S_IRWXO" in code


def test_it_reports_rather_than_raises():
    """The caller has already written the secret; refusing to continue would
    leave it written and unusable."""
    code = _code("ensure_permissions")
    assert "raise" not in code
    assert "return False" in code
    assert "return True" in code


def test_the_fernet_key_uses_it():
    """This is the key every agent's telemetry is encrypted with."""
    i = SRC.index("def load_or_create_fernet_key")
    body = SRC[i:i + 2000]
    assert "ensure_permissions" in body
    assert "os.chmod(path, 0o600)" not in body


def test_the_env_file_uses_it():
    assert "ensure_permissions(ENV_PATH)" in SRC


def test_ensure_permissions_actually_restricts(tmp_path, monkeypatch):
    """Behaviour, not just shape."""
    import os as _os
    ns = {"os": _os, "stat": stat, "pathlib": pathlib, "print": lambda *a, **k: None}
    exec(compile(ast.Module(body=[_fn("ensure_permissions")], type_ignores=[]),
                 "<perm>", "exec"), ns)

    secret = tmp_path / "fernet.key"
    secret.write_bytes(b"k" * 44)
    assert ns["ensure_permissions"](secret) is True
    if _os.name != "nt":
        mode = stat.S_IMODE(secret.stat().st_mode)
        assert not mode & (stat.S_IRWXG | stat.S_IRWXO), oct(mode)


def test_a_missing_file_is_reported_not_raised(tmp_path):
    import os as _os
    ns = {"os": _os, "stat": stat, "pathlib": pathlib, "print": lambda *a, **k: None}
    exec(compile(ast.Module(body=[_fn("ensure_permissions")], type_ignores=[]),
                 "<perm>", "exec"), ns)
    assert ns["ensure_permissions"](tmp_path / "does-not-exist") is False


# --------------------------------------------------------------------------
# The migration
# --------------------------------------------------------------------------

def test_only_already_present_is_ignored():
    """1060 duplicate column and 1061 duplicate key mean the migration has
    already run. A lock timeout is a different thing entirely.

    The boot migrations moved to core/schema_init.py; the assertion follows
    them rather than the file they used to be in.
    """
    schema_init = (pathlib.Path(__file__).resolve().parent.parent
                   / "core" / "schema_init.py").read_text(encoding="utf-8")
    i = schema_init.index("for ddl in (")
    block = schema_init[i:i + 1400]
    assert "1060" in block and "1061" in block
    assert "migration failed" in block
    assert re.search(r"except Exception:\s*\n\s*pass\s*#\s*already present", block) is None


# --------------------------------------------------------------------------
# `except:` with no exception type
# --------------------------------------------------------------------------

def test_no_handler_catches_bare_except():
    """`except:` also catches KeyboardInterrupt and SystemExit.

    A Ctrl-C landing inside such a block is discarded, and so is the exit a
    supervisor sends. One of these sat around a `json.loads` in the automation
    list; narrowing it to ValueError does not change the fallback but does
    stop it eating a shutdown.

    Counted separately from the cap above, because this one has no legitimate
    use: whatever the handler is for, it can name it.
    """
    import ast
    import pathlib

    offenders = []
    root = pathlib.Path(__file__).resolve().parent.parent
    for f in root.rglob("*.py"):
        s = str(f).replace("\\", "/")
        if any(skip in s for skip in ("node_modules", "/.venv", "/.git/", "/build/")):
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for h in ast.walk(tree):
            if isinstance(h, ast.ExceptHandler) and h.type is None:
                offenders.append(f"{f.relative_to(root)}:{h.lineno}")

    assert not offenders, (
        "`except:` catches KeyboardInterrupt and SystemExit as well:\n  "
        + "\n  ".join(offenders)
    )
