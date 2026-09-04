"""A collector that fails must report and retry, never stop existing.

The Ports tab was empty on a host that had been up for days, and
`portscan_result sent` appeared zero times in its log. Not once - so the
scanner had not merely failed, it had stopped running entirely.

`main_async` ended its error paths with `sys.exit(1)`. SystemExit inherits
from BaseException, so `periodic_wrapped`'s `except Exception` never saw it,
and in a thread Python discards it without a word. The first failed scan
ended that thread for the life of the agent. `info_collector` did the same on
two paths.

The other half of the same evening: real-time FIM watched all of `C:\\Users`
with no exclusions and recorded every `.py`, `.exe` and `.dll` written
underneath - temp directories, browser caches, pip installs. Thousands of
"integrity violation" rows an hour, a local queue that never drained, and
`network_connections` and `hardware_inventory` waiting behind them. The
exclusions were not missing: `conf/file_scan.yaml` has the key, the console
pushes it, `check_permissions` honours it, and `fim.py` never read the file.

Both are the same failure to the operator: a tab that is empty or full of
noise, and nothing anywhere saying which.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "Sentora"
MAIN = AGENT / "main.py"
FIM = AGENT / "modules" / "fim.py"

COLLECTOR_MODULES = [
    AGENT / "modules" / "portscanner" / "portscanner.py",
    AGENT / "modules" / "find_vulns" / "info_collector.py",
    AGENT / "modules" / "edr_enforcer.py",
    AGENT / "modules" / "inventory.py",
    AGENT / "modules" / "fim.py",
]


def _code_only(path: pathlib.Path) -> str:
    """Source without comments or docstrings.

    Each of these files explains the `sys.exit` it removed, and matching the
    text finds the explanation.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            del body[0]
    return ast.unparse(tree)


@pytest.mark.parametrize("path", COLLECTOR_MODULES, ids=lambda p: p.stem)
def test_no_collector_calls_sys_exit(path):
    """In a thread, SystemExit ends that thread and Python says nothing."""
    assert "sys.exit" not in _code_only(path), (
        f"{path.name} ends a code path with sys.exit; under `periodic_wrapped` "
        f"that kills the collector permanently and silently"
    )


def test_the_runner_survives_one_anyway():
    """Both offenders are fixed, so this guards the next one rather than the
    last one - which is the only useful place for a guard like this."""
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "periodic_wrapped")
    handlers = [ast.unparse(h.type) for h in ast.walk(fn)
                if isinstance(h, ast.ExceptHandler) and h.type]
    assert "SystemExit" in handlers, \
        "a library calling sys.exit still ends the collector"


# --------------------------------------------------------------------------
# FIM noise
# --------------------------------------------------------------------------

def test_fim_reads_the_config_it_is_given():
    """`conf/file_scan.yaml` is pushed from the console. A setting that is
    configurable, documented, and connected to nothing is worse than one that
    does not exist - somebody sets it and believes it took."""
    code = _code_only(FIM)
    assert "file_scan" in code
    assert "exclude_dirs" in code


def test_fim_excludes_the_directories_that_churn():
    """Watching `C:\\Users` at all is only defensible with these. The
    interesting things under it - documents, startup folders, ssh keys - are
    not in a temp directory or a browser cache."""
    source = FIM.read_text(encoding="utf-8")
    for pattern in ("AppData\\\\Local\\\\Temp", "node_modules", "$Recycle.Bin"):
        assert pattern in source, pattern


def test_the_exclusion_check_happens_before_the_hash():
    """Hashing a file costs a read of it, and in a temp directory there are
    thousands a minute."""
    tree = ast.parse(FIM.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "process")
    code = ast.unparse(fn)
    assert "is_excluded" in code
    assert code.index("is_excluded") < code.index("calculate_sha256")


def test_configured_exclusions_add_to_the_defaults():
    """Somebody adding one directory should not silently un-exclude every
    temp folder."""
    code = _code_only(FIM)
    assert "excludes.append" in code, \
        "the configured list replaces the defaults instead of extending them"


@pytest.mark.parametrize("path,excluded", [
    ("C:\\Users\\pc\\AppData\\Local\\Temp\\x\\build.py", True),
    ("C:\\Users\\pc\\Documents\\notes.py", False),
    ("C:\\Users\\pc\\project\\node_modules\\pkg\\index.js", True),
    ("C:\\Users\\pc\\.ssh\\authorized_keys", False),
])
def test_the_matcher_separates_noise_from_signal(path, excluded):
    """Compiled and run, because a pattern list that matches nothing looks
    exactly like a pattern list that is working."""
    import fnmatch

    tree = ast.parse(FIM.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "is_excluded")
    defaults = next(n for n in tree.body
                    if isinstance(n, ast.Assign)
                    and getattr(n.targets[0], "id", "") == "DEFAULT_EXCLUDES")
    namespace: dict = {"fnmatch": fnmatch}
    exec(compile(ast.Module(body=[defaults, fn], type_ignores=[]),
                 str(FIM), "exec"), namespace)
    patterns = namespace["DEFAULT_EXCLUDES"]["windows"]
    assert namespace["is_excluded"](path, patterns) is excluded, path


def test_the_suppressed_count_is_reported():
    """Without it, the only evidence the exclusions are working is the absence
    of events - which is also what a broken watcher produces."""
    code = _code_only(FIM)
    assert "suppressed" in code
    assert "suppressed {count} events in excluded directories" in code
