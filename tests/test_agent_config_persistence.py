r"""A pushed config must survive the agent restarting.

`set_config` wrote to `os.path.dirname(os.path.abspath(__file__))/conf/...`
and `log_extractor` read from the same place. In a PyInstaller **onefile**
build that path is `sys._MEIPASS` - the directory the bootloader extracts into
and **deletes when the process exits**.

So a rules change pushed from the console:

  1. was written
  2. answered "Config updated successfully"
  3. read back correctly for the rest of that process's life
  4. was gone after the next restart, silently back to the shipped copy

The agent restarts on a fifteen-minute watchdog, so the window in which the
change appeared to exist was short and its disappearance was never announced.
An operator tightening a detection rule had every reason to believe it held.

Frozen behaviour cannot be exercised by importing the module - `sys.frozen`
and `sys._MEIPASS` are set by the bootloader - so it is driven here by setting
those attributes, which is exactly what PyInstaller does.
"""

import importlib.util
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "Sentora" / "modules" / "agent_paths.py"


def _fresh_module():
    """A fresh copy, so `monkeypatch` on sys.frozen is read at call time."""
    spec = importlib.util.spec_from_file_location("_agent_paths_under_test", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def paths():
    return _fresh_module()


@pytest.fixture
def frozen(paths, tmp_path, monkeypatch):
    """Stand in for a onefile build: an install dir and an extraction dir."""
    install = tmp_path / "install"
    extracted = tmp_path / "_MEI12345"
    (install).mkdir()
    (extracted / "conf").mkdir(parents=True)
    (install / "main.exe").write_bytes(b"MZ")

    for name in ("rules.yaml", "log_paths.yaml", "file_scan.yaml"):
        (extracted / "conf" / name).write_text(f"# shipped {name}\n", encoding="utf-8")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(extracted), raising=False)
    monkeypatch.setattr(sys, "executable", str(install / "main.exe"))
    return paths, install, extracted


# --------------------------------------------------------------------------
# The bug
# --------------------------------------------------------------------------

def test_writes_never_land_in_the_extraction_directory(frozen):
    """The whole failure in one assertion: that directory does not survive the
    process, so a config written there is a config that reverts."""
    paths, install, extracted = frozen
    target = paths.writable_config_path("rules")
    assert str(extracted) not in target, "config would be written to _MEIPASS"
    assert str(install) in target


def test_writes_go_beside_the_executable(frozen):
    paths, install, _ = frozen
    assert paths.writable_config_path("rules") == str(install / "conf" / "rules.yaml")


def test_a_written_config_is_what_gets_read_back(frozen):
    """Read and write must agree, or a push takes effect nowhere."""
    paths, _, _ = frozen
    target = paths.writable_config_path("rules")
    pathlib.Path(target).write_text("# operator edit\n", encoding="utf-8")
    assert paths.config_path("rules") == target
    assert pathlib.Path(paths.config_path("rules")).read_text(encoding="utf-8") == "# operator edit\n"


def test_the_shipped_copy_is_used_until_one_is_pushed(frozen):
    """A fresh install has rules before anybody configures anything."""
    paths, _, extracted = frozen
    assert paths.config_path("rules") == str(extracted / "conf" / "rules.yaml")


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------

def test_seeding_copies_the_shipped_configs_out(frozen):
    paths, install, _ = frozen
    created = paths.seed_persistent_config()
    assert created
    for name in ("rules.yaml", "log_paths.yaml", "file_scan.yaml"):
        assert (install / "conf" / name).exists()


def test_seeding_never_overwrites_an_operators_config(frozen):
    """A config somebody pushed is their decision. A new build silently
    replacing it would undo a change nobody was told about - the same failure
    this module exists to remove, in the other direction."""
    paths, install, _ = frozen
    (install / "conf").mkdir(exist_ok=True)
    mine = install / "conf" / "rules.yaml"
    mine.write_text("# mine\n", encoding="utf-8")

    paths.seed_persistent_config()
    assert mine.read_text(encoding="utf-8") == "# mine\n"


def test_seeding_is_idempotent(frozen):
    paths, _, _ = frozen
    first = paths.seed_persistent_config()
    second = paths.seed_persistent_config()
    assert first and not second, "a second run should create nothing"


def test_seeding_does_nothing_from_source(paths):
    """Unfrozen, both directories are the repository's own `conf/` and there
    is nothing to copy anywhere."""
    assert paths.seed_persistent_config() == []


# --------------------------------------------------------------------------
# Running from source must behave exactly as it did
# --------------------------------------------------------------------------

def test_from_source_both_paths_are_the_repository_conf(paths):
    assert paths.bundled_config_dir() == paths.persistent_config_dir()
    assert paths.config_path("rules").endswith(os.path.join("conf", "rules.yaml"))


def test_the_repository_config_actually_resolves(paths):
    """If this breaks, a developer run loads no rules and detects nothing."""
    assert pathlib.Path(paths.config_path("rules")).exists()
    assert pathlib.Path(paths.config_path("log_paths")).exists()


# --------------------------------------------------------------------------
# The callers
# --------------------------------------------------------------------------

def _source(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _command(name: str) -> str:
    """One command function's statements, by AST.

    Not a slice between two markers: the bodies moved out of the route
    handlers into `cmd_*` functions so the channel could call the same code,
    and a slice would then have been reading whatever happened to sit between
    the markers instead.
    """
    import ast

    tree = ast.parse(_source("Sentora/main.py"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    raise AssertionError(f"{name} not found in main.py")


def test_the_config_commands_no_longer_walk_up_from_dunder_file():
    assert "agent_paths.config_path" in _command("cmd_get_config")
    assert "agent_paths.writable_config_path" in _command("cmd_set_config")
    for name in ("cmd_get_config", "cmd_set_config"):
        assert "os.path.dirname(os.path.abspath(__file__))" not in _command(name)


def test_the_route_and_the_channel_run_the_same_code():
    """Two implementations of "write the rules file" would drift, and the one
    that drifted would be reachable only in the deployments that had already
    moved to the channel - so the bug would appear on exactly the hosts nobody
    was still watching the old path on."""
    for handler, command in (("get_config", "cmd_get_config"),
                             ("set_config", "cmd_set_config")):
        assert command in _command(handler)
    dispatch = _command("dispatch_channel_request")
    assert "cmd_get_config" in dispatch
    assert "cmd_set_config" in dispatch


def test_the_reader_resolves_at_use_not_at_import():
    """A config pushed while the agent is running lands beside the executable.
    A path frozen at import would keep reading the build's copy until the next
    restart - so the change would appear to take and do nothing."""
    import ast
    extractor = _source("Sentora/modules/log_extractor/log_extractor.py")
    tree = ast.parse(extractor)
    body = next(ast.unparse(n) for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    assert "agent_paths.config_path('rules')" in body, \
        "the rules path is resolved outside main(), so a pushed config is " \
        "not read until the agent restarts"


def test_the_agent_seeds_on_startup():
    main = _source("Sentora/main.py")
    assert "seed_persistent_config()" in main
