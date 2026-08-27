r"""Self-destruct must remove the agent, and nothing else.

It ran `Remove-Item -Recurse -Force (Get-Item -Path .).FullName` on Windows and
`rm -rf "$(pwd)"` elsewhere - the *working* directory, not the install
directory. A Scheduled Task registered without a start-in path inherits its
working directory, and for a SYSTEM task that is C:\Windows\System32. The
agent runs elevated, so the command would have been carried out.

An uninstall that can take out the host is worse than no uninstall.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

MAIN = pathlib.Path(__file__).resolve().parent.parent / "Sentora" / "main.py"
SRC = MAIN.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _load_target_resolver(agent_dir, marker_exists=True):
    """Compile `_destruction_target` alone, with AGENT_DIR pointed at a path."""
    import os as _os
    nodes = [n for n in TREE.body
             if getattr(n, "name", None) == "_destruction_target"
             or (isinstance(n, ast.Assign)
                 and getattr(n.targets[0], "id", "") == "_UNDELETABLE")]
    assert len(nodes) == 2, [getattr(n, "name", None) for n in nodes]
    nodes.sort(key=lambda n: n.lineno)

    ns = {"os": _os, "AGENT_DIR": str(agent_dir)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<sd>", "exec"), ns)
    return ns["_destruction_target"]


def test_a_real_install_directory_is_accepted(tmp_path):
    (tmp_path / "main.py").write_text("# agent", encoding="utf-8")
    resolve = _load_target_resolver(tmp_path)
    assert resolve() == str(tmp_path.resolve())


def test_a_frozen_install_is_accepted(tmp_path):
    (tmp_path / "SentoraAgent.exe").write_bytes(b"MZ")
    resolve = _load_target_resolver(tmp_path)
    assert resolve() == str(tmp_path.resolve())


def test_a_directory_without_the_agent_is_refused(tmp_path):
    """The System32 case: the path resolved, but the agent is not in it."""
    resolve = _load_target_resolver(tmp_path)
    assert resolve() is None


@pytest.mark.parametrize("path", [
    "/", "/usr", "/etc", "/home", "/var",
    r"C:\ ".strip(), r"C:\Windows", r"C:\Windows\System32",
    r"C:\Program Files", r"C:\Users",
])
def test_system_directories_are_refused(path):
    """Even if somebody drops a main.py in one of them."""
    resolve = _load_target_resolver(path)
    assert resolve() is None, f"{path} was accepted as a deletion target"


def test_case_and_trailing_separator_do_not_bypass_the_list():
    for variant in (r"c:\windows\system32" + "\\", r"C:\WINDOWS\SYSTEM32",
                    "/usr/", "/USR"):
        assert _load_target_resolver(variant)() is None, variant


def test_the_handler_refuses_rather_than_guessing():
    code = _code_of("perform_destruction")
    assert "REFUSED" in code
    assert "_destruction_target" in code


# --------------------------------------------------------------------------
# Uninstalling means removing what starts the agent
# --------------------------------------------------------------------------
#
# Self-destruct deleted the install directory and exited, and the agent came
# back: the Windows scheduled task carries `-RestartCount 99` with a one
# minute interval and a fifteen-minute watchdog trigger, whose entire purpose
# is to start the agent whenever it is not running. Exiting is the condition
# that watchdog reverses. Meanwhile the console showed the action completed.


def test_autostart_is_removed_before_anything_is_deleted():
    """Order is the whole fix. Deleting files while the watchdog is armed does
    not uninstall the agent, it makes it restart from a damaged install."""
    code = _code_of("perform_destruction")
    disable_at = code.find("disable_autostart")
    delete_at = code.find("Popen")
    assert disable_at != -1, "perform_destruction no longer disables autostart"
    assert delete_at != -1, "perform_destruction no longer deletes anything"
    assert disable_at < delete_at, "files are deleted before autostart is removed"


def test_a_failed_autostart_removal_deletes_nothing():
    """A stale install that still runs is recoverable. A watchdog relaunching
    a half-deleted binary is not."""
    code = _code_of("perform_destruction")
    head = code[:code.find("Popen")]
    assert "if not removed" in head
    assert "os._exit(1)" in head


def test_removal_is_verified_not_assumed():
    """`schtasks /Delete` and `systemctl disable` both report success in cases
    where the unit survives, and the next step is irreversible."""
    code = _code_of("disable_autostart")
    assert "_autostart_still_present" in code
    # The check has to gate the answer, not merely be called next to it.
    assert "still registered" in code


def test_the_linux_unit_file_is_removed_not_just_disabled():
    """`disable` drops the enablement symlink and leaves the unit, so
    `systemctl start` still works and a later `enable` brings it all back."""
    code = _code_of("disable_autostart")
    assert "/etc/systemd/system/" in code
    assert "daemon-reload" in code


def test_deletion_failures_are_not_silenced():
    """A running executable is locked on Windows, so removal genuinely fails -
    and it failed exactly when the watchdog had relaunched the agent, which is
    the case an operator most needs to hear about."""
    code = _code_of("perform_destruction")
    assert "SilentlyContinue" not in code, "a failed uninstall reports nothing"
    assert "FAILED to remove" in code


def test_the_uninstall_log_lives_outside_the_deleted_directory():
    """Everything the agent normally logs goes through the directory being
    deleted, so a failed uninstall would explain itself into a file that no
    longer exists."""
    source = MAIN.read_text(encoding="utf-8")
    assert "UNINSTALL_LOG" in source
    for marker in ("ProgramData", "/var/log/"):
        assert marker in source, f"{marker} missing from the uninstall log path"


def _code_of(name: str) -> str:
    """A function's source with its docstring removed.

    These docstrings quote the old, dangerous commands so the reason survives
    in the code. Matching against them would make the tests pass or fail on
    the prose rather than the behaviour.
    """
    fn = next(n for n in ast.walk(TREE)
              if isinstance(n, ast.FunctionDef) and n.name == name)
    body = list(fn.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return "\n".join(ast.unparse(n) for n in body)


def test_the_command_no_longer_targets_the_working_directory():
    code = _code_of("perform_destruction")
    assert "$(pwd)" not in code
    assert "Get-Item -Path ." not in code


def test_the_path_is_not_handed_to_a_shell_to_re_parse():
    r"""`rm -rf $(pwd)` splits on spaces; `C:\Program Files\...` would have
    deleted `C:\Program`."""
    code = _code_of("perform_destruction")
    assert "shell=True" not in code
    assert "-LiteralPath" in code      # Windows: not treated as a wildcard
    assert '"$0"' in code              # POSIX: passed as an argument
