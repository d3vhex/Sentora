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


# --------------------------------------------------------------------------
# Uninstall was sent to an endpoint that does not implement it
# --------------------------------------------------------------------------
#
# `trigger_self_destruct` pushed `action: "self_destruct"` to the agent's
# `/soar/execute`, which accepts only the members of its `ActionType` enum -
# and `self_destruct` is not one of them, so every push came back 501 "action
# not implemented". The agent implements it at its own `/self_destruct`
# endpoint, which the server never called.
#
# `restart_service` *is* in that enum. That is the entire reason restart
# appeared to work while uninstall did not.

import ast as _ast

APP = pathlib.Path(__file__).resolve().parent.parent / "app.py"
APP_TREE = _ast.parse(APP.read_text(encoding="utf-8"))
SOAR_SRC = (pathlib.Path(__file__).resolve().parent.parent / "Sentora"
            / "modules" / "soar" / "soar.py").read_text(encoding="utf-8")


def _app_fn(name: str) -> str:
    """A handler's statements, without its docstring.

    The docstrings here quote the endpoint that was wrong, so matching against
    them would fail on the prose that explains the fix.
    """
    for node in _ast.walk(APP_TREE):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            body = list(node.body)
            if (body and isinstance(body[0], _ast.Expr)
                    and isinstance(body[0].value, _ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            return "\n".join(_ast.unparse(n) for n in body)
    raise AssertionError(f"{name} not found in app.py")


def test_self_destruct_uses_the_agents_own_endpoint():
    code = _app_fn("trigger_self_destruct")
    assert "/self_destruct" in code
    assert "soar/execute" not in code, \
        "uninstall is being sent as a SOAR action again; the agent answers 501"


def test_the_agent_does_not_accept_it_as_a_soar_action():
    """Pinning the reason the above matters. If `self_destruct` is ever added
    to ActionType this test should be revisited deliberately, not silently."""
    actions = SOAR_SRC.split("class ActionType(Enum):", 1)[1].split("class ", 1)[0]
    assert "self_destruct" not in actions
    assert "restart_service" in actions, "the enum no longer looks as expected"


@pytest.mark.parametrize("handler,path", [
    ("trigger_restart", "/restart"),
    ("trigger_reload_auth", "/reload_auth"),
    ("trigger_self_destruct", "/self_destruct"),
])
def test_lifecycle_commands_go_to_their_own_endpoints(handler, path):
    code = _app_fn(handler)
    assert "_agent_lifecycle_command" in code
    assert path in code


def test_a_queued_command_is_not_reported_as_done():
    """"Sent" and "the agent did it" are different things to tell someone who
    has just clicked Uninstall."""
    code = _app_fn("_agent_lifecycle_command")
    assert '"delivered": "direct"' in code or "'delivered': 'direct'" in code
    assert '"delivered": "queued"' in code or "'delivered': 'queued'" in code
    assert "202" in code, "a queued command should not answer 200"


def test_a_queued_command_is_not_reported_as_failed_either():
    """The row is in the queue and the agent polls it, so an agent that is
    simply not answering this second has not failed."""
    code = _app_fn("_agent_lifecycle_command")
    assert '"status": "pending"' in code or "'status': 'pending'" in code


def test_the_command_is_durable_before_it_is_hurried():
    """Queue first, then push. The other order loses the command if the push
    raises."""
    code = _app_fn("_agent_lifecycle_command")
    assert code.index("INSERT INTO") < code.index("_agent_proxy")


def test_the_server_removes_the_autostart_itself():
    """Uninstall must not depend on the agent uninstalling itself correctly.

    The agent gained a `disable_autostart` step that runs before it deletes
    anything, and that is the right place for it - but it only exists in
    builds that carry it. An older binary answers "Destruction initiated",
    deletes its files, exits, and is restarted a minute later by the scheduled
    task's watchdog, while the server reads HTTP 200 and reports a completed
    uninstall.
    """
    assert "_remove_agent_autostart" in _app_fn("trigger_self_destruct")


def test_the_autostart_goes_before_the_agent_is_told_to_destroy_itself():
    """The other order leaves a window in which the watchdog restarts an agent
    that has already deleted half of itself."""
    code = _app_fn("trigger_self_destruct")
    assert code.index("_remove_agent_autostart") < code.index("_agent_lifecycle_command")


def test_it_uses_a_command_every_agent_version_accepts():
    """`run_cmd` is in every `ActionType`; `self_destruct` never was."""
    assert "run_cmd" in _app_fn("_remove_agent_autostart")


def test_the_command_matches_how_the_installer_set_it_up():
    code = _app_fn("_remove_agent_autostart")
    assert "SentoraAgent" in code
    assert "schtasks" in code
    assert "sentora-agent" in code
    assert "systemctl" in code


def test_an_unknown_os_sends_nothing():
    """Guessing a command for an OS we cannot identify is how an uninstall
    turns into an unrelated failure on the endpoint."""
    assert "OS is unknown" in _app_fn("_remove_agent_autostart")


def test_a_failure_removing_autostart_does_not_stop_the_uninstall():
    """This runs before the uninstall proper. Raising would leave the agent
    installed and the operator with no idea why."""
    code = _app_fn("_remove_agent_autostart")
    assert "except Exception" in code
    assert "failed to send" in code


def test_the_autostart_outcome_reaches_the_operator():
    """"Uninstalled" and "uninstalled, but the watchdog may bring it back" are
    different things to have been told."""
    assert "autostart_removal" in _app_fn("trigger_self_destruct")
    assert "if the agent comes back" in _app_fn("_remove_agent_autostart")


def test_an_absent_autostart_is_a_success_not_an_error():
    """Deleting something that is not there prints an error, and reporting
    that as the detail of a success read as "Autostart removed (ERROR: cannot
    find the file)"."""
    assert "was already absent" in _code_of("disable_autostart")


def test_the_removal_always_runs():
    """The check chooses the wording. It must not choose whether to act.

    An earlier version returned early when the autostart looked absent, to
    avoid that error message. `_autostart_still_present` answers False for any
    non-zero exit - schtasks missing from PATH, a permissions refusal, output
    it cannot read - so on any of those the agent deleted its files, exited,
    and was restarted by the watchdog it had never touched. A confusing
    message is worth less than an uninstall that happens.
    """
    code = _code_of("disable_autostart")
    head = code[:code.index("schtasks")]
    assert "return True" not in head, \
        "disable_autostart can still return before deleting anything"
    assert "was_present" in code, "the check should feed the wording, not the flow"


def test_success_is_decided_by_verification_not_by_the_command():
    """Both `schtasks /Delete` and `systemctl disable` report success in cases
    where the unit survives, and the next step is irreversible."""
    code = _code_of("disable_autostart")
    tail = code[code.rindex("_autostart_still_present"):]
    assert "still registered after removal" in tail


def test_console_output_is_decoded_with_the_oem_codepage():
    """`text=True` uses the locale codepage; console tools write in the OEM
    one. On a Turkish install schtasks produced mojibake that travelled all
    the way to the operator's screen."""
    source = MAIN.read_text(encoding="utf-8")
    assert "GetOEMCP" in source
    run = _code_of("_run")
    assert "text=True" not in run, "raw bytes, then decode deliberately"
    assert "_decode_console" in run


def test_the_operator_is_told_once():
    """The server removes the autostart and the agent removes it again, so
    both had something to say. Concatenated, two true halves read as a
    failure."""
    code = _app_fn("trigger_self_destruct")
    assert 'body["message"] = ' in code or "body['message'] = " in code
    assert "Autostart:" in code


def test_the_action_log_records_three_outcomes():
    """SUCCESS was written whenever the call was delivered, so a push the
    agent answered 501 to was logged as a completed uninstall - and anyone
    reading that log later had no way to know the host still had an agent."""
    code = _app_fn("_record_lifecycle")
    for outcome in ("SUCCESS", "QUEUED", "FAILED"):
        assert outcome in code
