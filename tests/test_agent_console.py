r"""An interactive shell for hosts that have no screen.

The screen stream was the only way to get onto a host, and on the machines
that matter it shows nothing - a headless server has no desktop, and the agent
now says so plainly. Correct, and not what an operator wanted: they wanted a
console.

This is the most dangerous interface in the product, so what is tested here is
mostly the limits rather than the happy path. It is worth being clear that it
adds no *capability*: `ActionType.RUN_CMD` already runs an arbitrary argv as
root or SYSTEM on any enrolled endpoint, behind the same authentication. This
is a better interface to the same power.

The PTY itself only exists on Linux, so its behaviour is exercised there and
the module's shape - framing, limits, refusals - is checked everywhere.
"""

import importlib.util
import json
import os
import pathlib
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "Sentora" / "modules" / "console.py"
IS_POSIX = os.name == "posix"


def _load():
    spec = importlib.util.spec_from_file_location("_console_under_test", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _body(name: str) -> str:
    """The statements of one class or function in console.py, docstring aside.

    By AST rather than by slicing the file between two markers, which is what
    these assertions used to do. Inserting `PipeSession` moved the boundaries
    and three tests started reading the wrong code - and one failed on prose
    in a docstring rather than on anything the module does.
    """
    import ast

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and node.name == name:
            statements = list(node.body)
            if (statements and isinstance(statements[0], ast.Expr)
                    and isinstance(statements[0].value, ast.Constant)
                    and isinstance(statements[0].value.value, str)):
                statements = statements[1:]
            return "\n".join(ast.unparse(s) for s in statements)
    raise AssertionError(f"{name} not found in console.py")


@pytest.fixture
def console():
    return _load()


# --------------------------------------------------------------------------
# Wire framing
# --------------------------------------------------------------------------

def test_output_is_framed_as_json(console):
    frame = json.loads(console.encode_output(b"hello\n"))
    assert frame == {"t": "o", "d": "hello\n"}


def test_output_survives_bytes_that_are_not_utf8(console):
    """A shell emits whatever a program printed. Raising on invalid UTF-8
    would kill a working session over one stray byte."""
    frame = json.loads(console.encode_output(b"\xff\xfe ok"))
    assert frame["t"] == "o"
    assert "ok" in frame["d"]


def test_input_frames_are_parsed(console):
    assert console.decode_input(json.dumps({"t": "i", "d": "ls\n"})) == \
        ("input", {"data": "ls\n"})
    assert console.decode_input(json.dumps({"t": "r", "cols": 120, "rows": 40})) == \
        ("resize", {"cols": 120, "rows": 40})


@pytest.mark.parametrize("raw", [
    "not json",
    "[]",
    '{"t": "i"}',              # no data
    '{"t": "i", "d": 42}',     # data is not a string
    '{"t": "r", "cols": "wide"}',
    '{"t": "zzz"}',
    "",
])
def test_a_malformed_frame_is_ignored_not_fatal(console, raw):
    """The peer is a browser. A stray frame must not take down a session
    somebody is working in."""
    kind, _ = console.decode_input(raw)
    assert kind == "ignore"


def test_exit_and_error_frames_are_distinguishable(console):
    """"the shell exited" and "no shell could start" call for different
    reactions from the operator, so they are different frames."""
    assert json.loads(console.encode_exit(0, "done"))["t"] == "x"
    assert json.loads(console.encode_error("no pty"))["t"] == "e"


# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------

def test_windows_says_what_is_missing_when_conpty_is_absent(console, monkeypatch):
    """A pipe-backed shell that looks like a terminal and behaves like a
    broken one is worse than saying ConPTY is not shipped."""
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    monkeypatch.setattr(console, "winpty_available", lambda: False)
    reason = console.describe_unavailable()
    assert "pywinpty" in reason
    assert "run_cmd" in reason, "the reason should name what to use instead"

    with pytest.raises(console.ConsoleUnavailable):
        console.WinPtySession()


def test_windows_uses_conpty_when_it_is_there(console, monkeypatch):
    """The Windows path is ConPTY or nothing. `new_session` must not fall back
    to the POSIX PTY, which does not exist there."""
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    calls = []
    monkeypatch.setattr(console, "WinPtySession", lambda argv=None: calls.append(argv) or "win")
    assert console.new_session(["powershell.exe"]) == "win"
    assert calls == [["powershell.exe"]]


def test_the_posix_pty_is_refused_on_windows(console, monkeypatch):
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    with pytest.raises(console.ConsoleUnavailable):
        console.PtySession()


def test_conpty_is_declared_as_a_dependency():
    """`pywinpty` has to be installed for the build to bundle it, and marked
    Windows-only or a Linux build tries to resolve a package that has no
    Linux wheel."""
    reqs = (ROOT / "Sentora" / "requirements.txt").read_text(encoding="utf-8")
    line = next(l for l in reqs.splitlines() if l.startswith("pywinpty"))
    assert "platform_system == 'Windows'" in line


def test_a_dead_shell_says_why(console):
    """"the shell exited" is not a diagnosis.

    The first version swallowed the reason in the drain loop, so a shell that
    died on startup and one the operator typed `exit` into reached the browser
    as the same sentence. The module keeps being about exactly this failure,
    and it was no better for being mine.
    """
    source = MODULE.read_text(encoding="utf-8")
    drain = source[source.index("def _drain"):]
    drain = drain[:drain.index("def close")]
    assert "exit_reason" in drain
    assert "except Exception as e" in drain, "the reason is being swallowed again"
    assert "argv was" in drain, "the reason should name what was launched"


def test_the_reason_reaches_the_browser():
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    block = main[main.index('@app.websocket("/console/ws")'):]
    block = block[:block.index('@app.websocket("/screen/ws")')]
    assert "exit_reason" in block


def test_the_shell_does_not_start_in_the_system_profile():
    r"""The agent runs as SYSTEM, whose home is
    `C:\Windows\system32\config\systemprofile` - a directory a shell has no
    business starting in and which some policies deny. A working directory
    that cannot be entered makes the shell exit before printing anything.
    """
    win = _body("WinPtySession")
    assert "expanduser" not in win, \
        "the shell would start in C:\\Windows\\system32\\config\\systemprofile"
    assert "SystemDrive" in win


def test_a_startup_race_is_not_read_as_an_exit(console):
    """ConPTY reports nothing for a moment while the shell starts, and
    `isalive()` can be false in that window. Treating the first empty read as
    an exit ended every session instantly."""
    source = MODULE.read_text(encoding="utf-8")
    drain = source[source.index("def _drain"):]
    drain = drain[:drain.index("def close")]
    assert "idle_reads" in drain


def test_the_shell_is_launched_by_absolute_path_on_windows(console, monkeypatch):
    """The agent runs as SYSTEM, whose PATH is not an interactive login's. A
    name that does not resolve makes ConPTY build the pseudoconsole - so
    `spawn` succeeds - and the process inside it die at once, which arrives as
    "the shell exited" with nothing behind it."""
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(console.os.path, "exists", lambda p: "powershell.exe" in p)
    argv = console.default_shell()
    assert argv[0].lower().endswith("powershell.exe")
    assert "\\" in argv[0], "a bare name is what caused this"


def test_a_shell_that_dies_at_once_is_caught_at_startup(console):
    """`spawn` succeeding only means ConPTY built the pseudoconsole. Checking
    a moment later puts the fact in the log when it is true, rather than
    leaving it to be inferred from a failed write."""
    win = _body("WinPtySession")
    assert "isalive" in win
    assert "exited immediately" in win


def test_a_deliberate_close_keeps_its_own_reason(console):
    """Setting `_closed` makes the drain loop exit without a reason of its
    own, so a session torn down by a failed write reported the generic "the
    shell exited" - which is how the actual cause stayed hidden."""
    source = MODULE.read_text(encoding="utf-8")
    close = source[source.index("    def close(self, why"):]
    close = close[:close.index("    def read")]
    assert "if why and not self.exit_reason" in close


def test_the_control_c_status_is_named_not_just_printed(console):
    """3221225786 is unreadable, and the cause is not "the shell crashed" -
    the console it was attached to was destroyed under it."""
    source = MODULE.read_text(encoding="utf-8")
    assert "STATUS_CONTROL_C_EXIT = 3221225786" in source
    assert "the console was destroyed under it" in source


def test_a_console_is_allocated_before_hosting_a_pseudoconsole(console):
    """Task Scheduler starts the agent with no console at all.
    `CreatePseudoConsole` still succeeds there, which is why `spawn` reported
    success while the shell inside it was killed at once."""
    source = MODULE.read_text(encoding="utf-8")
    assert "AllocConsole" in source
    assert "ShowWindow" in source, "a service must not put a console on a desktop"


def test_more_than_one_shell_is_tried(console, monkeypatch):
    """The failure is a property of the console, not of the shell, and
    cmd.exe starts under conditions PowerShell will not."""
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(console.os.path, "exists", lambda p: True)
    candidates = console.windows_shell_candidates()
    assert len(candidates) >= 2
    assert candidates[0][0].lower().endswith("powershell.exe")
    assert candidates[-1][0].lower().endswith("cmd.exe")


def test_every_attempt_is_reported(console, monkeypatch):
    """Both routes, and why each failed.

    "no console available" on its own sent an operator looking in the wrong
    place for two days. When neither hosting it here nor hosting it in the
    user's session works, the message has to carry both reasons - and the
    first version referred to a name Python had already unbound, so the one
    path whose whole purpose is to explain itself raised UnboundLocalError.
    """
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    monkeypatch.setattr(console, "ensure_console", lambda: False)
    monkeypatch.setattr(console, "windows_shell_candidates",
                        lambda: [["a.exe"], ["b.exe"]])

    def _fail(argv):
        raise console.ConsoleUnavailable(f"{argv[0]} died")

    def _no_helper():
        raise console.ConsoleUnavailable("nobody is logged in")

    def _no_pipe():
        raise console.ConsoleUnavailable("no shell to pipe to")

    monkeypatch.setattr(console, "WinPtySession", _fail)
    monkeypatch.setattr(console, "HelperSession", _no_helper)
    # Stubbed too, or this test spawns a real shell on the machine running it
    # and never reaches the message it is about.
    monkeypatch.setattr(console, "PipeSession", _no_pipe)

    with pytest.raises(console.ConsoleUnavailable) as excinfo:
        console.new_session()
    message = str(excinfo.value)
    assert "a.exe died" in message
    assert "b.exe died" in message
    assert "nobody is logged in" in message
    assert "no shell to pipe to" in message


# --------------------------------------------------------------------------
# Session 0 cannot host a pseudoconsole
# --------------------------------------------------------------------------
#
# Both PowerShell and cmd.exe were killed at once with STATUS_CONTROL_C_EXIT,
# with a console allocated and without one. That is the wall the screen stream
# hit, and it has the same answer: run the part that needs a desktop session
# inside one.

def test_the_helper_is_the_same_binary(console, monkeypatch):
    """One shipped file. A second executable would be another thing to sign,
    ship and get out of step - the same reason the screen helper is."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Program Files\Sentora-Agent\main.exe")
    argv = console._helper_command()
    assert argv[0].endswith("main.exe")
    assert "--console-helper" in argv


def test_the_agent_routes_the_helper_flag_before_anything_starts():
    """It must not take the single-instance lock or start a collector."""
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    block = main[main.index('if "--console-helper" in sys.argv:'):]
    block = block[:block.index("app.config.AUTO_RELOAD")]
    assert "console_helper_main" in block


def test_the_direct_path_is_tried_first(console):
    """It is the only one that works when the agent is not a service - a
    developer running it from a terminal - and it costs a few hundred ms."""
    source = MODULE.read_text(encoding="utf-8")
    body = source[source.index("def new_session"):]
    assert body.index("new_direct_session") < body.index("HelperSession()")


def test_the_helper_needs_somebody_logged_in(console):
    """A host with nobody logged in has no console, exactly as it has no
    screen, and saying so is the honest answer."""
    source = MODULE.read_text(encoding="utf-8")
    launcher = source[source.index("def _spawn_user_session_helper"):]
    launcher = launcher[:launcher.index("class HelperSession")]
    assert "active_console_session" in launcher
    assert "nobody is logged in" in launcher


def test_the_parents_pipe_ends_are_not_inheritable(console):
    """Otherwise the pipe never reports EOF when the helper exits and the
    reader blocks forever - the same trap the screen helper documents."""
    source = MODULE.read_text(encoding="utf-8")
    launcher = source[source.index("def _spawn_user_session_helper"):]
    launcher = launcher[:launcher.index("class HelperSession")]
    assert "HANDLE_FLAG_INHERIT" in launcher
    assert launcher.count("SetHandleInformation") >= 2, \
        "both of our own ends have to be cleared"


def test_the_helper_keeps_stray_prints_off_the_frame_stream(console):
    """The pipe is the child's stdout, so one stray print lands mid-frame."""
    source = MODULE.read_text(encoding="utf-8")
    helper = source[source.index("def console_helper_main"):]
    helper = helper[:helper.index("def new_direct_session")]
    assert "sys.stdout = sys.stderr" in helper


def test_the_privilege_change_is_stated(console):
    """The shell runs as the logged-in user, not SYSTEM. That is a real change
    and belongs in the code rather than being discovered."""
    source = MODULE.read_text(encoding="utf-8")
    assert "not SYSTEM" in source


# --------------------------------------------------------------------------
# The fallback, and being honest about it
# --------------------------------------------------------------------------
#
# ConPTY does not work in this deployment: both shells are killed at once with
# STATUS_CONTROL_C_EXIT, in session 0 and in the logged-in user's session,
# with a console allocated and without one. The argument against a pipe-backed
# shell was right - no echo, no line editing, `vim` hangs - and a limited
# console that works still beats an elegant one that does not exist. What
# makes it defensible is that the limits are announced.

def test_the_helper_must_report_ready_before_it_counts(console):
    """Starting the process is not the same as having a console.

    Treating it as such made the pipe fallback unreachable: the helper
    launched, failed to host anything, and reported that in a frame nobody was
    waiting for - by which time the constructor had already returned a session
    that would never produce output, so nothing ever raised and nothing else
    was tried.
    """
    body = _body("HelperSession")
    assert "_ready.wait" in body
    assert "_startup_error" in body
    assert "raise ConsoleUnavailable" in body


def test_a_helper_that_dies_silently_does_not_hang_the_caller(console):
    """If the pipe closes before the helper says anything, the constructor
    must not wait out the full timeout for an answer that is not coming."""
    body = _body("HelperSession")
    assert "exited at once" in body


def test_the_helper_announces_that_it_hosted_one(console):
    helper = _body("console_helper_main")
    assert '"t": "m"' in helper or "'t': 'm'" in helper


def test_the_pipe_fallback_is_the_last_resort(console):
    source = MODULE.read_text(encoding="utf-8")
    body = source[source.index("def new_session"):]
    assert body.index("new_direct_session") < body.index("HelperSession()")
    assert body.index("HelperSession()") < body.index("PipeSession()")


def test_all_three_failures_are_reported(console):
    source = MODULE.read_text(encoding="utf-8")
    body = source[source.index("def new_session"):]
    for label in ("Pseudoconsole here", "In the user's session", "Behind pipes"):
        assert label in body, f"{label} missing from the final message"


def test_the_session_announces_what_it_is(console):
    """The browser has to know whether it is driving a terminal or a pipe
    before the first keystroke, not after."""
    class _Pipe:
        mode = "pipe"

    frame = json.loads(console.encode_mode(_Pipe()))
    assert frame["t"] == "m"
    assert frame["mode"] == "pipe"
    assert "echoed locally" in frame["note"]
    assert "vim" in frame["note"], "the note should name what will not work"


def test_a_real_terminal_says_so_without_a_warning(console):
    class _Pty:
        mode = "pty"

    frame = json.loads(console.encode_mode(_Pty()))
    assert frame["mode"] == "pty"
    assert frame["note"] == ""


def test_the_mode_is_sent_before_any_output():
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    block = main[main.index('@app.websocket("/console/ws")'):]
    block = block[:block.index('@app.websocket("/screen/ws")')]
    assert "encode_mode" in block
    assert block.index("encode_mode") < block.index("encode_output")


def test_the_pipe_shell_does_not_echo(console, monkeypatch):
    """`powershell.exe` with a redirected stdin still behaves as an
    interactive host: it draws a prompt and writes back every line it reads.
    With the browser echoing too, one keypress appeared two or three times and
    there was no telling which copy was real. `-Command -` makes it a command
    processor instead."""
    monkeypatch.setattr(console, "IS_WINDOWS", True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(console.os.path, "exists", lambda p: "powershell.exe" in p)
    argv = console.pipe_shell()
    assert argv[-2:] == ["-Command", "-"]


def test_the_pipe_shell_is_not_the_interactive_one(console, monkeypatch):
    """`default_shell` is for a pty, where the terminal echoes and the shell
    should be interactive. Using it behind a pipe is what caused the double
    echo, so the two must not converge by accident."""
    monkeypatch.setattr(console, "IS_WINDOWS", False)
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(console.os.path, "exists", lambda p: True)
    assert "-i" in console.default_shell()
    assert "-i" not in console.pipe_shell()


def test_the_pipe_session_uses_the_non_echoing_shell(console):
    assert "pipe_shell()" in _body("PipeSession")


def test_enter_is_translated_for_a_pipe(console, monkeypatch):
    """xterm sends \\r for Enter; a pipe-fed shell wants \\n and would
    otherwise sit there having received a command with no line ending."""
    source = MODULE.read_text(encoding="utf-8")
    pipe = source[source.index("class PipeSession"):]
    pipe = pipe[:pipe.index("def _helper_command")]
    assert 'replace(b"\\r\\n", b"\\n")' in pipe


def test_the_helper_log_goes_somewhere_writable(console):
    r"""The helper runs as the logged-in user - that is the point of launching
    it into their session - and `C:\Program Files\Sentora-Agent` is not
    writable by them. The first version wrote there, the write failed, and the
    last-resort logger swallowed it: the one process that knew why the console
    failed produced no file at all."""
    body = _body("helper_log_path")
    assert "TEMP" in body
    # The statements, not the docstring - which explains the bug and so
    # naturally names the directory the code must not use.
    assert "Program Files" not in body


def test_conpty_is_bundled_by_the_windows_build():
    """PyInstaller does not follow the import inside `WinPtySession.__init__`,
    so without this the shipped agent reports ConPTY missing on a host that
    has it."""
    build = (ROOT / "Sentora" / "build_agent.ps1").read_text(encoding="utf-8")
    assert '"winpty"' in build


def test_a_shell_that_does_not_exist_is_not_launched(console, monkeypatch):
    """$SHELL can name something that has been uninstalled. Spawning it fails
    at the pty, where the reason is much harder to see than here.

    `os.path.exists` is stubbed rather than trusted, so this checks the choice
    rather than the filesystem of whichever machine runs the tests.
    """
    monkeypatch.setattr(console, "IS_WINDOWS", False)
    monkeypatch.setenv("SHELL", "/definitely/not/here")
    monkeypatch.setattr(console.os.path, "exists",
                        lambda p: p in ("/bin/bash", "/bin/sh"))
    assert console.default_shell()[0] == "/bin/bash"


def test_the_environment_shell_wins_when_it_is_real(console, monkeypatch):
    monkeypatch.setattr(console, "IS_WINDOWS", False)
    monkeypatch.setenv("SHELL", "/usr/bin/zsh")
    monkeypatch.setattr(console.os.path, "exists", lambda p: True)
    assert console.default_shell()[0] == "/usr/bin/zsh"


def test_a_host_with_no_shell_says_so(console, monkeypatch):
    monkeypatch.setattr(console, "IS_WINDOWS", False)
    monkeypatch.delenv("SHELL", raising=False)
    monkeypatch.setattr(console.os.path, "exists", lambda p: False)
    with pytest.raises(console.ConsoleUnavailable):
        console.default_shell()


# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

@pytest.mark.skipif(not IS_POSIX, reason="a PTY needs a POSIX host")
def test_a_session_reads_back_what_the_shell_prints(console):
    session = console.PtySession(["/bin/sh"])
    try:
        session.write("echo sentora-console-ok\n")
        seen = b""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and b"sentora-console-ok" not in seen:
            chunk = session.read(0.2)
            if chunk is None:
                break
            seen += chunk
        assert b"sentora-console-ok" in seen
    finally:
        session.close()


@pytest.mark.skipif(not IS_POSIX, reason="a PTY needs a POSIX host")
def test_closing_kills_the_whole_process_group(console):
    """A backgrounded job that outlives the console has nothing left pointing
    at who ran it."""
    session = console.PtySession(["/bin/sh"])
    session.write("sleep 300 &\n")
    time.sleep(0.5)
    # Read the group id while the shell is alive: once it is gone `getpgid`
    # has nothing to answer from.
    pgid = os.getpgid(session.proc.pid)
    session.close()

    # Polled rather than slept on. `killpg` is delivered asynchronously, and a
    # fixed sleep is either a flake on a loaded machine or a second wasted on
    # every run. The first version also asked `getpgid` about a pid the parent
    # had killed but never reaped - a zombie answers that quite happily, so
    # the check passed on Windows by being skipped and failed on CI by being
    # true.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.05)
    pytest.fail("the shell's process group outlived the session")


@pytest.mark.skipif(not IS_POSIX, reason="a PTY needs a POSIX host")
@pytest.mark.skipif(not IS_POSIX, reason="a PTY needs a POSIX host")
def test_the_shell_is_reaped_not_left_a_zombie(console):
    """A killed child that is never waited on stays a zombie for the life of
    the agent, and the agent is long-lived: a console opened a few times a day
    would accumulate them quietly."""
    session = console.PtySession(["/bin/sh"])
    time.sleep(0.3)
    session.close()
    assert session.proc.poll() is not None, \
        "the shell was killed but never waited on"


@pytest.mark.skipif(not IS_POSIX, reason="a PTY needs a POSIX host")
def test_only_one_session_at_a_time(console):
    """Two concurrent roots on one host is an accident that gets blamed on the
    wrong person, because the audit trail cannot tell them apart."""
    first = console.open_session(["/bin/sh"])
    try:
        with pytest.raises(console.ConsoleUnavailable) as excinfo:
            console.open_session(["/bin/sh"])
        assert "already open" in str(excinfo.value)
    finally:
        console.close_active("test")
    assert first.closed


def test_an_idle_session_expires(console, monkeypatch):
    """Enforced by the agent, not the browser: a tab that was closed cannot
    time anything out, and an abandoned root shell is the case that matters."""
    monkeypatch.setattr(console, "IDLE_TIMEOUT_S", 1)
    monkeypatch.setattr(console, "MAX_SESSION_S", 9999)

    class _Fake(console.PtySession):
        def __init__(self):            # no pty, just the clock
            self.started_at = time.monotonic() - 5
            self.last_input_at = time.monotonic() - 5
            self._closed = False

    assert "idle" in (_Fake().expired() or "")


def test_a_long_session_expires_even_while_busy(console, monkeypatch):
    """Typing forever should not keep a root shell open forever."""
    monkeypatch.setattr(console, "IDLE_TIMEOUT_S", 9999)
    monkeypatch.setattr(console, "MAX_SESSION_S", 1)

    class _Fake(console.PtySession):
        def __init__(self):
            self.started_at = time.monotonic() - 5
            self.last_input_at = time.monotonic()   # active right now
            self._closed = False

    assert "open for more than" in (_Fake().expired() or "")


def test_a_fresh_session_has_not_expired(console):
    class _Fake(console.PtySession):
        def __init__(self):
            self.started_at = time.monotonic()
            self.last_input_at = time.monotonic()
            self._closed = False

    assert _Fake().expired() is None


# --------------------------------------------------------------------------
# The wiring
# --------------------------------------------------------------------------

def _source(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_the_agent_endpoint_requires_authentication():
    main = _source("Sentora/main.py")
    block = main[main.index('@app.websocket("/console/ws")'):]
    block = block[:block.index('@app.websocket("/screen/ws")')]
    assert "_ws_authorized(request)" in block
    assert "1008" in block, "an unauthorised console must be refused, not opened"


def test_the_agent_always_tears_the_session_down():
    """Every exit path. A shell left running with nobody attached is the worst
    outcome this endpoint has."""
    main = _source("Sentora/main.py")
    block = main[main.index('@app.websocket("/console/ws")'):]
    block = block[:block.index('@app.websocket("/screen/ws")')]
    assert "finally:" in block
    assert "close_active" in block


def test_the_proxy_is_gated_by_the_permission_that_governs_run_cmd():
    """`read_telemetry` gates the screen stream because that is an
    observation. This is a root shell, and `run_cmd` - the same power - is
    gated by `manage_soar`."""
    app = _source("app.py")
    block = app[app.index('@app.websocket("/console-proxy/<agent>")'):]
    block = block[:block.index("async def console_proxy")]
    assert 'require_permission("manage_soar")' in block


def test_opening_a_console_is_audited():
    """Audited on open rather than on close: a session that ends because the
    server died would otherwise leave no record that it happened."""
    app = _source("app.py")
    block = app[app.index("async def console_proxy"):]
    block = block[:block.index("async def _console_relay")]
    assert "CONSOLE_OPEN" in block


def test_the_proxy_tries_every_known_address():
    app = _source("app.py")
    block = app[app.index("async def console_proxy"):]
    block = block[:block.index("async def _console_relay")]
    assert "_agent_http_bases" in block
    assert "for base in bases" in block
