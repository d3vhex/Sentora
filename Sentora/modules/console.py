r"""An interactive shell on the endpoint, for hosts that have no screen.

Why this exists
---------------
The screen stream was the only way to "get onto" a host, and on the machines
that matter it shows nothing: a headless server has no desktop, `mss` cannot
open a capture, and the honest answer - which the agent now gives - is that
there is no screen to stream. Correct, and not what an operator wanted. What
they wanted was a console.

Not a new power
---------------
`ActionType.RUN_CMD` already executes an arbitrary argv as root or SYSTEM on
any enrolled endpoint, from the same console, behind the same authentication.
An interactive session is a better interface to a capability that is already
there, not an additional one - and it is the honest interface, because a
one-shot `run_cmd` is what an operator reaches for when they wanted a shell
and then runs twenty times.

That said, it is still the most dangerous thing in the product, so the limits
below are part of the design rather than hardening added later.

Limits, and why each one
------------------------
**One session per agent.** A shell is not a resource to pool. Several
concurrent roots on one host is an accident waiting to be blamed on the wrong
person, and the audit trail cannot tell them apart.

**Idle and absolute timeouts.** A forgotten root shell on a production host is
a liability that grows quietly. Both are enforced by the agent, not the
browser: a tab that was closed cannot time anything out.

**The child dies with the session.** The shell is started in its own session
(`setsid`), so teardown kills the whole process group. Without that a
`sleep 9999 &` outlives the console that started it and nothing is left
pointing at who ran it.

Platforms
---------
Linux gets a real PTY, which is what makes editors, job control and
line-editing work. Windows needs ConPTY, reached through `pywinpty`, which the
agent does not ship - so on Windows this reports exactly that rather than
offering a pipe-backed shell that looks like a terminal and behaves like a
broken one.
"""

from __future__ import annotations

import json
import os
import platform
import signal
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"

# A shell nobody has typed into for this long is a shell nobody is using.
IDLE_TIMEOUT_S = int(os.getenv("CONSOLE_IDLE_TIMEOUT", "900"))       # 15 min
# And one that has been open this long should be reopened deliberately.
MAX_SESSION_S = int(os.getenv("CONSOLE_MAX_SESSION", "3600"))        # 1 hour

READ_CHUNK = 65536

# How long to wait for the console helper to report that it hosted a console.
# Long enough for a cold process start in another session, short enough that an
# operator is not left looking at a blank pane while the fallback waits.
HELPER_READY_TIMEOUT_S = float(os.getenv("CONSOLE_HELPER_TIMEOUT", "12"))

# Wire format. JSON both ways: terminal traffic is small, and a single framed
# type removes the "is this control or data" ambiguity that a mixed
# text/binary protocol has to resolve by inspection.
#
#   in   {"t": "i", "d": "ls\n"}            keystrokes
#        {"t": "r", "cols": 120, "rows": 30} window resize
#   out  {"t": "o", "d": "..."}             output
#        {"t": "x", "code": 0, "why": ""}   the session ended
#        {"t": "e", "d": "..."}             it could not start


class ConsoleUnavailable(Exception):
    """No interactive console here, with a reason fit to show an operator."""


def _close_fd(fd: int) -> None:
    """Release a file descriptor we are finished with.

    The one place in this module where a failure is swallowed, and it is
    swallowed because the only way this fails is that the descriptor is
    already closed - which is the state we were asking for. Every other
    failure here is reported, because everywhere else the reason is the thing
    an operator needs.
    """
    try:
        os.close(fd)
    except OSError:
        pass


def default_shell() -> list[str]:
    """The shell to start, honouring $SHELL when it names something real."""
    if IS_WINDOWS:
        # An absolute path, not a bare name.
        #
        # The agent runs as SYSTEM, and PATH in that context is not the one an
        # interactive login gets. A name that does not resolve makes ConPTY
        # create the pseudoconsole - so `spawn` succeeds - and the process
        # inside it die at once, which arrives as "the shell exited" with
        # nothing behind it.
        root = os.environ.get("SystemRoot", r"C:\Windows")
        for candidate in (
            os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            os.path.join(root, "System32", "cmd.exe"),
        ):
            if os.path.exists(candidate):
                return [candidate, "-NoLogo", "-NoProfile"] \
                    if candidate.endswith("powershell.exe") else [candidate]
        return ["powershell.exe", "-NoLogo", "-NoProfile"]
    shell = os.environ.get("SHELL", "")
    if shell and os.path.exists(shell):
        return [shell, "-i"]
    for candidate in ("/bin/bash", "/bin/sh"):
        if os.path.exists(candidate):
            return [candidate, "-i"]
    raise ConsoleUnavailable("no shell found on this host (/bin/bash, /bin/sh)")


#: 0xC000013A. The process was ended by a console control event rather than
#: exiting on its own - the console it was attached to went away.
STATUS_CONTROL_C_EXIT = 3221225786


def ensure_console() -> bool:
    """Give this process a console if it has none. Returns whether it has one.

    The agent is a service in session 0 and Task Scheduler starts it with no
    console at all. `CreatePseudoConsole` still succeeds there - which is why
    `spawn` reported success - but the shell inside it was killed at once with
    `STATUS_CONTROL_C_EXIT`, the status a process gets when the console it is
    attached to is destroyed.

    Allocating one first gives ConPTY's `conhost` something to attach to. The
    window is hidden immediately: a service must not put a console box on
    somebody's desktop, and in session 0 there is no desktop to put it on.
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # `GetConsoleWindow` is NULL for a process started with
        # CREATE_NO_WINDOW even though it *has* a console, so asking that
        # alone made this try to allocate a second one and report failure.
        # A non-zero console codepage is the reliable "I am attached to one".
        if kernel32.GetConsoleWindow() or kernel32.GetConsoleCP():
            return True
        if not kernel32.AllocConsole():
            return False
        handle = kernel32.GetConsoleWindow()
        if handle:
            ctypes.windll.user32.ShowWindow(handle, 0)   # SW_HIDE
        return True
    except Exception as e:
        print(f"[console] could not allocate a console: {e}", flush=True)
        return False


def windows_shell_candidates() -> list[list[str]]:
    """Shells to try, best first.

    More than one because the failure mode being worked around is a property
    of the console rather than of the shell, and `cmd.exe` starts under
    conditions PowerShell will not. Trying the second costs a few hundred
    milliseconds and is the difference between a working console and a
    message saying there is none.
    """
    root = os.environ.get("SystemRoot", r"C:\Windows")
    powershell = os.path.join(root, "System32", "WindowsPowerShell",
                              "v1.0", "powershell.exe")
    cmd = os.path.join(root, "System32", "cmd.exe")
    candidates = []
    if os.path.exists(powershell):
        candidates.append([powershell, "-NoLogo", "-NoProfile"])
    if os.path.exists(cmd):
        candidates.append([cmd])
    return candidates or [["powershell.exe", "-NoLogo", "-NoProfile"]]


def winpty_available() -> bool:
    """Whether ConPTY is reachable from this build."""
    if not IS_WINDOWS:
        return False
    try:
        import winpty  # noqa: F401
        return True
    except Exception:
        return False


def describe_unavailable() -> str:
    """Why an interactive console cannot run here."""
    if IS_WINDOWS:
        if not winpty_available():
            return ("an interactive console on Windows needs ConPTY through "
                    "pywinpty, which this agent build does not ship. Rebuild "
                    "the agent, or use a SOAR run_cmd action for one-shot "
                    "commands.")
        return "no interactive console available on this host."
    return "no interactive console available on this host."


class PtySession:
    """A shell attached to a pseudo-terminal.

    Reading and writing are separate: the caller pumps output on its own
    thread or loop and calls `write` from wherever input arrives, which is how
    a websocket relay wants to use it.
    """

    def __init__(self, argv: list[str] | None = None, cwd: str | None = None):
        if IS_WINDOWS:
            raise ConsoleUnavailable(describe_unavailable())

        import pty

        self.argv = argv or default_shell()
        self.started_at = time.monotonic()
        self.last_input_at = self.started_at
        self._closed = False
        self._lock = threading.Lock()
        self.exit_reason = ""

        master, slave = pty.openpty()
        self.fd = master
        try:
            self.proc = subprocess.Popen(
                self.argv,
                stdin=slave, stdout=slave, stderr=slave,
                cwd=cwd or os.path.expanduser("~"),
                # Its own session, so the pty becomes the controlling terminal
                # and teardown can kill the whole group rather than just the
                # shell - otherwise a backgrounded job outlives the console.
                start_new_session=True,
                env={**os.environ, "TERM": "xterm-256color"},
                close_fds=True,
            )
        except Exception:
            _close_fd(master)
            _close_fd(slave)
            raise
        finally:
            # The child holds its own copy. While the parent keeps one too the
            # pty never reports end-of-file, so a shell that exits leaves the
            # reader blocked on a descriptor nobody will ever write to again.
            _close_fd(slave)

    # -- lifecycle ---------------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed

    def expired(self) -> str | None:
        """The reason this session should end now, if it should."""
        now = time.monotonic()
        if now - self.last_input_at > IDLE_TIMEOUT_S:
            return f"idle for more than {IDLE_TIMEOUT_S}s"
        if now - self.started_at > MAX_SESSION_S:
            return f"open for more than {MAX_SESSION_S}s"
        return None

    def close(self, why: str = "") -> None:
        """Kill the shell and everything it started."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        # Whoever closed this knows more than the reader will: setting
        # `_closed` makes the read loop end without a reason of its own, so a
        # session torn down by a failed write would report the generic "the
        # shell exited". Same trap as the Windows path, same fix.
        if why and not self.exit_reason:
            self.exit_reason = why

        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception as e:
            # Already gone is the common case and means the job is done. A
            # group we genuinely cannot kill is worth a line: it is a root
            # shell still running with nobody attached to it.
            if self.proc.poll() is None:
                print(f"[console] could not kill session group: {e}", flush=True)
        _close_fd(self.fd)

    # -- io ----------------------------------------------------------------

    def read(self, timeout: float = 0.2) -> bytes | None:
        """Whatever the shell has produced, or None when it has ended."""
        import select

        if self._closed:
            return None
        try:
            ready, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            return None
        if not ready:
            return b""
        try:
            data = os.read(self.fd, READ_CHUNK)
        except OSError:
            # The slave side closed: the shell exited.
            return None
        return data or None

    def write(self, data: str | bytes) -> None:
        if self._closed:
            return
        self.last_input_at = time.monotonic()
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        try:
            os.write(self.fd, data)
        except OSError as e:
            print(f"[console] write failed: {e}", flush=True)
            self.close(f"the shell was already gone when input arrived ({e})")

    def resize(self, cols: int, rows: int) -> None:
        """Tell the pty its size, so full-screen programs render correctly."""
        if self._closed:
            return
        cols = max(2, min(int(cols), 500))
        rows = max(1, min(int(rows), 300))
        try:
            import fcntl
            import termios
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except Exception as e:
            # Cosmetic only - the shell still works at its default size, and
            # failing the session over a window size would be worse.
            print(f"[console] resize ignored: {e}", flush=True)


class WinPtySession:
    """A shell attached to a Windows pseudo-console.

    ConPTY, reached through `pywinpty`. Not a pipe-backed `cmd.exe`: a shell
    behind pipes has no terminal, so there is no echo, no line editing, no
    job control and no full-screen program - it looks like a terminal in the
    browser and behaves like a broken one, which is worse than saying it is
    not available.

    `pywinpty`'s read blocks until there is output, so a background thread
    drains it into a queue. That keeps `read(timeout)` meaning the same thing
    on both platforms, and it is what lets the idle timeout fire on a session
    whose shell is sitting there printing nothing - which is exactly the
    abandoned-root-shell case the timeout exists for.
    """

    def __init__(self, argv: list[str] | None = None, cwd: str | None = None):
        if not winpty_available():
            raise ConsoleUnavailable(describe_unavailable())

        import queue as _queue
        from winpty import PtyProcess

        self.argv = argv or default_shell()
        self.started_at = time.monotonic()
        self.last_input_at = self.started_at
        self._closed = False
        self._lock = threading.Lock()
        self._queue: "_queue.Queue[bytes | None]" = _queue.Queue()
        self.exit_reason = ""

        # Not the home directory.
        #
        # The agent runs as SYSTEM, whose profile is under
        # `C:\Windows\system32\config\systemprofile` - a directory that exists
        # but that a shell has no business starting in, and which some
        # policies deny. A working directory that cannot be entered makes the
        # shell exit before it prints anything, which is indistinguishable
        # from "the console is broken".
        start_dir = cwd or os.environ.get("SystemDrive", "C:") + os.sep
        try:
            self._pty = PtyProcess.spawn(
                self.argv, dimensions=(24, 80), cwd=start_dir)
        except Exception as e:
            raise ConsoleUnavailable(
                f"could not start {' '.join(self.argv)} in {start_dir}: {e}")

        # Whether it is still there a moment after spawn.
        #
        # `spawn` succeeding only means ConPTY built the pseudoconsole; the
        # process inside it can die immediately, and that arrived as "the
        # shell exited" with nothing behind it. Checking here puts the fact in
        # the log at the moment it is true, rather than leaving it to be
        # inferred from a failed write twenty milliseconds later.
        time.sleep(0.15)
        alive = False
        try:
            alive = bool(self._pty.isalive())
        except Exception as e:
            print(f"[console] could not check the console: {e}", flush=True)
        if not alive:
            status = getattr(self._pty, "exitstatus", None)
            explanation = ""
            if status == STATUS_CONTROL_C_EXIT:
                # Naming it, because the number is unreadable and the cause is
                # not "the shell crashed": the console it was attached to was
                # destroyed under it.
                explanation = (
                    " - the console was destroyed under it (STATUS_CONTROL_C_EXIT),"
                    " which is what happens when a service with no console of"
                    " its own hosts a pseudoconsole")
            raise ConsoleUnavailable(
                f"{' '.join(self.argv)} exited immediately"
                + (f" with status {status}" if status is not None else "")
                + f" (started in {start_dir}){explanation}")
        print(f"[console] shell alive: {' '.join(self.argv)} in {start_dir}",
              flush=True)

        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    # -- lifecycle ---------------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def proc(self):
        """Enough of `Popen` for the caller's exit reporting."""
        return self

    def poll(self):
        try:
            return None if self._pty.isalive() else self._pty.exitstatus
        except Exception:
            return None

    def expired(self) -> str | None:
        now = time.monotonic()
        if now - self.last_input_at > IDLE_TIMEOUT_S:
            return f"idle for more than {IDLE_TIMEOUT_S}s"
        if now - self.started_at > MAX_SESSION_S:
            return f"open for more than {MAX_SESSION_S}s"
        return None

    def _drain(self) -> None:
        """Move ConPTY output into the queue, and say why it stopped.

        The reason was swallowed here in the first version - both `break`s
        were bare - so a shell that died on startup reached the browser as
        "the shell exited" with nothing behind it. That is the failure this
        whole module keeps being about, and it is no better for being mine.
        """
        idle_reads = 0
        while not self._closed:
            try:
                chunk = self._pty.read(READ_CHUNK)
            except EOFError:
                status = getattr(self._pty, "exitstatus", None)
                self.exit_reason = (
                    "the console closed its output"
                    + (f" (exit status {status})" if status is not None else "")
                    + f" - argv was {' '.join(self.argv)}")
                print(f"[console] {self.exit_reason}", flush=True)
                break
            except Exception as e:
                self.exit_reason = f"reading from the console failed: {e}"
                print(f"[console] {self.exit_reason}", flush=True)
                break

            if not chunk:
                # ConPTY reports nothing for a moment while the shell starts,
                # and `isalive()` can be false in that window. Treating the
                # first empty read as an exit ended every session instantly.
                if not self._pty.isalive():
                    idle_reads += 1
                    if idle_reads > 10:
                        status = getattr(self._pty, "exitstatus", None)
                        self.exit_reason = (
                            f"the shell exited immediately"
                            + (f" (status {status})" if status is not None else "")
                            + f" - argv was {' '.join(self.argv)}")
                        print(f"[console] {self.exit_reason}", flush=True)
                        break
                    time.sleep(0.1)
                    continue
                idle_reads = 0
                # Nothing to read and the shell is alive: do not spin.
                time.sleep(0.02)
                continue

            idle_reads = 0
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "replace")
            self._queue.put(chunk)
        self._queue.put(None)

    def close(self, why: str = "") -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        # Whoever closed this knows more than the drain loop will, and setting
        # `_closed` makes that loop exit without a reason of its own. Without
        # this a session torn down by a failed write reported the generic
        # "the shell exited", which is how the actual cause stayed hidden.
        if why and not self.exit_reason:
            self.exit_reason = why
        try:
            self._pty.terminate(force=True)
        except Exception as e:
            print(f"[console] could not terminate console: {e}", flush=True)
        self._queue.put(None)

    # -- io ----------------------------------------------------------------

    def read(self, timeout: float = 0.2) -> bytes | None:
        import queue as _queue

        if self._closed:
            return None
        try:
            chunk = self._queue.get(timeout=timeout)
        except _queue.Empty:
            return b""
        return chunk           # None means the shell ended

    def write(self, data: str | bytes) -> None:
        if self._closed:
            return
        self.last_input_at = time.monotonic()
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        try:
            self._pty.write(data)
        except Exception as e:
            print(f"[console] write failed: {e}", flush=True)
            self.close(f"the console was already closed when input arrived ({e})")

    def resize(self, cols: int, rows: int) -> None:
        if self._closed:
            return
        cols = max(2, min(int(cols), 500))
        rows = max(1, min(int(rows), 300))
        try:
            self._pty.setwinsize(rows, cols)
        except Exception as e:
            print(f"[console] resize ignored: {e}", flush=True)


def pipe_shell() -> list[str]:
    r"""A shell that reads commands and echoes nothing.

    Not the interactive form. `powershell.exe` with a redirected stdin still
    behaves as an interactive host: it draws a prompt and writes back every
    line it reads. With the browser echoing too, one keystroke appeared twice
    - `dir` arrived as `ddiirr` - and there was no way to tell which copy was
    real.

    `-Command -` makes it a command processor: read a line, run it, print the
    output. Nothing else. The browser then owns the prompt and the echo, which
    it has to anyway, because a pipe has no line discipline and backspace
    would otherwise travel to the shell as a character in the command.
    """
    if IS_WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        powershell = os.path.join(root, "System32", "WindowsPowerShell",
                                  "v1.0", "powershell.exe")
        if os.path.exists(powershell):
            return [powershell, "-NoLogo", "-NoProfile", "-Command", "-"]
        cmd = os.path.join(root, "System32", "cmd.exe")
        if os.path.exists(cmd):
            return [cmd, "/Q"]          # /Q: echo off
        return ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", "-"]

    shell = os.environ.get("SHELL", "")
    if shell and os.path.exists(shell):
        return [shell, "-s"]            # read from stdin, no -i: no prompt
    for candidate in ("/bin/bash", "/bin/sh"):
        if os.path.exists(candidate):
            return [candidate, "-s"]
    raise ConsoleUnavailable("no shell found on this host (/bin/bash, /bin/sh)")


class PipeSession:
    r"""A shell behind pipes, when no pseudoconsole can be had.

    ConPTY does not work in this deployment: both PowerShell and `cmd.exe` are
    killed at once with `STATUS_CONTROL_C_EXIT`, in session 0 and in the
    logged-in user's session, with a console allocated and without one.

    This is the thing I did not want to build, and the argument against it was
    right: a shell behind pipes has no terminal, so there is no echo, no line
    editing, no job control, and `vim` or `top` will hang rather than draw.
    Presented as a terminal it looks broken.

    It is here because "run a command, read the output" is most of what an
    operator opens a console for, and a limited console that works beats an
    elegant one that does not exist. What makes it defensible is that the
    limits are *stated*: the session announces `mode: pipe`, the browser
    echoes locally so typing is visible, and the banner says what is missing.
    A degraded tool that says it is degraded is a different thing from a
    broken one.
    """

    mode = "pipe"

    def __init__(self, argv: list[str] | None = None, cwd: str | None = None):
        import queue as _queue

        self.argv = argv or pipe_shell()
        self.started_at = time.monotonic()
        self.last_input_at = self.started_at
        self._closed = False
        self._lock = threading.Lock()
        self._queue: "_queue.Queue[bytes | None]" = _queue.Queue()
        self.exit_reason = ""
        self._warned_resize = False

        start_dir = cwd or (os.environ.get("SystemDrive", "C:") + os.sep
                            if IS_WINDOWS else os.path.expanduser("~"))
        try:
            self.proc = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=start_dir, bufsize=0,
                creationflags=(subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0),
            )
        except Exception as e:
            raise ConsoleUnavailable(
                f"could not start {' '.join(self.argv)} in {start_dir}: {e}")

        threading.Thread(target=self._drain, daemon=True).start()

    @property
    def closed(self) -> bool:
        return self._closed

    def expired(self) -> str | None:
        now = time.monotonic()
        if now - self.last_input_at > IDLE_TIMEOUT_S:
            return f"idle for more than {IDLE_TIMEOUT_S}s"
        if now - self.started_at > MAX_SESSION_S:
            return f"open for more than {MAX_SESSION_S}s"
        return None

    def _drain(self) -> None:
        try:
            while not self._closed:
                chunk = self.proc.stdout.read(1)
                if not chunk:
                    break
                # Take whatever else is already buffered, so output arrives in
                # lines rather than one character per frame.
                extra = self.proc.stdout.read1(READ_CHUNK) if hasattr(
                    self.proc.stdout, "read1") else b""
                self._queue.put(chunk + (extra or b""))
        except Exception as e:
            self.exit_reason = f"reading from the shell failed: {e}"
        if not self.exit_reason:
            self.exit_reason = f"the shell exited (status {self.proc.poll()})"
        self._queue.put(None)

    def close(self, why: str = "") -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if why and not self.exit_reason:
            self.exit_reason = why
        try:
            self.proc.kill()
        except Exception as e:
            print(f"[console] could not stop the shell: {e}", flush=True)
        self._queue.put(None)

    def read(self, timeout: float = 0.2) -> bytes | None:
        import queue as _queue

        if self._closed:
            return None
        try:
            return self._queue.get(timeout=timeout)
        except _queue.Empty:
            return b""

    def write(self, data: str | bytes) -> None:
        if self._closed:
            return
        self.last_input_at = time.monotonic()
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        # xterm sends \r for Enter; a pipe-fed shell wants \n.
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except Exception as e:
            print(f"[console] write failed: {e}", flush=True)
            self.close(f"the shell was already gone when input arrived ({e})")

    def resize(self, cols: int, rows: int) -> None:
        """Nothing to resize. Said once, not on every keystroke."""
        if not self._warned_resize:
            self._warned_resize = True
            print("[console] resize ignored: this session has no terminal",
                  flush=True)


def _helper_command() -> list[str]:
    """Argv that re-enters this file as the console helper."""
    args = ["--console-helper"]
    if getattr(sys, "frozen", False):
        return [sys.executable] + args
    return [sys.executable, os.path.abspath(sys.argv[0])] + args


def _spawn_user_session_helper():
    r"""Start the console helper in the active console session.

    Deliberately not shared with `screen_capture.spawn_helper`, which needs
    one pipe and this needs two - the console has to be typed into. Merging
    them would mean a launcher with a mode flag threaded through the Win32
    calls, for two callers with different lifetimes. The Win32 sequence is the
    same either way and is documented there.

    Returns `(process, stdin_writer, stdout_reader)`.
    """
    if not IS_WINDOWS:
        raise ConsoleUnavailable("the console helper is a Windows path")

    try:
        from modules import screen_capture
    except Exception as e:
        raise ConsoleUnavailable(f"cannot locate the session launcher: {e}")

    session = screen_capture.active_console_session()
    if session is None:
        raise ConsoleUnavailable(
            "nobody is logged in at the console, so there is no session to "
            "open a shell in. The agent runs as a service and cannot host one "
            "itself - see the note in modules/console.")

    try:
        import msvcrt
        import win32api
        import win32con
        import win32pipe
        import win32process
        import win32profile
        import win32security
        import win32ts
    except ImportError as e:
        raise ConsoleUnavailable(f"pywin32 is not available in this build ({e})")

    sa = win32security.SECURITY_ATTRIBUTES()
    sa.bInheritHandle = True
    # child stdout -> us, and us -> child stdin.
    out_read, out_write = win32pipe.CreatePipe(sa, 0)
    in_read, in_write = win32pipe.CreatePipe(sa, 0)
    # Our own ends must not be inheritable, or the pipe never reports EOF when
    # the helper exits and the reader blocks forever.
    win32api.SetHandleInformation(out_read, win32con.HANDLE_FLAG_INHERIT, 0)
    win32api.SetHandleInformation(in_write, win32con.HANDLE_FLAG_INHERIT, 0)

    user_token = primary = env = None
    try:
        user_token = win32ts.WTSQueryUserToken(session)
        primary = win32security.DuplicateTokenEx(
            user_token, win32security.SecurityImpersonation,
            win32con.MAXIMUM_ALLOWED, win32security.TokenPrimary, None)
        env = win32profile.CreateEnvironmentBlock(primary, False)

        startup = win32process.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESTDHANDLES
        startup.hStdInput = in_read
        startup.hStdOutput = out_write
        startup.hStdError = None
        startup.lpDesktop = "winsta0\\default"

        argv = _helper_command()
        handle, thread_handle, _pid, _tid = win32process.CreateProcessAsUser(
            primary, argv[0], subprocess.list2cmdline(argv), None, None, True,
            win32con.CREATE_NO_WINDOW | win32con.CREATE_UNICODE_ENVIRONMENT,
            env, None, startup)
        try:
            win32api.CloseHandle(thread_handle)
        except Exception as e:
            print(f"[console] helper thread handle leaked: {e}", flush=True)
    except ConsoleUnavailable:
        raise
    except Exception as e:
        raise ConsoleUnavailable(f"could not start the console helper: {e}")
    finally:
        for token in (primary, user_token):
            if token is not None:
                try:
                    win32api.CloseHandle(token)
                except Exception:
                    print("[console] a token handle would not close", flush=True)
        if env is not None:
            try:
                win32profile.DestroyEnvironmentBlock(env)
            except Exception as e:
                print(f"[console] environment block leaked: {e}", flush=True)

    # Drop our copies of the child's ends, or the pipes never see EOF.
    for handle in (out_write, in_read):
        try:
            win32api.CloseHandle(handle)
        except Exception as e:
            print(f"[console] a pipe handle would not close: {e}", flush=True)

    reader = os.fdopen(msvcrt.open_osfhandle(int(out_read), os.O_RDONLY | os.O_BINARY), "rb", 0)
    out_read.Detach()
    writer = os.fdopen(msvcrt.open_osfhandle(int(in_write), os.O_WRONLY | os.O_BINARY), "wb", 0)
    in_write.Detach()

    class _Handle:
        def __init__(self, h):
            self._h = h

        def terminate(self):
            try:
                win32process.TerminateProcess(self._h, 1)
            except Exception as e:
                print(f"[console] could not terminate the helper: {e}", flush=True)
            finally:
                try:
                    win32api.CloseHandle(self._h)
                except Exception:
                    print("[console] a process handle would not close", flush=True)

    return _Handle(handle), writer, reader


class HelperSession:
    r"""A console hosted by a helper in the logged-in user's session.

    ConPTY cannot be hosted from session 0. Both PowerShell and `cmd.exe` are
    killed at once with `STATUS_CONTROL_C_EXIT` there, with a console
    allocated and without one - the pseudoconsole is created, and the process
    inside it never survives.

    That is the same wall the screen stream hit, and it has the same answer:
    run the part that needs a desktop session inside one. `main.exe
    --console-helper` is launched with `CreateProcessAsUser` into the active
    console session, hosts the PTY there, and relays frames over two
    inherited pipes.

    **The shell runs as the logged-in user, not SYSTEM.** That is a real
    change and worth stating rather than discovering: it is a smaller
    privilege than the rest of the agent has, which for an interactive console
    is the better default, and it is the only way to have one at all on
    Windows. A host with nobody logged in has no console, exactly as it has no
    screen.

    Frames are newline-delimited JSON, the same shapes the websocket uses.
    JSON escapes its own newlines, so a line is always a whole frame.
    """

    def __init__(self, argv: list[str] | None = None):
        import queue as _queue

        self.argv = argv or []
        self.started_at = time.monotonic()
        self.last_input_at = self.started_at
        self._closed = False
        self._lock = threading.Lock()
        self._queue: "_queue.Queue[bytes | None]" = _queue.Queue()
        self.exit_reason = ""

        self.mode = "pty"
        self._ready = threading.Event()
        self._startup_error = ""

        self._proc, self._stdin, self._stdout = _spawn_user_session_helper()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

        # Wait for the helper to say it hosted a console.
        #
        # Starting the process is not the same as having a console, and
        # treating it as such is what made the pipe fallback unreachable: the
        # helper launched, failed to host anything, and reported that in a
        # frame nobody was waiting for - by which time this constructor had
        # already returned a session that would never produce output.
        if not self._ready.wait(HELPER_READY_TIMEOUT_S):
            self.close("the console helper never reported ready")
            raise ConsoleUnavailable(
                f"the console helper did not respond within "
                f"{HELPER_READY_TIMEOUT_S}s")
        if self._startup_error:
            self.close(self._startup_error)
            raise ConsoleUnavailable(self._startup_error)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def proc(self):
        return self

    def poll(self):
        return None

    def expired(self) -> str | None:
        now = time.monotonic()
        if now - self.last_input_at > IDLE_TIMEOUT_S:
            return f"idle for more than {IDLE_TIMEOUT_S}s"
        if now - self.started_at > MAX_SESSION_S:
            return f"open for more than {MAX_SESSION_S}s"
        return None

    def _drain(self) -> None:
        try:
            for line in self._stdout:
                if self._closed:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line.decode("utf-8", "replace"))
                except Exception:
                    continue
                kind = msg.get("t")
                if kind == "m":
                    # The helper hosted a console. Not forwarded: the agent
                    # sends its own mode frame to the browser.
                    self.mode = msg.get("mode") or "pty"
                    self._ready.set()
                elif kind == "o":
                    self._ready.set()
                    self._queue.put(str(msg.get("d", "")).encode("utf-8", "replace"))
                elif kind in ("x", "e"):
                    self.exit_reason = str(msg.get("why") or msg.get("d") or "")
                    if not self._ready.is_set():
                        # It never got a console. Say so through the
                        # constructor, so the caller can try something else.
                        self._startup_error = self.exit_reason
                        self._ready.set()
                    print(f"[console] helper ended: {self.exit_reason}", flush=True)
                    break
        except Exception as e:
            self.exit_reason = f"the console helper stopped: {e}"
            print(f"[console] {self.exit_reason}", flush=True)
        if not self._ready.is_set():
            # The pipe closed before the helper said anything - it died on
            # startup. Unblock the constructor rather than let it wait out the
            # full timeout for an answer that is never coming.
            self._startup_error = self.exit_reason or "the console helper exited at once"
            self._ready.set()
        self._queue.put(None)

    def close(self, why: str = "") -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if why and not self.exit_reason:
            self.exit_reason = why
        for name, stream in (("stdin", self._stdin), ("stdout", self._stdout)):
            try:
                stream.close()
            except Exception as e:
                print(f"[console] helper {name} pipe would not close: {e}",
                      flush=True)
        try:
            self._proc.terminate()
        except Exception as e:
            print(f"[console] could not stop the console helper: {e}", flush=True)
        self._queue.put(None)

    def read(self, timeout: float = 0.2) -> bytes | None:
        import queue as _queue

        if self._closed:
            return None
        try:
            return self._queue.get(timeout=timeout)
        except _queue.Empty:
            return b""

    def _send(self, payload: dict) -> None:
        if self._closed:
            return
        try:
            self._stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
            self._stdin.flush()
        except Exception as e:
            print(f"[console] could not reach the console helper: {e}", flush=True)
            self.close(f"the console helper went away ({e})")

    def write(self, data: str | bytes) -> None:
        self.last_input_at = time.monotonic()
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        self._send({"t": "i", "d": data})

    def resize(self, cols: int, rows: int) -> None:
        self._send({"t": "r", "cols": int(cols), "rows": int(rows)})


def helper_log_path() -> str:
    r"""Where the helper writes. Somewhere it is actually allowed to.

    Not beside the executable. The helper runs as the logged-in user - that is
    the whole point of launching it into their session - and
    `C:\Program Files\Sentora-Agent` is not writable by them. The first
    version wrote there, the write failed, the last-resort logger swallowed
    it, and the one process that knew why the console failed produced no file
    at all. Twice hidden.
    """
    for base in (os.environ.get("TEMP"), os.environ.get("TMP"),
                 os.environ.get("ProgramData"), os.path.expanduser("~")):
        if base and os.path.isdir(base):
            return os.path.join(base, "sentora-console-helper.log")
    return os.path.join(os.path.abspath(os.sep), "sentora-console-helper.log")


def _helper_log(message: str) -> None:
    """Say something from inside the helper.

    The helper is started with `hStdError = None` and moves its own stdout off
    the frame pipe, so every print it makes goes nowhere - which meant the one
    process that knows why the console failed was the one process that could
    not say. A file beside the executable is the only channel it has.
    """
    line = f"{datetime.now().isoformat(timespec='seconds')} {message}\n"
    try:
        with open(helper_log_path(), "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        # Nowhere left to report to; the frame stream is the only other
        # channel and it is reserved for the session itself.
        pass


def describe_host() -> str:
    """What this process is, for the helper log. Cheap and always safe."""
    bits = [f"pid={os.getpid()}"]
    if IS_WINDOWS:
        try:
            import win32api
            import win32ts
            bits.append(f"session={win32ts.ProcessIdToSessionId(win32api.GetCurrentProcessId())}")
        except Exception as e:
            bits.append(f"session=? ({e})")
        try:
            import ctypes
            bits.append(f"console_window={bool(ctypes.windll.kernel32.GetConsoleWindow())}")
        except Exception as e:
            bits.append(f"console_window=? ({e})")
    bits.append(f"user={os.environ.get('USERNAME') or os.environ.get('USER')}")
    return " ".join(bits)


def console_helper_main() -> int:
    """The child side: host a PTY here, relay frames over stdin/stdout.

    Runs in the user's session, where ConPTY works. Speaks the same frame
    shapes as the websocket so nothing has to translate in the middle.
    """
    out = sys.stdout.buffer
    stdin = sys.stdin.buffer
    sys.stdout = sys.stderr          # keep stray prints off the frame stream

    if IS_WINDOWS:
        try:
            import msvcrt
            msvcrt.setmode(out.fileno(), os.O_BINARY)
            msvcrt.setmode(stdin.fileno(), os.O_BINARY)
        except Exception as e:
            print(f"[console-helper] binary mode failed: {e}", file=sys.stderr, flush=True)
            return 6

    def emit(payload: dict) -> bool:
        """Send one frame. False once the parent has gone.

        Returning rather than swallowing: the pump loop below has something to
        do with the answer - stop - and a helper that keeps capturing for a
        parent that has exited is a shell running with nobody attached.
        """
        try:
            out.write((json.dumps(payload) + "\n").encode("utf-8"))
            out.flush()
            return True
        except Exception:
            return False

    _helper_log(f"helper started: {describe_host()}")

    try:
        session = new_direct_session()
    except ConsoleUnavailable as e:
        _helper_log(f"no console here either: {e}")
        emit({"t": "e", "d": f"the helper could not host a console either: {e}"})
        return 3

    _helper_log(f"console hosted: {' '.join(getattr(session, 'argv', []))}")
    # Tell the parent it worked, before any output.
    #
    # Without this the parent treated "the process started" as "the console
    # works", so a helper that launched and then could not host anything was
    # reported as a live session - and the pipe fallback behind it was
    # unreachable, because nothing ever raised.
    emit({"t": "m", "mode": getattr(session, "mode", "pty")})

    def pump_out():
        while True:
            chunk = session.read(0.2)
            if chunk is None:
                emit({"t": "x", "why": getattr(session, "exit_reason", "")
                      or "the shell exited"})
                return
            if chunk and not emit({"t": "o", "d": chunk.decode("utf-8", "replace")}):
                # The agent has gone. Take the shell with us rather than leave
                # it running in the user's session with nothing attached.
                session.close("the agent went away")
                return

    threading.Thread(target=pump_out, daemon=True).start()

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        kind, payload = decode_input(line.decode("utf-8", "replace"))
        if kind == "input":
            session.write(payload["data"])
        elif kind == "resize":
            session.resize(payload["cols"], payload["rows"])
    session.close("the agent closed the console")
    return 0


def new_direct_session(argv: list[str] | None = None):
    """A PTY hosted by this process. Works wherever a desktop session does."""
    if not IS_WINDOWS:
        return PtySession(argv)
    if argv:
        return WinPtySession(argv)
    ensure_console()
    failures: list[str] = []
    for candidate in windows_shell_candidates():
        try:
            return WinPtySession(candidate)
        except ConsoleUnavailable as e:
            failures.append(str(e))
    raise ConsoleUnavailable(" | ".join(failures) or describe_unavailable())


def new_session(argv: list[str] | None = None) -> "PtySession | WinPtySession":
    """The right session for this host, or a reason there is none.

    On Windows the shell is tried more than once. The failure being worked
    around - `STATUS_CONTROL_C_EXIT` from a service with no console - is a
    property of the console rather than of the shell, so a console is
    allocated first and `cmd.exe` is tried when PowerShell will not start.
    Every attempt and its status is logged, because "no console available" on
    its own sent an operator looking in the wrong place for two days.
    """
    if not IS_WINDOWS:
        return PtySession(argv)
    if argv:
        return WinPtySession(argv)

    # Try here first. It costs a few hundred milliseconds and it is the only
    # path that works when the agent is not a service - a developer running
    # it from a terminal, for instance.
    # Kept in a name of our own: `except ... as e` unbinds `e` at the end of
    # the block, so referring to it in the handler below raised
    # UnboundLocalError - and did so only on the path where both attempts
    # fail, which is the path whose whole purpose is to explain itself.
    direct_error = ""
    try:
        return new_direct_session()
    except ConsoleUnavailable as e:
        direct_error = str(e)
        print(f"[console] no console in this process ({direct_error}); "
              f"trying the user's session", flush=True)

    # Session 0 cannot host a pseudoconsole: both shells are killed at once
    # with STATUS_CONTROL_C_EXIT, with a console allocated and without one.
    # The screen stream hit the same wall and this is the same answer.
    try:
        return HelperSession()
    except ConsoleUnavailable as e:
        helper_error = str(e)
        print(f"[console] no console in the user's session either "
              f"({helper_error}); falling back to a shell behind pipes",
              flush=True)

    # Last resort, and honest about it. See PipeSession: no terminal, so no
    # echo, no line editing, and full-screen programs will hang. The session
    # announces `mode: pipe` so the browser can say so rather than present it
    # as a terminal that is behaving strangely.
    try:
        return PipeSession()
    except ConsoleUnavailable as pipe_error:
        raise ConsoleUnavailable(
            f"no console of any kind could be started. "
            f"Pseudoconsole here: {direct_error}. "
            f"In the user's session: {helper_error}. "
            f"Behind pipes: {pipe_error}")


# ---------------------------------------------------------------------------
# One session at a time
# ---------------------------------------------------------------------------

_active: PtySession | None = None
_active_lock = threading.Lock()


def open_session(argv: list[str] | None = None) -> PtySession:
    """Start the console, refusing if one is already open.

    A shell is not a resource to pool: two concurrent roots on one host is an
    accident that gets blamed on the wrong person, because the audit trail
    cannot tell them apart.
    """
    global _active
    with _active_lock:
        if _active is not None and not _active.closed:
            expired = _active.expired()
            if expired is None:
                raise ConsoleUnavailable(
                    "a console session is already open on this host. Close it, "
                    "or wait for it to time out.")
            _active.close(expired)
        _active = new_session(argv)
        return _active


def close_active(why: str = "") -> None:
    global _active
    with _active_lock:
        if _active is not None:
            _active.close(why)
            _active = None


def active_session() -> PtySession | None:
    return _active


# ---------------------------------------------------------------------------
# Wire framing
# ---------------------------------------------------------------------------

def encode_mode(session) -> str:
    """Tell the browser what kind of session this is.

    A pipe-backed shell renders nothing as you type and hangs on `vim`. Shown
    without saying so it reads as a broken terminal, which is the failure this
    whole module keeps circling. The browser echoes locally and says what is
    missing when it sees `pipe`.
    """
    mode = getattr(session, "mode", "pty")
    note = ("No terminal on this host, so this is a shell behind pipes: what "
            "you type is echoed locally, there is no line editing, and "
            "full-screen programs (vim, top) will not draw."
            if mode == "pipe" else "")
    return json.dumps({"t": "m", "mode": mode, "note": note})


def encode_output(data: bytes) -> str:
    return json.dumps({"t": "o", "d": data.decode("utf-8", "replace")})


def encode_exit(code: int | None, why: str = "") -> str:
    return json.dumps({"t": "x", "code": code, "why": why})


def encode_error(message: str) -> str:
    return json.dumps({"t": "e", "d": message})


def decode_input(raw: str) -> tuple[str, dict]:
    """Parse one client frame into `(kind, payload)`.

    Unknown or malformed frames become `("ignore", ...)` rather than raising:
    the peer is a browser, and a stray frame must not take down a session
    somebody is working in.
    """
    try:
        msg = json.loads(raw)
    except Exception:
        return "ignore", {"reason": "not JSON"}
    if not isinstance(msg, dict):
        return "ignore", {"reason": "not an object"}

    kind = msg.get("t")
    if kind == "i":
        data = msg.get("d")
        if not isinstance(data, str):
            return "ignore", {"reason": "input is not a string"}
        return "input", {"data": data}
    if kind == "r":
        try:
            return "resize", {"cols": int(msg.get("cols", 80)),
                              "rows": int(msg.get("rows", 24))}
        except (TypeError, ValueError):
            return "ignore", {"reason": "bad size"}
    return "ignore", {"reason": f"unknown frame {kind!r}"}
