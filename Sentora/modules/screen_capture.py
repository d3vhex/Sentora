r"""Screen capture from a service that cannot see the screen.

The problem
-----------
The Windows agent is registered with

    New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

which puts it in **session 0**. Since Vista, session 0 is isolated from the
interactive desktop: the logged-in user is in session 1 and session 0 has no
visible desktop at all. `mss` captures the desktop of the session it is in, so
the agent was grabbing nothing and the console showed a connected stream with
no frames - indistinguishable, from the operator's chair, from a broken
feature.

Running the agent as the logged-in user would fix the capture and break
everything else: FIM, registry monitoring, process termination and host
isolation all need SYSTEM. That is a bad trade for an EDR.

The shape of the fix
--------------------
The agent stays in session 0 and launches a short-lived **helper** inside the
active user's session, which can see the desktop. The helper captures and
hands frames back.

Three decisions worth stating, because each rules out an easier design:

**The helper is this same binary.** The agent ships as one PyInstaller file;
a second executable would be a second thing to sign, ship, upgrade and get out
of step. `main.exe --screen-helper` re-enters here instead.

**Frames come back over an inherited pipe, not a socket.** A loopback
listener would be reachable by every process on the machine, so it would need
a token, and a token passed on a command line is readable from any process
listing. An anonymous pipe handed to a child at creation is reachable by the
parent and the child and nothing else - there is no authentication step
because there is nobody else to authenticate.

**Frames are framed, and the helper's `sys.stdout` is moved off the pipe.**
The pipe *is* the child's stdout, so one stray `print` from any library in the
process would land in the middle of a JPEG. The helper redirects `sys.stdout`
to stderr immediately and writes frames only to the raw handle it saved, and
every frame carries a magic prefix so a reader can resynchronise instead of
returning a corrupt image.

What this does not do
---------------------
It cannot capture a machine with nobody logged in - there is no desktop to
capture, and saying so is the honest answer. It also cannot capture the
Windows lock screen or a UAC prompt: those live on the Winlogon and secure
desktops, and a process in the user's session is not permitted to read them.
"""

from __future__ import annotations

import os
import platform
import struct
import subprocess
import sys
import threading

IS_WINDOWS = platform.system() == "Windows"

# A stray write to the pipe must not be readable as a frame. Four bytes is
# enough to resynchronise on and cheap to scan for.
FRAME_MAGIC = b"SNTF"
_HEADER = struct.Struct("!I")

# A frame larger than this is a desynchronised reader, not a screenshot: a
# 4K JPEG at quality 95 is a few megabytes. Believing a bogus length would
# make us allocate whatever the corrupt bytes happened to say.
MAX_FRAME_BYTES = 32 * 1024 * 1024


class CaptureUnavailable(Exception):
    """No capture is possible, with a reason fit to show an operator."""


# ---------------------------------------------------------------------------
# Session detection
# ---------------------------------------------------------------------------

def current_session_id() -> int | None:
    """The Windows session this process is in. None off Windows or on error."""
    if not IS_WINDOWS:
        return None
    try:
        import win32api
        import win32ts
        return win32ts.ProcessIdToSessionId(win32api.GetCurrentProcessId())
    except Exception:
        return None


def in_session_zero() -> bool:
    """True when this process cannot see the interactive desktop.

    Session 0 is the service session. Anything else - including a normal
    interactive login - can capture directly and does not need a helper.
    """
    return IS_WINDOWS and current_session_id() == 0


def active_console_session() -> int | None:
    """The session at the physical console, or None if nobody is logged in.

    `WTSGetActiveConsoleSessionId` returns 0xFFFFFFFF when there is no active
    console session (no user logged in, or the session is in transition).
    """
    if not IS_WINDOWS:
        return None
    try:
        import win32ts
        session = win32ts.WTSGetActiveConsoleSessionId()
    except Exception:
        return None
    if session in (0xFFFFFFFF, None):
        return None
    # Session 0 as the *console* session means no interactive user - on a
    # modern Windows that value is the service session, never a desktop.
    if session == 0:
        return None
    return int(session)


def describe_unavailable() -> str:
    """Why capture is not possible here, in words an operator can act on."""
    if not IS_WINDOWS:
        if not os.environ.get("DISPLAY"):
            return ("no display on this host (DISPLAY is unset). A headless "
                    "server has no screen to stream.")
        return "no capture available on this host."
    if active_console_session() is None:
        return ("nobody is logged in at the console, so there is no desktop "
                "to capture. The agent runs as a service and can only stream "
                "a session that exists.")
    return ("the agent runs as a service in session 0 and cannot reach the "
            "interactive desktop directly.")


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def encode_frame(jpeg: bytes) -> bytes:
    """One frame, as it travels down the pipe."""
    return FRAME_MAGIC + _HEADER.pack(len(jpeg)) + jpeg


def read_frame(stream) -> bytes | None:
    """Read one frame, resynchronising past anything that is not a frame.

    Returns None at end of stream. Junk before a magic marker is skipped
    rather than treated as fatal: the child's own stdout is redirected away
    from this pipe, but a native library writing to fd 1 directly would not go
    through `sys.stdout`, and losing the stream to that would be a worse
    failure than dropping the bytes.
    """
    window = b""
    while True:
        byte = stream.read(1)
        if not byte:
            return None
        window += byte
        if len(window) > len(FRAME_MAGIC):
            window = window[-len(FRAME_MAGIC):]
        if window != FRAME_MAGIC:
            continue

        header = _read_exactly(stream, _HEADER.size)
        if header is None:
            return None
        (length,) = _HEADER.unpack(header)
        if length <= 0 or length > MAX_FRAME_BYTES:
            # Not a real header. Keep scanning rather than trusting it.
            window = b""
            continue
        payload = _read_exactly(stream, length)
        if payload is None:
            return None
        return payload


def _read_exactly(stream, count: int) -> bytes | None:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# The helper (child side)
# ---------------------------------------------------------------------------

def run_helper(fps: int = 10, quality: int = 60, width: int = 1280) -> int:
    """Capture the desktop and write frames to stdout until the pipe closes.

    Runs in the user's session, launched by `spawn_helper` below. Exits when
    the parent goes away, which shows up as a write failure on the pipe.
    """
    # Take the raw pipe before anything else can write to it, then move
    # `sys.stdout` off it. Any print from here on - ours, a library's, a
    # warning - goes to stderr and cannot corrupt a frame.
    out = sys.stdout.buffer
    sys.stdout = sys.stderr

    if IS_WINDOWS:
        # Without this the pipe is in text mode and every 0x0A inside a JPEG
        # is written as 0x0D 0x0A. Practically every frame contains one, so
        # the stream would not be slightly degraded - it would be uniformly
        # corrupt, while still looking like a working stream from both ends.
        #
        # Refusing to start is the right answer to that. A capture that sends
        # broken images is worse than one that says it cannot run: the first
        # costs an operator an afternoon, the second costs a line in a log.
        try:
            import msvcrt
            msvcrt.setmode(out.fileno(), os.O_BINARY)
        except Exception as e:
            print(f"[screen-helper] cannot put the frame pipe in binary mode "
                  f"({e}); refusing to stream rather than send corrupt frames.",
                  file=sys.stderr, flush=True)
            return 6

    try:
        import mss as _mss
        from PIL import Image
    except ImportError as e:
        print(f"[screen-helper] missing dependency: {e}", file=sys.stderr, flush=True)
        return 2

    import io as _io
    import time as _time

    fps = max(1, min(int(fps), 30))
    quality = max(20, min(int(quality), 95))
    width = max(320, min(int(width), 2560))
    interval = 1.0 / fps

    try:
        capture = _mss.mss()
    except Exception as e:
        print(f"[screen-helper] cannot open a capture: {e}", file=sys.stderr, flush=True)
        return 3

    try:
        with capture as sct:
            if not sct.monitors:
                print("[screen-helper] no monitors detected", file=sys.stderr, flush=True)
                return 4
            monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
            while True:
                started = _time.monotonic()
                shot = sct.grab(monitor)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                if img.width > width:
                    ratio = width / img.width
                    img = img.resize((width, int(img.height * ratio)))
                buf = _io.BytesIO()
                img.save(buf, format="JPEG", quality=quality, optimize=False)
                try:
                    out.write(encode_frame(buf.getvalue()))
                    out.flush()
                except Exception:
                    # The parent closed the pipe: the viewer went away, or the
                    # agent stopped. Either way there is nobody to stream to.
                    return 0
                elapsed = _time.monotonic() - started
                if elapsed < interval:
                    _time.sleep(interval - elapsed)
    except Exception as e:
        print(f"[screen-helper] capture loop ended: {e}", file=sys.stderr, flush=True)
        return 5


# ---------------------------------------------------------------------------
# The launcher (parent side)
# ---------------------------------------------------------------------------

def helper_command(fps: int, quality: int, width: int) -> list[str]:
    """Argv that re-enters this file as the helper.

    Frozen, `sys.executable` is the agent binary itself. Unfrozen it is the
    Python interpreter and the script has to be named explicitly, which is
    what a developer running from source gets.
    """
    args = ["--screen-helper", "--fps", str(fps), "--q", str(quality), "--w", str(width)]
    if getattr(sys, "frozen", False):
        return [sys.executable] + args
    return [sys.executable, os.path.abspath(sys.argv[0])] + args


def _quietly_close(*handles) -> None:
    """Release Windows handles we are done with.

    The single place in this module where a failure is swallowed, and it is
    swallowed because there is nothing a caller could do with it: these are
    handles being discarded on a path that has already succeeded or already
    failed for another reason. A handle that is already closed, or belongs to
    a process that has exited, raises here and means nothing.

    Everything else in this file reports why it failed, because everywhere
    else the reason is the thing an operator needs.
    """
    try:
        import win32api
    except Exception:
        return
    for handle in handles:
        if handle is None:
            continue
        try:
            win32api.CloseHandle(handle)
        except Exception:
            pass


class HelperStream:
    """Frames from a helper process, and the means to stop it."""

    def __init__(self, proc, reader):
        self._proc = proc
        self._reader = reader
        self._closed = False

    def read_frame(self) -> bytes | None:
        if self._closed:
            return None
        return read_frame(self._reader)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for label, action in (("pipe", self._reader.close),
                              ("helper", self._proc.terminate)):
            try:
                action()
            except Exception as e:
                # Both are disposal, but neither is nothing: a pipe that will
                # not close leaks a handle, and a helper that will not stop is
                # a process screenshotting a desktop with nobody watching.
                print(f"[screen-helper] could not release {label}: {e}",
                      file=sys.stderr, flush=True)


def spawn_helper(fps: int = 10, quality: int = 60, width: int = 1280) -> HelperStream:
    """Start the helper in the active user's session and return its frames.

    Raises `CaptureUnavailable` with an operator-readable reason when there is
    no session to launch into.
    """
    if not IS_WINDOWS:
        raise CaptureUnavailable(describe_unavailable())

    session = active_console_session()
    if session is None:
        raise CaptureUnavailable(describe_unavailable())

    try:
        import win32api
        import win32con
        import win32event  # noqa: F401  (imported for its side effect on some builds)
        import win32pipe
        import win32process
        import win32profile
        import win32security
        import win32ts
        import msvcrt
    except ImportError as e:
        raise CaptureUnavailable(
            f"pywin32 is not available in this build, so the agent cannot "
            f"launch a capture helper ({e})."
        )

    # An inheritable pipe. The child gets the write end as its stdout; the
    # read end is explicitly made non-inheritable so it does not leak into
    # this or any other child, which would keep the pipe open after the
    # helper exits and leave a reader blocked forever.
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.bInheritHandle = True
    read_handle, write_handle = win32pipe.CreatePipe(sa, 0)
    win32api.SetHandleInformation(read_handle, win32con.HANDLE_FLAG_INHERIT, 0)

    user_token = None
    primary = None
    env = None
    try:
        try:
            user_token = win32ts.WTSQueryUserToken(session)
        except Exception as e:
            raise CaptureUnavailable(
                f"could not obtain the token for session {session}: {e}. "
                f"This normally means the session ended between the check and "
                f"the launch."
            )

        primary = win32security.DuplicateTokenEx(
            user_token,
            win32security.SecurityImpersonation,
            win32con.MAXIMUM_ALLOWED,
            win32security.TokenPrimary,
            None,
        )
        env = win32profile.CreateEnvironmentBlock(primary, False)

        startup = win32process.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESTDHANDLES
        startup.hStdOutput = write_handle
        startup.hStdError = None
        startup.hStdInput = None
        # The interactive window station and desktop. Without this the process
        # starts attached to the service desktop and captures nothing - the
        # exact failure this module exists to fix.
        startup.lpDesktop = "winsta0\\default"

        argv = helper_command(fps, quality, width)
        cmdline = subprocess.list2cmdline(argv)

        handle, thread_handle, _pid, _tid = win32process.CreateProcessAsUser(
            primary,
            argv[0],
            cmdline,
            None,            # process attributes
            None,            # thread attributes
            True,            # inherit handles - this is how stdout reaches it
            win32con.CREATE_NO_WINDOW | win32con.CREATE_UNICODE_ENVIRONMENT,
            env,
            None,            # current directory
            startup,
        )
        _quietly_close(thread_handle)
    except CaptureUnavailable:
        _quietly_close(read_handle, write_handle)
        raise
    except Exception as e:
        _quietly_close(read_handle, write_handle)
        raise CaptureUnavailable(f"could not start the capture helper: {e}")
    finally:
        _quietly_close(primary, user_token)
        if env is not None:
            try:
                win32profile.DestroyEnvironmentBlock(env)
            except Exception as e:
                # Disposal, like _quietly_close, but a leak here is a copy of
                # a user's environment block held for the life of the agent.
                print(f"[screen-helper] could not release the environment "
                      f"block: {e}", file=sys.stderr, flush=True)

    # The parent must drop its copy of the write end. While it holds one, the
    # pipe never reports end-of-file, so a helper that dies leaves the reader
    # blocked on a pipe nobody will ever write to again.
    _quietly_close(write_handle)

    fd = msvcrt.open_osfhandle(int(read_handle), os.O_RDONLY | os.O_BINARY)
    # `open_osfhandle` transfers ownership of the handle to the fd, so the
    # handle must not be closed separately - closing the file object is what
    # releases it. Detaching keeps that ownership in one place.
    read_handle.Detach()
    reader = os.fdopen(fd, "rb", buffering=0)

    return HelperStream(_ProcessHandle(handle), reader)


class _ProcessHandle:
    """Just enough of `Popen` for `HelperStream.close`."""

    def __init__(self, handle):
        self._handle = handle

    def terminate(self) -> None:
        try:
            import win32process
            win32process.TerminateProcess(self._handle, 1)
        except Exception as e:
            # Almost always "the process already exited", which is the
            # outcome we wanted. Logged rather than hidden because the other
            # possibility - a helper we cannot stop - is a process
            # screenshotting a desktop with nobody watching.
            print(f"[screen-helper] could not terminate helper: {e}",
                  file=sys.stderr, flush=True)
        finally:
            _quietly_close(self._handle)


# ---------------------------------------------------------------------------
# Entry point used by main.py
# ---------------------------------------------------------------------------

def helper_main(argv: list[str]) -> int:
    """Parse `--screen-helper` arguments and run the capture loop."""
    def value_after(flag: str, default: int) -> int:
        try:
            return int(argv[argv.index(flag) + 1])
        except Exception:
            return default

    return run_helper(
        fps=value_after("--fps", 10),
        quality=value_after("--q", 60),
        width=value_after("--w", 1280),
    )
