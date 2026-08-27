"""Screen capture from a session that has no screen.

The Windows agent runs as a service in session 0, which since Vista is
isolated from the interactive desktop. It was capturing nothing and reporting
success, so the console showed a live stream that stayed black.

`modules/screen_capture` launches a helper into the logged-in user's session
and reads frames back over an inherited pipe. The launch itself needs Windows
and a live desktop, so what is tested here is everything around it: the wire
framing, the resynchronisation, the session logic, and the argv the helper is
re-entered with. Those are the parts that can be wrong quietly.
"""

import io
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT_ROOT = ROOT / "Sentora"

sys.path.insert(0, str(AGENT_ROOT))
try:
    from modules import screen_capture
except Exception as exc:  # pragma: no cover
    pytest.skip(f"agent module unavailable: {exc}", allow_module_level=True)
finally:
    if str(AGENT_ROOT) in sys.path:
        sys.path.remove(str(AGENT_ROOT))


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def test_a_frame_survives_the_round_trip():
    payload = b"\xff\xd8\xff\xe0 not really a jpeg \x00\x0a\x0d\xff\xd9"
    stream = io.BytesIO(screen_capture.encode_frame(payload))
    assert screen_capture.read_frame(stream) == payload


def test_frames_carrying_newlines_are_not_mangled():
    """The pipe is the child's stdout, and on Windows that is text mode by
    default - 0x0A becomes 0x0D 0x0A and every JPEG containing one is ruined.
    The helper sets binary mode; this pins the expectation that raw bytes
    come back exactly."""
    payload = bytes(range(256)) * 4
    stream = io.BytesIO(screen_capture.encode_frame(payload))
    assert screen_capture.read_frame(stream) == payload


def test_several_frames_read_in_order():
    frames = [b"one", b"two", b"three"]
    blob = b"".join(screen_capture.encode_frame(f) for f in frames)
    stream = io.BytesIO(blob)
    assert [screen_capture.read_frame(stream) for _ in frames] == frames
    assert screen_capture.read_frame(stream) is None


def test_junk_before_a_frame_is_skipped_not_fatal():
    """A native library writing to fd 1 bypasses `sys.stdout`, so the stream
    can carry bytes that are not ours. Losing the session to that would be a
    worse failure than dropping the bytes."""
    blob = b"WARNING: libjpeg says something\n" + screen_capture.encode_frame(b"pixels")
    assert screen_capture.read_frame(io.BytesIO(blob)) == b"pixels"


def test_a_bogus_length_does_not_get_believed():
    """Four bytes that happen to spell the magic, followed by a huge length.
    Trusting it would allocate whatever the corrupt bytes said."""
    import struct
    blob = (screen_capture.FRAME_MAGIC + struct.pack("!I", 0xFFFFFFFF)
            + screen_capture.encode_frame(b"real frame"))
    assert screen_capture.read_frame(io.BytesIO(blob)) == b"real frame"


def test_zero_length_is_rejected_too():
    import struct
    blob = (screen_capture.FRAME_MAGIC + struct.pack("!I", 0)
            + screen_capture.encode_frame(b"real frame"))
    assert screen_capture.read_frame(io.BytesIO(blob)) == b"real frame"


def test_a_truncated_frame_ends_the_stream():
    """Half a frame means the helper died mid-write. Returning the partial
    bytes as an image would paint garbage; None ends the stream cleanly."""
    whole = screen_capture.encode_frame(b"abcdefghij")
    assert screen_capture.read_frame(io.BytesIO(whole[:-3])) is None


def test_empty_stream_is_end_not_error():
    assert screen_capture.read_frame(io.BytesIO(b"")) is None


def test_magic_appearing_inside_a_payload_does_not_split_it():
    """The magic is four ordinary bytes and a JPEG may contain them. Framing
    is by length, so the reader must not resynchronise mid-payload."""
    payload = b"xx" + screen_capture.FRAME_MAGIC + b"yy"
    stream = io.BytesIO(screen_capture.encode_frame(payload))
    assert screen_capture.read_frame(stream) == payload


# ---------------------------------------------------------------------------
# Session logic
# ---------------------------------------------------------------------------

def test_no_helper_path_off_windows(monkeypatch):
    monkeypatch.setattr(screen_capture, "IS_WINDOWS", False)
    assert screen_capture.in_session_zero() is False
    assert screen_capture.active_console_session() is None


def test_session_zero_is_the_only_case_needing_a_helper(monkeypatch):
    monkeypatch.setattr(screen_capture, "IS_WINDOWS", True)
    monkeypatch.setattr(screen_capture, "current_session_id", lambda: 0)
    assert screen_capture.in_session_zero() is True
    # An interactive login can capture its own desktop; spawning a helper
    # there would be a second process doing what this one already can.
    monkeypatch.setattr(screen_capture, "current_session_id", lambda: 1)
    assert screen_capture.in_session_zero() is False


def test_spawn_refuses_when_nobody_is_logged_in(monkeypatch):
    """There is no desktop to capture, and saying so is the honest answer."""
    monkeypatch.setattr(screen_capture, "IS_WINDOWS", True)
    monkeypatch.setattr(screen_capture, "active_console_session", lambda: None)
    with pytest.raises(screen_capture.CaptureUnavailable) as excinfo:
        screen_capture.spawn_helper()
    assert "logged in" in str(excinfo.value).lower()


def test_spawn_refuses_off_windows(monkeypatch):
    monkeypatch.setattr(screen_capture, "IS_WINDOWS", False)
    with pytest.raises(screen_capture.CaptureUnavailable):
        screen_capture.spawn_helper()


def test_the_reason_is_written_for_an_operator(monkeypatch):
    """These strings reach the console verbatim. A reason nobody can act on
    is the failure this module was built to remove."""
    monkeypatch.setattr(screen_capture, "IS_WINDOWS", False)
    monkeypatch.delenv("DISPLAY", raising=False)
    assert "DISPLAY" in screen_capture.describe_unavailable()

    monkeypatch.setattr(screen_capture, "IS_WINDOWS", True)
    monkeypatch.setattr(screen_capture, "active_console_session", lambda: None)
    assert "logged in" in screen_capture.describe_unavailable()

    monkeypatch.setattr(screen_capture, "active_console_session", lambda: 1)
    reason = screen_capture.describe_unavailable()
    assert "session 0" in reason


# ---------------------------------------------------------------------------
# Re-entry
# ---------------------------------------------------------------------------

def test_frozen_helper_reenters_the_binary(monkeypatch):
    """One shipped file. A separate helper executable would be a second thing
    to sign, ship and get out of step with the agent."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Program Files\Sentora-Agent\main.exe")
    argv = screen_capture.helper_command(10, 60, 1280)
    assert argv[0].endswith("main.exe")
    assert "--screen-helper" in argv


def test_unfrozen_helper_names_the_script(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(sys, "argv", ["/opt/sentora/main.py"])
    argv = screen_capture.helper_command(10, 60, 1280)
    assert argv[0] == "/usr/bin/python3"
    assert argv[1].endswith("main.py")


def test_helper_arguments_survive_the_round_trip():
    argv = screen_capture.helper_command(24, 90, 1920)
    assert argv[argv.index("--fps") + 1] == "24"
    assert argv[argv.index("--q") + 1] == "90"
    assert argv[argv.index("--w") + 1] == "1920"


def test_helper_main_defaults_when_arguments_are_missing(monkeypatch):
    """A malformed argv must not crash the helper into a silent exit - it
    falls back to the same defaults the direct path uses."""
    seen = {}

    def fake_run(fps, quality, width):
        seen.update(fps=fps, quality=quality, width=width)
        return 0

    monkeypatch.setattr(screen_capture, "run_helper", fake_run)
    screen_capture.helper_main(["main.exe", "--screen-helper"])
    assert seen == {"fps": 10, "quality": 60, "width": 1280}

    seen.clear()
    screen_capture.helper_main(["main.exe", "--screen-helper", "--fps", "banana"])
    assert seen["fps"] == 10


def test_helper_main_reads_the_values_it_is_given(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        screen_capture, "run_helper",
        lambda fps, quality, width: seen.update(fps=fps, quality=quality, width=width))
    screen_capture.helper_main(
        ["main.exe", "--screen-helper", "--fps", "15", "--q", "80", "--w", "1600"])
    assert seen == {"fps": 15, "quality": 80, "width": 1600}


# ---------------------------------------------------------------------------
# Stream lifecycle
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True


def test_closing_the_stream_stops_the_helper():
    """A helper left running after the viewer goes away is a process
    screenshotting somebody's desktop with nobody watching."""
    proc = _FakeProc()
    reader = io.BytesIO(screen_capture.encode_frame(b"frame"))
    stream = screen_capture.HelperStream(proc, reader)

    assert stream.read_frame() == b"frame"
    stream.close()
    assert proc.terminated is True
    assert stream.read_frame() is None


def test_close_is_idempotent():
    proc = _FakeProc()
    stream = screen_capture.HelperStream(proc, io.BytesIO(b""))
    stream.close()
    stream.close()
    assert proc.terminated is True
