"""Tests for the agent's single-instance lock.

The installer registers a watchdog task that launches the agent every 15
minutes. That is only safe if a second launch refuses to run, so this is the
guard that makes the watchdog usable rather than a duplicate-spawning loop.

Imported by path rather than as a package: Sentora/main.py pulls in the whole
agent (psutil, watchdog, docker) at import time, none of which belongs in a
server-side test run.
"""
from __future__ import annotations

import socket
import time

import pytest


# The lock implementation, lifted verbatim in shape from Sentora/main.py.
# Duplicated deliberately: importing main.py would drag in the agent's entire
# dependency tree, and what is under test is the locking behaviour itself.
_instance_lock = None


def acquire_single_instance_lock(port: int, wait_seconds: int = 0) -> bool:
    global _instance_lock
    deadline = time.time() + wait_seconds
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            s.listen(1)
            _instance_lock = s
            return True
        except OSError:
            s.close()
            if time.time() >= deadline:
                return False
            time.sleep(0.2)


@pytest.fixture
def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(autouse=True)
def _release_lock():
    yield
    global _instance_lock
    if _instance_lock is not None:
        _instance_lock.close()
        _instance_lock = None


def test_first_instance_acquires_the_lock(free_port):
    assert acquire_single_instance_lock(free_port) is True


def test_second_instance_is_refused(free_port):
    """The property the watchdog depends on."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", free_port))
    holder.listen(1)
    try:
        assert acquire_single_instance_lock(free_port) is False
    finally:
        holder.close()


def test_lock_is_released_when_the_holder_closes(free_port):
    """No stale-lock problem: a PID file would need liveness checking, a
    socket is reclaimed by the OS however the process died."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", free_port))
    holder.listen(1)
    assert acquire_single_instance_lock(free_port) is False

    holder.close()
    assert acquire_single_instance_lock(free_port) is True


def test_wait_window_covers_a_restarting_predecessor(free_port):
    """The deliberate-restart path: the outgoing agent may hold the socket for
    a moment after being signalled, and the incoming one should not give up."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", free_port))
    holder.listen(1)

    import threading
    threading.Timer(0.5, holder.close).start()

    start = time.time()
    assert acquire_single_instance_lock(free_port, wait_seconds=5) is True
    assert time.time() - start < 5, "should have acquired as soon as it was free"


def test_lock_reference_is_retained(free_port):
    """The socket must outlive the function call. If it were a local, garbage
    collection would close it and release the lock while the agent still ran."""
    assert acquire_single_instance_lock(free_port) is True
    assert _instance_lock is not None
    assert _instance_lock.fileno() != -1
