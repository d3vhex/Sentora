"""The lock must describe the image that gets built.

`requirements.txt` named twenty packages with no versions. Two builds of the
same commit installed different code, and a Trivy run was a statement about
the afternoon it ran rather than about this repository: CI green, production
on a different version.

The failure mode this guards against is subtler than "no lock". It is a lock
that has drifted from the spec — someone adds a dependency, forgets to
regenerate, and the scan keeps passing while covering a set that is no longer
what ships.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = ROOT / "requirements.txt"
LOCK = ROOT / "requirements.lock"


def _normalise(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _spec_packages() -> set[str]:
    out = set()
    for line in SPEC.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        out.add(_normalise(re.split(r"[\[<>=!;]", line)[0]))
    return out


def _lock_packages() -> dict[str, str]:
    out = {}
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        if line.startswith((" ", "#")) or "==" not in line:
            continue
        name, version = line.split("==", 1)
        out[_normalise(name)] = version.split()[0].strip()
    return out


def test_the_lock_exists():
    assert LOCK.exists(), "requirements.lock is missing; see its header to regenerate"


def test_every_declared_dependency_is_pinned():
    missing = _spec_packages() - set(_lock_packages())
    assert not missing, (
        f"in requirements.txt but not locked: {sorted(missing)}. "
        f"Regenerate the lock — see its header."
    )


def test_every_pin_has_a_version():
    for name, version in _lock_packages().items():
        assert re.fullmatch(r"[0-9][0-9A-Za-z.\-+!]*", version), (name, version)


def test_transitive_dependencies_are_pinned_too():
    """A lock that only covers direct dependencies is not a lock: most CVEs
    arrive through something you did not name."""
    locked = _lock_packages()
    assert len(locked) > len(_spec_packages()), (
        "the lock has no transitive packages, so it was not produced by a "
        "resolver"
    )


def test_the_dockerfile_installs_from_the_lock():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "requirements.lock" in text
    assert not re.search(r"pip install[^\n]*-r [^\n]*requirements\.txt", text), (
        "the image still installs from the unpinned list"
    )


def test_the_scanner_would_catch_a_stale_lock():
    """CI is not the only place this must hold, but it must hold there too."""
    wf = ROOT / ".github" / "workflows" / "trivy.yml"
    if not wf.exists():
        pytest.skip("no trivy workflow")
    text = wf.read_text(encoding="utf-8")
    assert "requirements.lock" in text


def test_the_lock_says_how_to_regenerate_it():
    """Resolution is platform-specific; a lock produced on a developer's
    machine describes a build that never happens."""
    head = LOCK.read_text(encoding="utf-8")[:1600]
    assert "pip-compile" in head
    assert "python:3.10-slim" in head or "image Python" in head
