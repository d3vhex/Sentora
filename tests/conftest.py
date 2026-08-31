"""Pytest fixtures shared across all test modules.

We deliberately keep these minimal — heavy MySQL/RabbitMQ setup belongs in
integration-only tests marked with `@pytest.mark.integration`.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# This directory too, so one test module can share a helper with another.
#
# Without it `from test_build_agent_sh import ...` raises ModuleNotFoundError,
# and the workaround is to copy the helper - which has already happened twice
# for the same twelve lines. Every module here is named `test_*`, so nothing
# it exposes can shadow a real package.
sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(scope="session", autouse=True)
def _stub_env(tmp_path_factory):
    """Default env that lets app.py import without touching a real DB or
    network stack. Anything that needs the real stack must mark itself
    `@pytest.mark.integration` and skip-if-not-configured."""
    fake_data = tmp_path_factory.mktemp("sentora-test-data")
    os.environ.setdefault("FERNET_KEY_PATH", str(fake_data / "fernet.key"))
    os.environ.setdefault("AGENT_SHARED_SECRET", "test-shared-secret-32chars-_______")
    os.environ.setdefault("DB_HOST", "127.0.0.1")
    os.environ.setdefault("DB_PORT", "3306")
    os.environ.setdefault("DB_USER", "root")
    os.environ.setdefault("DB_PASSWORD", "test-password")
    os.environ.setdefault("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api")
    yield
