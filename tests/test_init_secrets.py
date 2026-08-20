"""Tests for the secret bootstrapper.

The property that matters most is the negative one: running this twice must
never rotate a key that already has a value. FERNET_KEY has no rotation path,
so an accidental second run that regenerated it would silently make every
previously encrypted column unreadable.
"""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from scripts import init_secrets


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Point the script at a throwaway .env."""
    path = tmp_path / ".env"
    monkeypatch.setattr(init_secrets, "ENV_PATH", path)
    return path


def values_in(path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, value = stripped.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def test_placeholder_is_replaced(env_file):
    env_file.write_text("FERNET_KEY=<RUN-scripts/init_secrets.py>\n", encoding="utf-8")

    assert init_secrets.main() == 0

    value = values_in(env_file)["FERNET_KEY"]
    assert not value.startswith("<")
    Fernet(value.encode())  # raises unless it is a usable key


def test_empty_value_is_filled(env_file):
    env_file.write_text("RABBITMQ_PASSWORD=\n", encoding="utf-8")

    assert init_secrets.main() == 0
    assert values_in(env_file)["RABBITMQ_PASSWORD"] != ""


def test_missing_keys_are_appended(env_file):
    env_file.write_text("DB_PASSWORD=already-set\n", encoding="utf-8")

    assert init_secrets.main() == 0

    values = values_in(env_file)
    for key in init_secrets.GENERATORS:
        assert values.get(key), f"{key} was not written"
    assert values["DB_PASSWORD"] == "already-set"


def test_existing_value_is_never_overwritten(env_file):
    """The guard against destroying a database's worth of encrypted columns."""
    original = Fernet.generate_key().decode()
    env_file.write_text(f"FERNET_KEY={original}\n", encoding="utf-8")

    assert init_secrets.main() == 0
    assert values_in(env_file)["FERNET_KEY"] == original


def test_running_twice_changes_nothing(env_file):
    env_file.write_text("", encoding="utf-8")

    assert init_secrets.main() == 0
    first = values_in(env_file)

    assert init_secrets.main() == 0
    assert values_in(env_file) == first


def test_db_password_is_not_generated(env_file):
    """MySQL fixes root's password at volume init, so writing a fresh one here
    would lock the app out rather than rotate anything."""
    assert "DB_PASSWORD" not in init_secrets.GENERATORS


@pytest.mark.parametrize("key", ["RABBITMQ_PASSWORD", "AGENT_SHARED_SECRET", "OPENSEARCH_PASSWORD"])
def test_generated_passwords_survive_url_interpolation(env_file, key):
    """The broker password is interpolated into an amqp:// URL unescaped."""
    env_file.write_text("", encoding="utf-8")
    assert init_secrets.main() == 0

    value = values_in(env_file)[key]
    assert value
    for char in (":", "@", "/", "#", "?", " ", '"', "'"):
        assert char not in value, f"{key} contains {char!r}, which breaks URL interpolation"


def test_generated_secrets_differ_from_each_other(env_file):
    env_file.write_text("", encoding="utf-8")
    assert init_secrets.main() == 0

    values = values_in(env_file)
    generated = [values[key] for key in init_secrets.GENERATORS]
    assert len(set(generated)) == len(generated), "a secret was reused across keys"


def test_missing_env_file_is_an_error_not_a_crash(env_file):
    assert not env_file.exists()
    assert init_secrets.main() == 1


def test_comments_and_unrelated_keys_are_preserved(env_file):
    env_file.write_text(
        "# leading comment\n"
        "DB_HOST=db\n"
        "FERNET_KEY=<RUN-scripts/init_secrets.py>\n"
        "# trailing comment\n"
        "OSV_MODE=auto\n",
        encoding="utf-8",
    )

    assert init_secrets.main() == 0

    text = env_file.read_text(encoding="utf-8")
    assert "# leading comment" in text
    assert "# trailing comment" in text
    assert "DB_HOST=db" in text
    assert "OSV_MODE=auto" in text
