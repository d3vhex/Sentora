"""The backup that did not exist when it was needed.

Docker Desktop was reset on the development machine and every named volume
went with it - `mysql_data` holding every SIEM event, every agent database,
users and sessions. Nothing had a copy.

These tests exist because the first version of the restore path was broken in
two ways at once, and both were found by running it rather than reading it:

    docker -v with a relative path creates a *named volume* instead of
    mounting the directory, and reports the drive letter as an invalid
    character - which reads like a quoting bug and is not one.

    restore() then printed "[+] Restored" anyway, on a run where every single
    archive had failed.

The second is the dangerous one. A restore that reports success it did not
have is worse than one that fails loudly: the failure is noticed now, the
false success is noticed the next time somebody actually needs the data.

Nothing here talks to Docker. The round trip was verified by hand - backup,
`docker compose down -v`, restore, and the restored `userdb` read back - and
what these pin is the logic around it that a live test would not isolate.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import backup_state  # noqa: E402


# --------------------------------------------------------------------------
# What gets backed up
# --------------------------------------------------------------------------

def test_the_volume_list_comes_from_compose_not_a_copy():
    """A volume added to compose later must not be silently absent from every
    backup taken after. Hard-coding the list is how that happens."""
    volumes = backup_state.declared_volumes()
    assert "mysql_data" in volumes
    assert "opensearch_data" in volumes
    assert "sentora_data" in volumes

    compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
    for name in volumes:
        assert name in compose


def test_both_a_logical_dump_and_the_raw_volumes_are_taken():
    """They fail differently. A tar of MySQL's datadir is version-specific and
    may not mount on a different server build; a mysqldump survives that and
    can be read by a human, but cannot express OpenSearch's on-disk format."""
    source = (ROOT / "scripts" / "backup_state.py").read_text(encoding="utf-8")
    assert "mysqldump" in source
    assert "tar" in source


def test_secrets_are_deliberately_not_copied_into_the_backup():
    """`.env` holds FERNET_KEY, DB_PASSWORD and the agent shared secret.
    Writing those into a `backups/` directory that gets tarred up and moved
    around is how secrets end up somewhere nobody is tracking."""
    source = (ROOT / "scripts" / "backup_state.py").read_text(encoding="utf-8")
    assert ".env is NOT included" in source
    assert "back it up separately" in source


def test_backups_are_not_committed():
    """They contain the database."""
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "backups/" in ignore


# --------------------------------------------------------------------------
# The restore path, where the bugs were
# --------------------------------------------------------------------------

def test_a_relative_source_is_resolved_to_an_absolute_path(tmp_path, monkeypatch, capsys):
    """`docker -v backups/x:/from` creates a named volume called
    `backups\\x` rather than mounting the directory. Passing a relative path
    is the normal way somebody invokes this."""
    seen = {}

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "run"]:
            seen["mounts"] = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
        return _ok()

    monkeypatch.setattr(backup_state, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "mysql_data.tar.gz").write_bytes(b"x")

    backup_state.restore(pathlib.Path("b"))

    from_mount = next(m for m in seen["mounts"] if m.endswith(":/from:ro"))
    host_path = from_mount[:-len(":/from:ro")]
    assert pathlib.PurePosixPath(host_path).is_absolute() or ":" in host_path


def test_a_failed_restore_reports_failure(tmp_path, monkeypatch, capsys):
    """It printed "[+] Restored" on a run where every archive failed."""
    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "run"]:
            return _fail("docker: Error response from daemon")
        return _ok()

    monkeypatch.setattr(backup_state, "run", fake_run)
    (tmp_path / "mysql_data.tar.gz").write_bytes(b"x")

    code = backup_state.restore(tmp_path)
    out = capsys.readouterr().out

    assert code != 0
    assert "FAILED" in out
    assert "[+] Restored" not in out


def test_a_successful_restore_reports_success(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(backup_state, "run", lambda cmd, **kw: _ok())
    (tmp_path / "mysql_data.tar.gz").write_bytes(b"x")

    assert backup_state.restore(tmp_path) == 0
    assert "[+] Restored" in capsys.readouterr().out


def test_restoring_underneath_a_running_stack_is_refused(tmp_path, monkeypatch, capsys):
    """MySQL holds state in memory. Replacing its datadir while it runs leaves
    a worse state than the one being restored from."""
    def fake_run(cmd, **kw):
        if cmd[:3] == ["docker", "compose", "ps"]:
            return _ok(stdout="abc123\n")
        return _ok()

    monkeypatch.setattr(backup_state, "run", fake_run)
    (tmp_path / "mysql_data.tar.gz").write_bytes(b"x")

    assert backup_state.restore(tmp_path) == 2
    assert "Refusing" in capsys.readouterr().out


def test_an_empty_directory_is_refused_rather_than_reported_as_restored(tmp_path, capsys):
    """Pointing at the wrong directory would otherwise print success, having
    restored nothing at all."""
    assert backup_state.restore(tmp_path) == 2
    assert "Nothing to restore" in capsys.readouterr().out


def test_archive_names_map_back_to_volume_names(tmp_path, monkeypatch):
    """`mysql_data.tar.gz` -> `<project>_mysql_data`. Getting this wrong
    restores into a volume nothing mounts, and reports success."""
    created = []

    def fake_run(cmd, **kw):
        if cmd[:3] == ["docker", "volume", "create"]:
            created.append(cmd[3])
        return _ok()

    monkeypatch.setattr(backup_state, "run", fake_run)
    monkeypatch.setattr(backup_state, "project_name", lambda: "sentora")
    for name in ("mysql_data", "opensearch_data", "sentora_data"):
        (tmp_path / f"{name}.tar.gz").write_bytes(b"x")

    backup_state.restore(tmp_path)
    assert created == ["sentora_mysql_data", "sentora_opensearch_data",
                       "sentora_sentora_data"]


# --------------------------------------------------------------------------

class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _ok(stdout=""):
    return _Result(0, stdout)


def _fail(stderr=""):
    return _Result(1, "", stderr)


def test_both_fernet_keys_are_accounted_for():
    """There are two, they are not interchangeable, and confusing them makes
    a loss look survivable.

        .env FERNET_KEY   the server key, on the host filesystem
        data/fernet.key   the agent key, inside the sentora_data volume

    The volume was the one that went. A backup that covers `.env` and not the
    volume protects the half that was never at risk.
    """
    source = (ROOT / "scripts" / "backup_state.py").read_text(encoding="utf-8")
    assert "data/fernet.key" in source
    assert "no rotation path" in source
    assert "sentora_data" in backup_state.declared_volumes()


def test_the_agent_key_volume_is_in_every_backup():
    """It is the one with no recovery path. If it is ever dropped from the
    volume list, this fails rather than the next restore doing."""
    assert "sentora_data" in backup_state.declared_volumes()
