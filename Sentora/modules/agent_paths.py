r"""Where the agent's editable configuration actually lives.

The problem
-----------
`set_config` wrote to `os.path.dirname(os.path.abspath(__file__))/conf/...`
and `log_extractor` read from the same place. Inside a PyInstaller **onefile**
build that path is `sys._MEIPASS` - a temporary directory the bootloader
extracts into and **deletes when the process exits**.

So pushing a rules change from the console:

  1. wrote the file
  2. answered "Config updated successfully"
  3. was read back correctly for the rest of that process's life
  4. vanished on the next restart, silently reverting to the shipped copy

An operator tightening a detection rule had every reason to believe it had
taken. The agent restarts on a fifteen-minute watchdog, so the window in which
the change appeared to exist was usually short and never announced.

The rule
--------
Two locations, and which is which matters:

  **bundled**    inside the binary (`_MEIPASS/conf`). Read-only, ships with
                 the build, and is the default a fresh install starts from.
  **persistent** `conf/` beside the executable, in the install directory.
                 Writable, survives restarts, and wins when it exists.

Reads prefer the persistent copy and fall back to the bundled one, so an agent
that has never been reconfigured still has rules. Writes always go to the
persistent copy - never into a directory that is about to be deleted.

Unfrozen (a developer running from source) both resolve to the repository's
own `conf/`, which is the behaviour that already existed.
"""

from __future__ import annotations

import os
import shutil
import sys

CONFIG_FILES = {
    "rules": "rules.yaml",
    "log_paths": "log_paths.yaml",
    "file_scan": "file_scan.yaml",
}


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundled_config_dir() -> str:
    """The read-only `conf/` that ships inside the build."""
    if is_frozen():
        base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(sys.executable))
        return os.path.join(base, "conf")
    # From source: <repo>/Sentora/conf, two levels up from modules/agent_paths.py
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "conf"))


def persistent_config_dir() -> str:
    """The writable `conf/` in the install directory. Survives restarts."""
    if is_frozen():
        return os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "conf")
    return bundled_config_dir()


def config_path(name: str) -> str:
    """Where to *read* one config from: persistent if present, else bundled.

    `name` is a key of `CONFIG_FILES` or a bare filename.
    """
    filename = CONFIG_FILES.get(name, name)
    persistent = os.path.join(persistent_config_dir(), filename)
    if os.path.exists(persistent):
        return persistent
    return os.path.join(bundled_config_dir(), filename)


def writable_config_path(name: str) -> str:
    """Where to *write* one config. Creates the directory if needed.

    Seeds from the bundled copy on first write so that a partial edit is never
    saved over nothing - and so the file on disk after a write is the whole
    config, not just whatever the console happened to send.
    """
    filename = CONFIG_FILES.get(name, name)
    target_dir = persistent_config_dir()
    os.makedirs(target_dir, exist_ok=True)
    return os.path.join(target_dir, filename)


def seed_persistent_config() -> list[str]:
    """Copy the bundled configs into the install directory once.

    Called at startup. Without it the first read after an upgrade silently
    changes which file is in use: a host that had been reconfigured keeps its
    persistent copy, and one that had not starts using the new build's
    defaults - which is correct, but only if both files exist where they are
    expected.

    Returns the files it created. Never overwrites: a persistent config is an
    operator's decision and a new build must not quietly discard it.
    """
    created: list[str] = []
    if not is_frozen():
        return created

    source_dir = bundled_config_dir()
    target_dir = persistent_config_dir()
    if os.path.abspath(source_dir) == os.path.abspath(target_dir):
        return created

    try:
        os.makedirs(target_dir, exist_ok=True)
    except Exception:
        return created

    for filename in CONFIG_FILES.values():
        source = os.path.join(source_dir, filename)
        target = os.path.join(target_dir, filename)
        if os.path.exists(target) or not os.path.exists(source):
            continue
        try:
            shutil.copy2(source, target)
            created.append(target)
        except Exception:
            continue
    return created
