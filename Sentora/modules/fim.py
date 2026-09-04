"""Real-time file integrity monitoring.

What this used to do: watch all of `C:\\Users` recursively, with no
exclusions, and record every `.py`, `.exe`, `.dll`, `.sh` or `.php` written
anywhere beneath it.

On a real Windows host that is `AppData\\Local\\Temp`, browser caches, pip and
npm installs, build output and every DLL a program unpacks - thousands of
"integrity violation" events an hour, none of them about integrity. The local
queue never drained: `fim_data sent (50 rows)` every ten seconds for ever,
while `network_connections` and `hardware_inventory` waited behind it. And a
real change to `/etc/shadow` arrived in the console among ten thousand rows
about a temp directory, which is the same as not arriving.

The exclusions were not missing by oversight. `conf/file_scan.yaml` has an
`exclude_dirs` key, the console pushes it, and `check_permissions` honours it -
this module never read the file at all, so the setting was configurable,
documented, and connected to nothing.
"""

import fnmatch
import hashlib
import os
import time
from datetime import datetime

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from . import agent_paths
from .db import insert_record

DEFAULT_MONITOR_PATHS = [
    "/etc",
    "/root/.ssh",
    "C:\\Windows\\System32\\drivers\\etc",
    "C:\\Users",
]

#: Directories that churn on every host and mean nothing when they do.
#:
#: Watching `C:\\Users` at all is only defensible with these: the interesting
#: things under it are a user's own documents, startup folders and ssh keys,
#: and none of those live here. A deployment that genuinely wants one of them
#: watched can shorten this list in `file_scan.yaml`.
DEFAULT_EXCLUDES = {
    "windows": [
        "*\\AppData\\Local\\Temp\\*",
        "*\\AppData\\Local\\Packages\\*",
        "*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*",
        "*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*",
        "*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Cache\\*",
        "*\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\*\\cache2\\*",
        "*\\AppData\\Local\\pip\\cache\\*",
        "*\\AppData\\Roaming\\npm-cache\\*",
        "*\\node_modules\\*",
        "*\\$Recycle.Bin\\*",
        "*\\.git\\*",
        "*\\__pycache__\\*",
        "*\\venv\\*",
        "*\\.venv\\*",
    ],
    "linux": [
        "/proc/*", "/sys/*", "/dev/*", "/run/*",
        "/var/lib/docker/*",
        "*/node_modules/*", "*/.git/*", "*/__pycache__/*",
        "*/venv/*", "*/.venv/*",
    ],
}

CRITICAL_FILES = [
    "passwd", "shadow", "hosts", "authorized_keys", "sshd_config",
    "config.php", ".env",
]

WATCHED_EXTENSIONS = (".php", ".py", ".sh", ".exe", ".dll")

IS_WINDOWS = os.name == "nt"


def _load_scan_config() -> tuple[list, list]:
    """(paths to watch, patterns to ignore) from `conf/file_scan.yaml`.

    Read at start rather than hardcoded, because the console pushes this file
    and an operator changing it expects something to happen. Falls back to the
    defaults above if the file is missing or unreadable - a FIM that refuses
    to start because a config file moved is worse than one watching the
    default set.
    """
    platform_key = "windows" if IS_WINDOWS else "linux"
    targets = [p for p in DEFAULT_MONITOR_PATHS if os.path.exists(p)]
    excludes = list(DEFAULT_EXCLUDES[platform_key])

    try:
        with open(agent_paths.config_path("file_scan"), "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except Exception as e:
        print(f"[FIM] file_scan.yaml unreadable ({e}); using defaults", flush=True)
        return targets, excludes

    configured = (cfg.get("target_dirs") or {}).get(platform_key) or []
    if configured:
        targets = [p for p in configured if os.path.exists(p)]

    # Added to the defaults rather than replacing them. Somebody adding one
    # directory should not silently lose the exclusion of every temp folder.
    for pattern in (cfg.get("exclude_dirs") or {}).get(platform_key) or []:
        pattern = str(pattern)
        if not any(ch in pattern for ch in "*?"):
            pattern = pattern.rstrip("/\\") + ("\\*" if IS_WINDOWS else "/*")
        if pattern not in excludes:
            excludes.append(pattern)

    return targets, excludes


def is_excluded(path: str, patterns) -> bool:
    """Whether a path is somewhere nobody wants an integrity alert about."""
    text = str(path)
    lowered = text.lower()
    for pattern in patterns:
        if fnmatch.fnmatch(lowered, str(pattern).lower()):
            return True
    return False


class FIMHandler(FileSystemEventHandler):
    def __init__(self, excludes=None):
        super().__init__()
        self.excludes = list(excludes or [])
        self.suppressed = 0

    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path, "modified")

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path, "created")

    def on_deleted(self, event):
        if not event.is_directory:
            self.process(event.src_path, "deleted")

    def process(self, path, status):
        # Before anything else, including the hash. Hashing a file in a temp
        # directory costs a read of it, and there are thousands.
        if is_excluded(path, self.excludes):
            self.suppressed += 1
            return

        filename = os.path.basename(path)
        is_critical = (any(c in filename for c in CRITICAL_FILES)
                       or path.endswith(WATCHED_EXTENSIONS))
        if not is_critical:
            return

        current_hash = calculate_sha256(path) if status != "deleted" else "DELETED"
        insert_record("fim_data", {
            "path": path,
            "hash_sha256": current_hash or "ERROR",
            "status": status,
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sent": False,
        })
        print(f"[!] FIM REALTIME: File {path} was {status.upper()}!")


def calculate_sha256(file_path):
    if not os.path.exists(file_path):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def start_realtime_monitoring():
    targets, excludes = _load_scan_config()
    if not targets:
        print("[!] FIM: No valid paths found to monitor.", flush=True)
        return

    handler = FIMHandler(excludes)
    observer = Observer()
    for path in targets:
        observer.schedule(handler, path, recursive=True)

    observer.start()
    print(f"[*] FIM: watching {len(targets)} path(s), "
          f"{len(excludes)} exclusion(s).", flush=True)
    try:
        while True:
            time.sleep(60)
            # How much noise the exclusions are absorbing. Without this the
            # only evidence that they are doing anything is the absence of
            # events, which is also what a broken watcher produces.
            if handler.suppressed:
                count = handler.suppressed
                print(f"[FIM] suppressed {count} events in excluded directories",
                      flush=True)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main():
    start_realtime_monitoring()


if __name__ == "__main__":
    main()
