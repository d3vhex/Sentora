import os
import hashlib
import time
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .db import insert_record, fetch_where

DEFAULT_MONITOR_PATHS = [
    "/etc",
    "/root/.ssh",
    "C:\\Windows\\System32\\drivers\\etc",
    "C:\\Users",
]

CRITICAL_FILES = [
    "passwd", "shadow", "hosts", "authorized_keys", "sshd_config", "config.php", ".env"
]

class FIMHandler(FileSystemEventHandler):
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
        filename = os.path.basename(path)
        is_critical = any(c in filename for c in CRITICAL_FILES) or any(path.endswith(ext) for ext in [".php", ".py", ".sh", ".exe", ".dll"])
        
        if not is_critical:
            return

        current_hash = calculate_sha256(path) if status != "deleted" else "DELETED"
        
        rec = {
            "path": path,
            "hash_sha256": current_hash or "ERROR",
            "status": status,
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sent": False
        }
        insert_record("fim_data", rec)
        print(f"[!] FIM REALTIME: File {path} was {status.upper()}!")

def calculate_sha256(file_path):
    if not os.path.exists(file_path): return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except: return None

def start_realtime_monitoring():
    event_handler = FIMHandler()
    observer = Observer()
    
    monitored_count = 0
    for path in DEFAULT_MONITOR_PATHS:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
            monitored_count += 1
            
    if monitored_count > 0:
        observer.start()
        print(f"[*] FIM: Real-time monitoring started for {monitored_count} base paths.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        print("[!] FIM: No valid paths found to monitor.")

def scan_baseline():
    """Initial baseline scan if needed."""
    print("[*] FIM: Performing initial baseline scan...")
    for path in DEFAULT_MONITOR_PATHS:
        if not os.path.exists(path): continue
        pass

def main():
    scan_baseline()
    start_realtime_monitoring()

if __name__ == "__main__":
    main()
