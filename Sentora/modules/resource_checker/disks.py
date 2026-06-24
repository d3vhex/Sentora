import psutil
import json
import platform
from datetime import datetime
from modules.db import insert_record, fetch_where, update_record, delete_all

def bytes_to_gb(byte_value):
    return round(byte_value / (1024**3), 2)

def send_local_alert(severity, message, metadata=None):
    """Helper to send alert to local events_alert table."""
    try:
        rec = {
            "source": "DiskMonitor",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "message": message,
            "categories": "system"
        }
        if metadata:
            rec["message"] += f" | {json.dumps(metadata)}"
        insert_record("events_alert", rec)
    except Exception as e:
        print(f"[DiskMonitor] Failed to send alert: {e}")

def _iter_partitions():
    """Cross-platform partition enumeration that survives the Windows
    `psutil.disk_partitions()` quirks where CD/floppy/removable entries
    can raise PermissionError just from being listed."""
    try:
        return psutil.disk_partitions(all=False)
    except Exception as e:
        print(f"[DiskMonitor] disk_partitions(all=False) failed: {e}", flush=True)
        try:
            return psutil.disk_partitions(all=True)
        except Exception as ee:
            print(f"[DiskMonitor] disk_partitions(all=True) failed: {ee}", flush=True)
            return []


def get_and_save_disk_info():
    is_windows = platform.system().lower() == 'windows'
    try:
        try:
            existing_rows = fetch_where("disk_usage")
        except Exception as e:
            print(f"[DiskMonitor] fetch_where('disk_usage') failed: {e}", flush=True)
            existing_rows = []
        existing_devices = {r['device'] for r in existing_rows}

        try:
            delete_all('disk_usage')
        except Exception as e:
            print(f"[DiskMonitor] delete_all('disk_usage') failed: {e}", flush=True)

        current_devices = set()
        partitions = _iter_partitions()
        ok = 0
        skipped = 0
        for partition in partitions:
            try:
                device = partition.device
                mountpoint = partition.mountpoint
                opts = (partition.opts or '').lower()

                if is_windows and ('cdrom' in opts or not mountpoint):
                    skipped += 1
                    continue

                current_devices.add(device)

                usage = psutil.disk_usage(mountpoint)
                data = {
                    'device': device,
                    'mountpoint': mountpoint,
                    'total_gb': bytes_to_gb(usage.total),
                    'used_gb': bytes_to_gb(usage.used),
                    'free_gb': bytes_to_gb(usage.free),
                    'percent': usage.percent,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                if device not in existing_devices and existing_devices:
                    send_local_alert(
                        "CRITICAL",
                        f"New disk entry detected: {device} mounted at {mountpoint}",
                        {"device": device, "mountpoint": mountpoint, "total_gb": data['total_gb']}
                    )

                try:
                    insert_record("disk_usage", data)
                    ok += 1
                except Exception as ie:
                    print(f"[DiskMonitor] insert failed for {device}: {ie}", flush=True)
                    skipped += 1

            except (PermissionError, OSError):
                skipped += 1
                continue
            except Exception as e:
                skipped += 1
                print(f"Could not get info for {partition.device}. Error: {e}", flush=True)

        if ok or skipped:
            print(f"[DiskMonitor] cycle: persisted={ok} skipped={skipped} partitions={len(partitions)}", flush=True)

    except Exception as e:
        print(f"An unexpected error occurred in DiskMonitor: {e}", flush=True)

