import psutil
import platform
import socket
import os
import subprocess
from datetime import datetime
from .db import insert_record

def get_cpu_info():
    cpu_name = platform.processor()
    if not cpu_name or cpu_name == "":
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        cpu_name = line.split(":")[1].strip()
                        break
        except Exception:
            cpu_name = platform.machine()
    return cpu_name

def get_ram_info():
    virtual_mem = psutil.virtual_memory()
    total_gb = round(virtual_mem.total / (1024**3), 2)
    return f"{total_gb} GB RAM"

def _reg_get(subkey, value_name, default=""):
    """Read a registry value, returning default if absent or empty."""
    try:
        import winreg
        val = winreg.QueryValueEx(subkey, value_name)[0]
        val = str(val).strip()
        return val if val else default
    except Exception:
        return default

def _format_install_date(raw):
    """Windows stores InstallDate as 'YYYYMMDD'. Return 'YYYY-MM-DD' when possible."""
    raw = (raw or "").strip()
    if len(raw) == 8 and raw.isdigit():
        return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
    return raw or "N/A"

def _dpkg_install_dates():
    """Map dpkg package name -> install date (YYYY-MM-DD) using the mtime of each
    package's /var/lib/dpkg/info/<pkg>.list file. Directory is read once."""
    dates = {}
    info_dir = "/var/lib/dpkg/info"
    try:
        for fn in os.listdir(info_dir):
            if not fn.endswith(".list"):
                continue
            pkg = fn[:-5].split(":")[0]  # drop '.list' and any ':arch' suffix
            if pkg in dates:
                continue
            try:
                mtime = os.path.getmtime(os.path.join(info_dir, fn))
                dates[pkg] = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
            except Exception:
                continue
    except Exception:
        pass
    return dates

def get_installed_software():
    software = []
    os_type = platform.system().lower()
    
    if os_type == "linux":
        # Debian/Ubuntu: dpkg. Maintainer ≈ vendor; install date from info .list mtime.
        try:
            res = subprocess.run(["dpkg-query", "-W", "-f=${Package}|${Version}|${Maintainer}\n"], capture_output=True, text=True, encoding='utf-8', errors='replace')
            if res.returncode == 0:
                dpkg_dates = _dpkg_install_dates()
                for line in res.stdout.splitlines():
                    parts = line.split("|")
                    if len(parts) >= 2 and parts[0]:
                        vendor = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else "Unknown"
                        software.append({
                            "name": parts[0],
                            "version": parts[1],
                            "vendor": vendor,
                            "install_date": dpkg_dates.get(parts[0], "N/A"),
                        })
        except Exception:
            pass

        # RHEL/Fedora/SUSE: rpm exposes vendor and install time directly.
        if not software:
            try:
                res = subprocess.run(["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{VENDOR}|%{INSTALLTIME}\n"], capture_output=True, text=True, encoding='utf-8', errors='replace')
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split("|")
                        if len(parts) >= 2 and parts[0]:
                            vendor = parts[2].strip() if len(parts) >= 3 and parts[2].strip() and parts[2].strip() != "(none)" else "Unknown"
                            install_date = "N/A"
                            if len(parts) >= 4 and parts[3].strip().isdigit():
                                try:
                                    install_date = datetime.fromtimestamp(int(parts[3])).strftime("%Y-%m-%d")
                                except Exception:
                                    install_date = "N/A"
                            software.append({
                                "name": parts[0],
                                "version": parts[1],
                                "vendor": vendor,
                                "install_date": install_date,
                            })
            except Exception:
                pass
                
    elif os_type == "windows":
        try:
            import winreg
            paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            for path in paths:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    vendor = _reg_get(subkey, "Publisher", "Unknown")
                                    install_date = _format_install_date(_reg_get(subkey, "InstallDate", ""))
                                    software.append({
                                        "name": name,
                                        "version": version,
                                        "vendor": vendor,
                                        "install_date": install_date,
                                    })
                                except Exception:
                                    continue
                        except Exception:
                            continue
        except Exception:
            pass
            
    return software

def get_open_ports():
    ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                ports.append({
                    "port": conn.laddr.port,
                    "address": conn.laddr.ip,
                    "pid": conn.pid,
                    "process": psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                })
    except Exception:
        pass
    return ports

def get_gpu_info():
    if platform.system() == "Windows":
        try:
            ps_cmd = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-CimInstance Win32_VideoController | Select-Object Caption | ConvertTo-Json"
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding='utf-8')
            if res.returncode == 0 and res.stdout:
                import json
                data = json.loads(res.stdout)
                if isinstance(data, list):
                    return " / ".join([d.get("Caption", "") for d in data])
                return data.get("Caption", "Unknown GPU")
        except Exception: pass
    return "Unknown GPU"

def get_mobo_info():
    if platform.system() == "Windows":
        try:
            ps_cmd = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product | ConvertTo-Json"
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding='utf-8')
            if res.returncode == 0 and res.stdout:
                import json
                data = json.loads(res.stdout)
                if isinstance(data, list): data = data[0]
                return f"{data.get('Manufacturer', '')} {data.get('Product', '')}".strip()
        except Exception: pass
    return "Unknown Motherboard"

def scan_inventory():
    """Enhanced scan of hardware, software, and network context."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cpu = get_cpu_info()
    ram = get_ram_info()
    gpu = get_gpu_info()
    mobo = get_mobo_info()
    
    insert_record("hardware_inventory", {
        "type": "cpu", "name": cpu, "vendor_id": "CPU", "product_id": "Model",
        "serial_number": "N/A", "status": "active", "timestamp": timestamp, "sent": False
    })
    insert_record("hardware_inventory", {
        "type": "ram", "name": ram, "vendor_id": "System", "product_id": "Memory",
        "serial_number": "N/A", "status": "active", "timestamp": timestamp, "sent": False
    })
    insert_record("hardware_inventory", {
        "type": "gpu", "name": gpu, "vendor_id": "GPU", "product_id": "Display",
        "serial_number": "N/A", "status": "active", "timestamp": timestamp, "sent": False
    })
    insert_record("hardware_inventory", {
        "type": "motherboard", "name": mobo, "vendor_id": "System", "product_id": "BaseBoard",
        "serial_number": "N/A", "status": "active", "timestamp": timestamp, "sent": False
    })
    
    for part in psutil.disk_partitions():
        try:
            insert_record("hardware_inventory", {
                "type": "disk", "name": part.device, "vendor_id": part.fstype,
                "product_id": part.mountpoint, "serial_number": "N/A", "status": "active",
                "timestamp": timestamp, "sent": False
            })
        except Exception: continue

    software_list = get_installed_software()
    for sw in software_list:
        insert_record("software_inventory", {
            "name": sw["name"][:255],
            "version": sw["version"][:100],
            "vendor": (sw.get("vendor") or "Unknown")[:255],
            "install_date": sw.get("install_date") or "N/A",
            "timestamp": timestamp,
            "sent": False
        })

    ports = get_open_ports()
    for p in ports:
        insert_record("network_inventory", {
            "protocol": "TCP",
            "local_address": p["address"],
            "local_port": p["port"],
            "remote_address": "0.0.0.0",
            "state": "LISTEN",
            "process_name": p["process"],
            "pid": p["pid"],
            "timestamp": timestamp,
            "sent": False
        })

    print(f"[*] Inventory: Scanned {len(software_list)} apps and {len(ports)} open ports.")

def main():
    scan_inventory()

if __name__ == "__main__":
    main()
