import os
import platform
import subprocess
import glob

class PersistenceHunter:
    """
    Hunts for common persistence mechanisms used by malware.
    """
    def __init__(self):
        self.system = platform.system().lower()

    def check_windows_registry(self):
        findings = []
        cmd = ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -ErrorAction SilentlyContinue | ConvertTo-Json"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
            if res.returncode == 0 and res.stdout and res.stdout.strip():
                import json
                try:
                    data = json.loads(res.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        for k, v in item.items():
                            if k not in ["PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider"]:
                                val_str = str(v).lower()
                                if "temp" in val_str or "appdata" in val_str or ".vbs" in val_str or ".ps1" in val_str:
                                    findings.append({
                                        "type": "PERSISTENCE",
                                        "severity": "HIGH",
                                        "message": f"Suspicious Registry Run Key detected: {k}",
                                        "details": {"key": k, "value": v}
                                    })
                except Exception as e:
                    pass
        except Exception:
            pass
        return findings

    def check_windows_startup(self):
        findings = []
        try:
            startup_path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.exists(startup_path):
                for f in os.listdir(startup_path):
                    if f.lower() != "desktop.ini":
                        findings.append({
                            "type": "PERSISTENCE",
                            "severity": "MEDIUM",
                            "message": f"File in Startup folder: {f}",
                            "details": {"file": f, "path": startup_path}
                        })
        except Exception:
            pass
        return findings

    def check_linux_cron(self):
        findings = []
        cron_paths = ["/etc/crontab", "/etc/cron.d/"]
        for p in cron_paths:
            if os.path.isfile(p):
                try:
                    with open(p, "r") as f:
                        for line in f:
                            if "wget " in line or "curl " in line or "nc " in line or "bash -i" in line:
                                findings.append({
                                    "type": "PERSISTENCE",
                                    "severity": "HIGH",
                                    "message": f"Suspicious cron job found in {p}",
                                    "details": {"payload": line.strip()}
                                })
                except Exception:
                    pass
            elif os.path.isdir(p):
                for item in os.listdir(p):
                    try:
                        with open(os.path.join(p, item), "r") as f:
                            for line in f:
                                if "wget " in line or "curl " in line or "nc " in line or "bash -i" in line:
                                    findings.append({
                                        "type": "PERSISTENCE",
                                        "severity": "HIGH",
                                        "message": f"Suspicious cron job found in {os.path.join(p, item)}",
                                        "details": {"payload": line.strip()}
                                    })
                    except Exception:
                        pass
        return findings

    def check_linux_bashrc(self):
        findings = []
        bashrc_path = os.path.expanduser("~/.bashrc")
        if os.path.isfile(bashrc_path):
            try:
                with open(bashrc_path, "r") as f:
                    for line in f:
                        if "nc " in line or "bash -i" in line or "/dev/tcp/" in line:
                            findings.append({
                                "type": "PERSISTENCE",
                                "severity": "HIGH",
                                "message": f"Suspicious alias/command in ~/.bashrc",
                                "details": {"payload": line.strip()}
                            })
            except Exception:
                pass
        return findings

    def run(self):
        findings = []
        if self.system == "windows":
            findings.extend(self.check_windows_registry())
            findings.extend(self.check_windows_startup())
        elif self.system == "linux":
            findings.extend(self.check_linux_cron())
            findings.extend(self.check_linux_bashrc())
        return findings

if __name__ == "__main__":
    hunter = PersistenceHunter()
    print(hunter.run())
