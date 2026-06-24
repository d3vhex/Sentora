import psutil
import socket
import datetime
import os
import platform
import subprocess

class LateralMovementDetector:
    """
    Detects suspicious lateral movement patterns such as:
    - Unusual RDP/SSH connections.
    - Multiple failed logon attempts (simulated).
    - Remote process execution (simulated).
    """
    def __init__(self):
        self.suspicious_ports = [3389, 22, 5900, 445, 139]
        
    def check_network_connections(self):
        findings = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    remote_ip, remote_port = conn.raddr if conn.raddr else (None, None)
                    if remote_port in self.suspicious_ports:
                        findings.append({
                            "type": "LATERAL_MOVEMENT",
                            "severity": "MEDIUM",
                            "message": f"Established connection on sensitive port {remote_port} from {remote_ip}",
                            "details": {
                                "local_port": conn.laddr.port,
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "pid": conn.pid
                            }
                        })
        except Exception as e:
            print(f"[LateralMovement] Error checking connections: {e}")
        return findings

    def check_suspicious_processes(self):
        findings = []
        suspicious_names = [
            "psexec.exe", "wsmprovhost.exe", "winrs.exe",
            "nmap", "masscan", "socat", "nc", "ncat", "netcat",
            "rdesktop", "mimikatz", "chisel"
        ]
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                if proc.info['name'] and proc.info['name'].lower() in suspicious_names:
                    findings.append({
                        "type": "LATERAL_MOVEMENT",
                        "severity": "HIGH",
                        "message": f"Suspicious process detected: {proc.info['name']}",
                        "details": {
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "user": proc.info['username']
                        }
                    })
        except Exception as e:
            pass
        return findings

    def check_brute_force(self):
        findings = []
        system = platform.system().lower()
        if system == "windows":
            try:
                cmd = ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/c:5", "/rd:true", "/f:text"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
                if res.returncode == 0 and res.stdout and "Event ID: 4625" in res.stdout:
                    findings.append({
                        "type": "BRUTE_FORCE",
                        "severity": "HIGH",
                        "message": "Recent failed logon attempts detected (Event ID 4625)",
                        "details": {"source": "Windows Security Event Log"}
                    })
            except Exception as e:
                pass
        elif system == "linux":
            try:
                cmd = ["journalctl", "-u", "sshd", "-n", "100", "--no-pager"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
                failed_count = (res.stdout or "").count("Failed password")
                if failed_count >= 5:
                    findings.append({
                        "type": "BRUTE_FORCE",
                        "severity": "HIGH",
                        "message": f"Multiple failed SSH logon attempts detected ({failed_count} recently)",
                        "details": {"source": "journalctl sshd"}
                    })
            except Exception as e:
                pass
        return findings

    def run(self):
        return self.check_network_connections() + self.check_suspicious_processes() + self.check_brute_force()

if __name__ == "__main__":
    detector = LateralMovementDetector()
    print(detector.run())
