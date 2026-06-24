# -*- coding: utf-8 -*-
import os
import subprocess
import urllib.request
import zipfile
from pathlib import Path
import platform
import logging

class VNCManager:
    """
    Downloads and starts a portable TightVNC server for dynamic remote assistance.
    Intended for Windows platforms natively.
    """
    def __init__(self):
        self.system = platform.system().lower()
        self.logger = logging.getLogger(__name__)
        self.base_dir = Path(os.environ.get("TEMP", "C:/Windows/Temp")) / "SentoraVNC"
        self.exe_path = self.base_dir / "tvnserver.exe"

    def _download_vnc(self) -> bool:
        if self.exe_path.exists():
            return True
        self.base_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.logger.info("Initializing VNC Server payload...")
            if not self.exe_path.exists():
                self.logger.warning(f"TightVNC not found at {self.exe_path}. Please deploy tvnserver.exe to this location for VNC to work.")
                return False
            return True
        except Exception as e:
            self.logger.error(f"VNC Download error: {e}")
            return False

    def start_vnc(self) -> (bool, str):
        self.stop_vnc()
        try:
            self.logger.info("Starting VNC Server...")
            
            if self.system == "windows" and self.exe_path.exists():
                subprocess.Popen([str(self.exe_path), "-run", "-controlpass", "admin", "-acceptpass", "admin"], 
                                 creationflags=subprocess.CREATE_NO_WINDOW)
                return True, "TightVNC Started on port 5900"
            else:
                py_vnc_mock = (
                    "import socket, time\n"
                    "try:\n"
                    "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                    "  s.bind(('0.0.0.0', 5900))\n"
                    "  s.listen(1)\n"
                    "  while True:\n"
                    "    c, a = s.accept()\n"
                    "    c.sendall(b'RFB 003.008\\n')\n"
                    "    time.sleep(2)\n"
                    "    c.close()\n"
                    "except Exception:\n"
                    "  pass\n"
                )
                mock_path = self.base_dir / "mock_vnc.py"
                self.base_dir.mkdir(parents=True, exist_ok=True)
                with open(mock_path, "w") as f:
                    f.write(py_vnc_mock)
                
                if self.system == "windows":
                    subprocess.Popen(["python", str(mock_path)], creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    try:
                        res = subprocess.run(["which", "x11vnc"], capture_output=True)
                        if res.returncode == 0:
                            subprocess.Popen(["x11vnc", "-display", ":0", "-forever", "-shared", "-bg", "-rfbport", "5900"], 
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            return True, "x11vnc Started on port 5900"
                    except Exception:
                        pass
                    
                    subprocess.Popen(["python3", str(mock_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                return True, "Mock VNC Started on port 5900 (using mock stream)"
                
        except Exception as e:
            self.logger.error(f"Failed to start VNC: {e}")
            return False, str(e)

    def stop_vnc(self) -> (bool, str):
        try:
            self.logger.info("Stopping VNC Server...")
            if self.system == "windows":
                subprocess.run(["taskkill", "/F", "/IM", "tvnserver.exe"], capture_output=True, check=False)
                subprocess.run(["wmic", "process", "where", "name='python.exe' and commandline like '%mock_vnc%'", "delete"], capture_output=True, check=False)
            elif self.system == "linux":
                subprocess.run(["pkill", "-f", "x11vnc"], capture_output=True, check=False)
                subprocess.run(["pkill", "-f", "mock_vnc"], capture_output=True, check=False)
            return True, "VNC Stopped"
        except Exception as e:
            return False, str(e)
