import subprocess
import platform
import sys
import os
import hashlib

import modules.enc_db as enc_db

enc_db.add_encrypted_fields("packages", ["package", "version"])

insert_record_enc = enc_db.insert_record_enc
delete_all_enc    = enc_db.delete_all_enc


TABLE = "packages"

def detect_platform():
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        return detect_linux_package_manager()
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

def detect_linux_package_manager():
    try:
        with open('/etc/os-release') as f:
            data = f.read().lower()
        if 'ubuntu' in data or 'debian' in data:
            return 'dpkg'
        elif 'centos' in data or 'fedora' in data or 'rhel' in data:
            return 'rpm'
        elif 'arch' in data or 'manjaro' in data:
            return 'pacman'
    except FileNotFoundError:
        pass

    for pm in ('dpkg-query', 'rpm', 'pacman'):
        if subprocess.call(['which', pm], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            if 'dpkg' in pm:
                return 'dpkg'
            elif 'rpm' in pm:
                return 'rpm'
            elif 'pacman' in pm:
                return 'pacman'

    raise RuntimeError('No supported package manager found on Linux')

def list_linux_packages(pm):
    if pm == 'dpkg':
        cmd = ['dpkg-query', '-W', '-f=${Package},${Version}\n']
    elif pm == 'rpm':
        cmd = ['rpm', '-qa', '--queryformat', '%{NAME},%{VERSION}-%{RELEASE}\n']
    elif pm == 'pacman':
        cmd = ['pacman', '-Q']
    else:
        raise RuntimeError('Unknown Linux package manager')

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
    if result.returncode != 0:
        print(f"Error getting Linux packages: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    if pm == 'pacman':
        return [line.split(' ', 1) for line in result.stdout.splitlines() if line.strip()]
    else:
        return [line.split(',', 1) for line in result.stdout.splitlines() if line.strip()]

def list_windows_packages():
    ps_script = (
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
        "Select-Object DisplayName, DisplayVersion | ConvertTo-Json"
    )
    cmd = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
        if result.returncode == 0 and result.stdout and result.stdout.strip():
            import json
            raw_data = json.loads(result.stdout)
            if isinstance(raw_data, dict):
                raw_data = [raw_data]
            
            packages = []
            for item in raw_data:
                name = item.get('DisplayName')
                version = item.get('DisplayVersion') or "0.0.0"
                if name:
                    packages.append([name, version])
            return packages
    except Exception as e:
        print(f"PowerShell package fetch failed: {e}. Falling back to basic check.")

    cmd = ['wmic', 'product', 'get', 'name,version']
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
...
def make_dup_fp(package: str, version: str) -> str:
    raw = f"{package}|{version}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def save_packages(packages):
    delete_all_enc(TABLE)
    seen = set()
    unique_packages = []
    for p, v in packages:
        fp = f"{p}|{v}"
        if fp not in seen:
            seen.add(fp)
            unique_packages.append((p, v))
            
    for package, version in unique_packages:
        payload = {
            'package': package,
            'version': version,
            'dup_fp': make_dup_fp(package, version),
        }
        insert_record_enc(TABLE, payload)

def main():
    try:
        system = detect_platform()
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    if system == 'windows':
        packages = list_windows_packages()
    else:
        pm = system
        packages = list_linux_packages(pm)

    save_packages(packages)


