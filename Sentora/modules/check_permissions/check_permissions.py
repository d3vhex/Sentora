import os
import re
import logging
import hashlib
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict
import platform
from stat import S_IMODE
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import getpass

try:
    import yaml  
except Exception:
    yaml = None

from modules.enc_db import insert_record_enc, fetch_where_dec, set_encrypt_fields_map


DEFAULT_TARGET_DIRS_LINUX = ['/etc', '/var/www', '/home']
DEFAULT_TARGET_DIRS_WINDOWS = ['C:\\Users']
DEFAULT_EXCLUDE_DIRS_LINUX = ['/proc', '/sys', '/dev', '/var/lib/docker', '/run']
DEFAULT_EXCLUDE_DIRS_WINDOWS = []

DEFAULT_BACKUP_EXTENSIONS = ['sql', 'sql.gz', 'tar', 'tar.gz', 'zip']
DEFAULT_CONFIG_REGEXES = [r'wp-config\.php', r'\.htaccess', r'.*\.conf$']

TABLE = 'critical_files'

BACKUP_PATTERN = None
CONFIG_PATTERN = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def compile_patterns(backup_extensions: List[str], config_regexes: List[str]):
    global BACKUP_PATTERN, CONFIG_PATTERN
    backup_extensions = sorted(backup_extensions, key=len, reverse=True)
    ext_union = "|".join(re.escape(ext) for ext in backup_extensions)
    backup_regex = rf".*\.({ext_union})$"
    BACKUP_PATTERN = re.compile(backup_regex, re.IGNORECASE)

    if config_regexes:
        config_union = "|".join(f"(?:{rx})" for rx in config_regexes)
    else:
        config_union = r"$a"  
    CONFIG_PATTERN = re.compile(config_union, re.IGNORECASE)

def is_critical(filename: str) -> bool:
    return bool(BACKUP_PATTERN.search(filename) or CONFIG_PATTERN.search(filename))

def normalize(value):
    return value.replace("'", "''") if isinstance(value, str) else value

def make_dup_fp(path: str, owner: str, grp: str, permissions: str) -> str:
    raw = f"{path}|{owner}|{grp}|{permissions}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def is_duplicate(path, owner, grp, permissions) -> bool:
    dup_fp = make_dup_fp(path, owner, grp, permissions)
    where = "dup_fp = %s"
    rows = fetch_where_dec(TABLE, where=where, params=(dup_fp,), limit=1)
    return bool(rows)

def extract_stat_common(path: str):
    try:
        st = os.stat(path, follow_symlinks=False)
        mode = oct(S_IMODE(st.st_mode))
        last_opened = datetime.utcfromtimestamp(st.st_atime).isoformat()
        return st, mode, last_opened
    except (OSError, PermissionError):
        return None, None, None

def check_file_linux(path: str) -> Optional[dict]:
    import pwd
    import grp as grp_module

    st, mode, last_opened = extract_stat_common(path)
    if st is None:
        return None

    uid, gid = st.st_uid, st.st_gid
    if uid == 0:
        return None

    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = str(uid)
    try:
        group_name = grp_module.getgrgid(gid).gr_name
    except KeyError:
        group_name = str(gid)

    return {
        'path': path,
        'owner': user,
        'grp': group_name,
        'permissions': mode,
        'last_opened': last_opened,
    }

def check_file_windows(path: str) -> Optional[dict]:
    st, mode, last_opened = extract_stat_common(path)
    if st is None:
        return None

    user = "Unknown"
    group_name = "N/A"
    win_perms = ""
    
    try:
        import win32security
        import win32api
        import ntsecuritycon as con
        
        try:
            sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, type = win32security.LookupAccountSid(None, owner_sid)
            user = f"{domain}\\{name}"
            
            sd_grp = win32security.GetFileSecurity(path, win32security.GROUP_SECURITY_INFORMATION)
            group_sid = sd_grp.GetSecurityDescriptorGroup()
            gname, gdomain, gtype = win32security.LookupAccountSid(None, group_sid)
            group_name = f"{gdomain}\\{gname}"
        except Exception:
            pass

        try:
            attrs = win32api.GetFileAttributes(path)
            attr_list = []
            if attrs & 1: attr_list.append("ReadOnly")
            if attrs & 2: attr_list.append("Hidden")
            if attrs & 4: attr_list.append("System")
            if attrs & 16: attr_list.append("Directory")
            if attrs & 32: attr_list.append("Archive")
            if attrs & 2048: attr_list.append("Compressed")
            if attrs & 16384: attr_list.append("Encrypted")
            win_perms = "|".join(attr_list)
        except Exception:
            pass
            
    except ImportError:
        try:
            user = getpass.getuser()
        except:
            pass
        if os.path.isdir(path):
            win_perms = "Directory"
        elif not os.access(path, os.W_OK):
            win_perms = "ReadOnly"
        else:
            win_perms = "Normal"

    return {
        'path': path,
        'owner': user,
        'grp': group_name,
        'permissions': win_perms or mode,
        'last_opened': last_opened,
    }

def scan_directory(root: str, exclude_dirs: List[str], pool: ThreadPoolExecutor, futures: list):
    root_is_windows = platform.system() == "Windows"
    norm_excludes = []
    for d in exclude_dirs or []:
        norm = os.path.normpath(d)
        if root_is_windows:
            norm = norm.lower()
        norm_excludes.append(norm)

    for dirpath, dirs, files in os.walk(root, followlinks=False):
        try:
            walk_path = os.path.normpath(dirpath)
            cmp_path = walk_path.lower() if root_is_windows else walk_path

            dirs[:] = [
                d for d in dirs
                if (os.path.normpath(os.path.join(dirpath, d)).lower() if root_is_windows
                    else os.path.normpath(os.path.join(dirpath, d))) not in norm_excludes
            ]
        except Exception:
            continue

        for fn in files:
            if is_critical(fn):
                full_path = os.path.join(dirpath, fn)
                if platform.system() == "Windows":
                    futures.append(pool.submit(check_file_windows, full_path))
                else:
                    futures.append(pool.submit(check_file_linux, full_path))

def load_config(config_path: Optional[str]) -> Dict:

    cfg = {
        "target_dirs": {
            "linux": DEFAULT_TARGET_DIRS_LINUX,
            "windows": DEFAULT_TARGET_DIRS_WINDOWS
        },
        "exclude_dirs": {
            "linux": DEFAULT_EXCLUDE_DIRS_LINUX,
            "windows": DEFAULT_EXCLUDE_DIRS_WINDOWS
        },
        "backup_extensions": DEFAULT_BACKUP_EXTENSIONS,
        "config_regexes": DEFAULT_CONFIG_REGEXES,
    }

    if config_path:
        if not os.path.isfile(config_path):
            raise FileNotFoundError(f"Config not found: {config_path}")
        if yaml and (config_path.endswith((".yml", ".yaml"))):
            with open(config_path, "r", encoding="utf-8") as f:
                y = yaml.safe_load(f) or {}
        else:
            import json
            with open(config_path, "r", encoding="utf-8") as f:
                y = json.load(f)

        td = y.get("target_dirs", {})
        exd = y.get("exclude_dirs", {})
        if isinstance(td, dict):
            cfg["target_dirs"]["linux"] = td.get("linux", cfg["target_dirs"]["linux"])
            cfg["target_dirs"]["windows"] = td.get("windows", cfg["target_dirs"]["windows"])
        if isinstance(exd, dict):
            cfg["exclude_dirs"]["linux"] = exd.get("linux", cfg["exclude_dirs"]["linux"])
            cfg["exclude_dirs"]["windows"] = exd.get("windows", cfg["exclude_dirs"]["windows"])

        be = y.get("backup_extensions", cfg["backup_extensions"])
        cr = y.get("config_regexes", cfg["config_regexes"])
        if isinstance(be, list) and be:
            cfg["backup_extensions"] = be
        if isinstance(cr, list) and cr:
            cfg["config_regexes"] = cr

    return cfg

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_cfg = os.path.normpath(os.path.join(here, "../../conf/file_scan.yaml"))
    config_path = os.getenv("RULES_CONFIG", default_cfg)


    cfg = load_config(config_path)

    if platform.system() == "Windows":
        target_dirs = cfg["target_dirs"]["windows"]
        exclude_dirs = cfg["exclude_dirs"]["windows"]
    else:
        target_dirs = cfg["target_dirs"]["linux"]
        exclude_dirs = cfg["exclude_dirs"]["linux"]

    compile_patterns(cfg["backup_extensions"], cfg["config_regexes"])

    logging.info("Target dirs: %s", target_dirs)
    if exclude_dirs:
        logging.info("Exclude dirs: %s", exclude_dirs)

    with ThreadPoolExecutor(max_workers=1) as pool:
        futures = []
        for directory in target_dirs:
            if not os.path.exists(directory):
                logging.warning("No files, skipping: %s", directory)
                continue
            scan_directory(directory, exclude_dirs, pool, futures)

        results = []
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                logging.warning("Task failed: %s", e)
                res = None
            if res:
                results.append(res)

    set_encrypt_fields_map({
    "critical_files": ["path", "owner", "grp", "permissions", "last_opened"]
    })

    for item in results:
        item['collected_at'] = datetime.utcnow()

        dup_fp = make_dup_fp(item['path'], item['owner'], item['grp'], item['permissions'])

        if not is_duplicate(item['path'], item['owner'], item['grp'], item['permissions']):
            payload = dict(item)
            payload['dup_fp'] = dup_fp
            insert_record_enc(TABLE, payload)
