"""Posture findings: how this host is configured, not what happened on it.

`security_audit` has existed in both schemas, in the server's ingest lists and
in its encrypted-field map since the beginning, and nothing ever wrote a row to
it. Three modules were documented as producing it and none did. So the table
shipped empty every cycle and the console showed it permanently as NOT
COLLECTED - which reads as a sensor that broke rather than one that was never
built. This is the collector.

What belongs here, and what does not
------------------------------------
Everything else the agent produces is an *event*: a process started, a file
changed, a log line arrived. These are **states**. "The Guest account is
enabled" is not something that happened at 14:03; it is true until somebody
changes it.

That difference decides the whole design:

**Deduplication is on the finding, not the row.** The same finding is re-found
every cycle, so without it one misconfiguration becomes one alert per cycle
for ever - `send_alert` learned this the hard way, where a normal loopback SMB
connection produced the identical alert 288 times a day. The fingerprint here
covers `category` and `finding` and deliberately *not* `details`, because
details carry values that drift ("2 members: Administrator, pc") and a
fingerprint over them re-inserts the same finding whenever one changes.

**An absent setting is a secure default, not an unknown.** Most of the Windows
registry values below do not exist on a correctly configured machine:
`DisableRealtimeMonitoring`, `AutoAdminLogon`, `UseLogonCredential`, `SMB1`.
A check that reports "could not determine" for each of those produces four
findings on a hardened host, which is how a posture scanner gets switched off.
Absent means the default, and the default is the safe side in every case here.

**Severity is what an attacker could do with it, not how alarming it sounds.**
An unquoted service path is the textbook privilege-escalation primitive and is
MEDIUM here, not HIGH, because exploiting it needs write access to a directory
that is admin-only on a default install. Calling it CRITICAL is how a finding
gets muted, and a muted finding is worse than an absent one - the console still
counts it as coverage.

Read-only throughout. This module reports; `soar` acts.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from dataclasses import dataclass
from typing import Iterable

TABLE = "security_audit"

#: Category values match the comment the schema has carried all along:
#: "AD", "User", "Service". `Host` covers the machine-wide settings that are
#: none of those three.
CAT_USER = "User"
CAT_SERVICE = "Service"
CAT_HOST = "Host"
CAT_AD = "AD"


@dataclass(frozen=True)
class Finding:
    category: str
    finding: str
    severity: str
    details: str = ""

    def fingerprint(self) -> str:
        """Identity of the finding, excluding its details.

        See the module docstring: `details` drifts, and a fingerprint that
        includes it turns one misconfiguration into a new row every time the
        count of local administrators changes.
        """
        return hashlib.sha256(
            f"{self.category}|{self.finding}".encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Pure evaluation. Every decision lives here, separately from the code that
# touches the host, so each one can be tested against a fixture rather than
# against whatever the developer's machine happens to be configured like.
# ---------------------------------------------------------------------------

def evaluate_registry(values: dict) -> list[Finding]:
    """Windows machine settings, from already-read registry values.

    `values` maps a short name to the value read, or `None` when the value is
    absent. Absent is the default, and the default is secure for all of these -
    see the module docstring.
    """
    out: list[Finding] = []

    # EnableLUA=0 turns UAC off entirely. Absent means on.
    if values.get("EnableLUA") == 0:
        out.append(Finding(
            CAT_HOST, "User Account Control is disabled", "HIGH",
            "EnableLUA=0. Every elevation prompt is skipped, so any code that "
            "runs as an administrator account runs elevated without asking."))

    # fDenyTSConnections=0 means RDP is accepting connections. Not a
    # misconfiguration by itself - plenty of hosts are meant to - so this is
    # LOW and phrased as a fact rather than a fault.
    if values.get("fDenyTSConnections") == 0:
        out.append(Finding(
            CAT_HOST, "Remote Desktop is enabled", "LOW",
            "fDenyTSConnections=0. Worth knowing on a workstation; expected on "
            "a jump host. Check that Network Level Authentication is on."))

    if values.get("DisableRealtimeMonitoring") == 1:
        out.append(Finding(
            CAT_HOST, "Defender real-time protection is disabled", "CRITICAL",
            "DisableRealtimeMonitoring=1. This is set by policy or by "
            "somebody with administrator rights; it is also the first thing "
            "an intruder does, and it is how the next stage goes unscanned."))

    if values.get("SMB1") == 1:
        out.append(Finding(
            CAT_HOST, "SMBv1 is enabled", "HIGH",
            "SMB1=1 on LanmanServer. The protocol has no message signing "
            "worth the name and is the transport EternalBlue used."))

    if values.get("AutoAdminLogon") in (1, "1"):
        out.append(Finding(
            CAT_USER, "Automatic logon is configured", "HIGH",
            "AutoAdminLogon=1. The account's password is stored in the "
            "registry under Winlogon\\DefaultPassword, readable by anyone who "
            "can read HKLM - which includes every local administrator and "
            "anything running as one."))

    if values.get("UseLogonCredential") == 1:
        out.append(Finding(
            CAT_USER, "WDigest is caching plaintext credentials", "CRITICAL",
            "UseLogonCredential=1. This puts cleartext passwords back in LSASS "
            "memory, which is exactly what a credential dump reads. The "
            "default on this Windows version is off; something set it."))

    if values.get("LimitBlankPasswordUse") == 0:
        out.append(Finding(
            CAT_USER, "Blank passwords may be used remotely", "HIGH",
            "LimitBlankPasswordUse=0. An account with no password can "
            "authenticate over the network rather than only at the console."))

    return out


def evaluate_firewall(profiles: dict) -> list[Finding]:
    """One finding per disabled profile, named.

    Not one finding saying "the firewall is off": the profiles are independent
    and which one is off changes what it means. Public off on a laptop is a
    different problem from Domain off on a server.
    """
    off = sorted(name for name, enabled in (profiles or {}).items()
                 if enabled is False)
    if not off:
        return []
    return [Finding(
        CAT_HOST, f"Host firewall is disabled on the {name} profile",
        "HIGH" if name in ("Public", "Domain") else "MEDIUM",
        f"The {name} profile is not filtering. Inbound connections reach "
        f"whatever is listening, and this platform's own port scan is the only "
        f"thing that will tell you what that is.")
        for name in off]


#: A path is only hijackable if somebody who is not already an administrator
#: can write to one of the directories Windows would try. On a default install
#: `C:\` and `C:\Program Files` are not writable, so the finding is about a
#: latent weakness rather than an open door - hence MEDIUM, and hence saying so.
_UNQUOTED_SAFE_PREFIXES = ("c:\\windows\\", "c:\\program files\\",
                           "c:\\program files (x86)\\")


def evaluate_service_paths(services: Iterable[dict]) -> list[Finding]:
    """Unquoted service binary paths containing a space.

    Windows resolves `C:\\Program Files\\App\\svc.exe` by trying
    `C:\\Program.exe` first, then `C:\\Program Files\\App\\svc.exe`. A writable
    directory anywhere along that sequence is a way to have your binary started
    as whatever the service runs as.
    """
    out: list[Finding] = []
    for svc in services or []:
        path = (svc.get("path") or "").strip()
        name = svc.get("name") or "?"
        if not path or path.startswith('"'):
            continue
        # The first token has to contain a space before the executable for the
        # ambiguity to exist at all.
        head = path.split(".exe")[0]
        if " " not in head or "\\" not in head:
            continue
        low = path.lower()
        privileged = not low.startswith(_UNQUOTED_SAFE_PREFIXES)
        out.append(Finding(
            CAT_SERVICE, f"Service binary path is unquoted: {name}",
            "HIGH" if privileged else "MEDIUM",
            f"ImagePath={path}. Windows tries each space-separated prefix in "
            f"turn, so a writable directory along that sequence lets somebody "
            f"substitute the binary."
            + ("" if privileged else
               " The path is under a directory only administrators can write "
               "to on a default install, which is what keeps this latent.")))
    return out


def evaluate_service_accounts(services: Iterable[dict]) -> list[Finding]:
    """Services running as SYSTEM from a directory anyone can write.

    The combination is the finding. A binary in `%TEMP%` is unusual; a binary
    in `%TEMP%` started as SYSTEM at every boot is persistence.
    """
    # `\programdata\` was in this list and is deliberately gone. That
    # directory's root is writable by users, which is what makes it the
    # textbook example - but the vendor subdirectories under it are not, and
    # Defender's own services live at
    # `C:\ProgramData\Microsoft\Windows Defender\Platform\...`. The first run
    # of this check reported WinDefend, WdNisSvc and MDCoreSvc as CRITICAL
    # persistence, which is the worst false positive available: it accuses the
    # anti-malware service of being the malware, and one of those is enough
    # for an operator to stop reading the category.
    #
    # Deciding it properly means asking whether a non-administrator can write
    # to that specific directory - an ACL query per service, too expensive for
    # every cycle. So the list is narrowed to directories that are writable by
    # design and have no legitimate business holding a service binary. A
    # binary under a vendor directory with wrong ACLs is missed; that is a
    # stated limit rather than a silent one.
    writable = ("\\temp\\", "\\users\\public\\",
                "\\appdata\\", "\\windows\\tasks\\")
    out: list[Finding] = []
    for svc in services or []:
        path = (svc.get("path") or "").strip().strip('"').lower()
        account = (svc.get("account") or "").lower()
        name = svc.get("name") or "?"
        if not path or not any(w in path for w in writable):
            continue
        privileged = any(a in account for a in
                         ("localsystem", "system", "administrator"))
        out.append(Finding(
            CAT_SERVICE, f"Service binary is in a writable directory: {name}",
            "CRITICAL" if privileged else "HIGH",
            f"ImagePath={svc.get('path')} runs as {svc.get('account') or 'an unknown account'}. "
            f"Services start themselves and survive a reboot, which is why "
            f"persistence keeps coming back to them."))
    return out


def evaluate_local_accounts(users: Iterable[dict], admin_members: Iterable[str]) -> list[Finding]:
    """Enabled accounts, their password policy, and who is an administrator."""
    out: list[Finding] = []
    users = list(users or [])

    for user in users:
        name = user.get("name") or "?"
        if not user.get("enabled"):
            continue
        if name.lower() == "guest":
            out.append(Finding(
                CAT_USER, "The Guest account is enabled", "HIGH",
                "Guest authenticates with no password and is a member of "
                "Everyone. It is disabled by default and there is rarely a "
                "reason to change that."))
        if user.get("password_expires") is False:
            out.append(Finding(
                CAT_USER, f"Password never expires: {name}", "LOW",
                f"{name} is enabled and its password has no expiry. Ordinary "
                f"for a service account, worth knowing for a person's."))
        if user.get("password_required") is False:
            # Worded carefully, and downgraded from HIGH after checking what
            # the flag means. `PasswordRequired=False` says the account is
            # *permitted* to have a blank password, not that it has one - this
            # host's `pc` account has the flag clear and a password set since
            # July. The first draft claimed "can authenticate with an empty
            # password", which is a different and much louder statement, and a
            # finding that overstates is one an operator learns to dismiss
            # along with the next one.
            out.append(Finding(
                CAT_USER, f"Password is not required: {name}", "MEDIUM",
                f"{name} is permitted to have a blank password. It may well "
                f"have one set now; the point is that nothing stops it being "
                f"cleared, and `LimitBlankPasswordUse=0` would then make it "
                f"usable over the network rather than only at the console."))

    members = sorted(set(admin_members or []))
    if len(members) > 2:
        # Not a fault, a fact worth surfacing: every extra administrator is
        # another account whose compromise is a full compromise.
        out.append(Finding(
            CAT_USER, "More than two local administrators", "LOW",
            f"{len(members)} members: {', '.join(members)}. Each one is a "
            f"full compromise of this host if its credentials are taken."))
    return out


def evaluate_sshd_config(text: str) -> list[Finding]:
    """Effective sshd settings, last directive winning.

    sshd takes the *first* occurrence of most keywords, which is the opposite
    of what a naive reader assumes - but a commented-out default followed by an
    explicit setting is the common shape, so the parse has to ignore comments
    and then take the first live value.
    """
    out: list[Finding] = []
    seen: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key not in seen:                     # first occurrence wins, as sshd does
            seen[key] = parts[1].strip().lower()

    if seen.get("permitrootlogin") in ("yes", "without-password", "prohibit-password"):
        risky = seen["permitrootlogin"] == "yes"
        out.append(Finding(
            CAT_USER, "SSH permits root login",
            "HIGH" if risky else "LOW",
            f"PermitRootLogin {seen['permitrootlogin']}. "
            + ("Root can authenticate with a password, so every failed guess "
               "is against the account that needs no privilege escalation."
               if risky else
               "Key-only, which is defensible; it still means the account "
               "everybody can name is directly reachable.")))

    if seen.get("passwordauthentication") == "yes":
        out.append(Finding(
            CAT_USER, "SSH accepts password authentication", "MEDIUM",
            "PasswordAuthentication yes. Every password on this host is "
            "reachable from anywhere the port is."))

    if seen.get("permitemptypasswords") == "yes":
        out.append(Finding(
            CAT_USER, "SSH accepts empty passwords", "CRITICAL",
            "PermitEmptyPasswords yes. An account with no password is a login "
            "with no credential."))
    return out


_NOPASSWD = re.compile(r"^\s*([^#\s][^\s]*)\s+.*NOPASSWD\s*:", re.I)


def evaluate_sudoers(text: str) -> list[Finding]:
    """NOPASSWD grants, which turn a shell into a root shell."""
    grants = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0]
        m = _NOPASSWD.match(line)
        if m:
            grants.append(m.group(1))
    if not grants:
        return []
    return [Finding(
        CAT_USER, "sudo is granted without a password", "HIGH",
        f"NOPASSWD for: {', '.join(sorted(set(grants)))}. Anything that can "
        f"run as one of these becomes root without needing the password - "
        f"which includes a web shell, a hijacked session, or a stolen key.")]


def evaluate_passwd(text: str) -> list[Finding]:
    """UID 0 accounts other than root."""
    extra = []
    for raw in (text or "").splitlines():
        parts = raw.strip().split(":")
        if len(parts) < 3:
            continue
        name, _, uid = parts[0], parts[1], parts[2]
        if uid == "0" and name != "root":
            extra.append(name)
    if not extra:
        return []
    return [Finding(
        CAT_USER, "An account other than root has UID 0", "CRITICAL",
        f"{', '.join(extra)} share root's user id, so they are root - with a "
        f"different name, which is the point of doing it.")]


def evaluate_file_modes(modes: dict) -> list[Finding]:
    """Permissions on files whose readability is the whole control."""
    out: list[Finding] = []
    for path, mode in (modes or {}).items():
        if mode is None:
            continue
        world = stat.S_IMODE(mode) & 0o007
        if path.endswith("shadow") and world:
            out.append(Finding(
                CAT_HOST, f"{path} is world-readable", "CRITICAL",
                f"mode {oct(stat.S_IMODE(mode))}. Every password hash on this "
                f"host is readable by every account on it."))
        elif world & 0o002:
            out.append(Finding(
                CAT_HOST, f"{path} is world-writable", "HIGH",
                f"mode {oct(stat.S_IMODE(mode))}."))
    return out


# ---------------------------------------------------------------------------
# Host access. Thin on purpose: gather, hand to an evaluator above.
# ---------------------------------------------------------------------------

_PS_QUERY = r"""
$ErrorActionPreference = 'SilentlyContinue'
$users = Get-LocalUser | ForEach-Object {
  [pscustomobject]@{
    name = $_.Name; enabled = [bool]$_.Enabled
    password_expires = ($null -ne $_.PasswordExpires)
    password_required = [bool]$_.PasswordRequired
  }
}
# By SID, not by name. This group is called "Administrators" in English and
# "Yoneticiler" on a Turkish install, among others - matching the name is a
# check that silently finds nothing on a localised Windows.
$admins = Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name }
$fw = @{}
Get-NetFirewallProfile | ForEach-Object { $fw[$_.Name] = [bool]$_.Enabled }
[pscustomobject]@{ users = $users; admins = $admins; firewall = $fw } |
  ConvertTo-Json -Depth 4 -Compress
"""


def _windows_facts() -> dict:
    """One PowerShell call for the things `winreg` and `psutil` cannot see."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_QUERY],
            capture_output=True, timeout=90,
        )
        # Decoded here rather than with `text=True`. That decodes using the
        # console code page - cp1254 on this Turkish install - and an account
        # or service name outside it raises UnicodeDecodeError inside
        # subprocess's own reader thread, where the caller cannot catch it: the
        # traceback prints and the call returns empty output with no exception.
        # A localised Windows is the normal case, not the edge one.
        raw = (proc.stdout or b"").decode("utf-8", errors="replace")
        return json.loads(raw or "{}") or {}
    except Exception as exc:
        print(f"[security_audit] local account query failed: {exc}", flush=True)
        return {}


_REG_READS = [
    # (short name, hive-relative key, value name)
    ("EnableLUA", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
    ("LimitBlankPasswordUse", r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse"),
    ("fDenyTSConnections", r"System\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"),
    ("SMB1", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
    ("AutoAdminLogon", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon"),
    ("UseLogonCredential", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
    ("DisableRealtimeMonitoring", r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
]


def _windows_registry() -> dict:
    """Read each value, or None when it is absent.

    None and 0 are different answers and the evaluator relies on it: absent
    means the Windows default, which is the secure side for all of these.
    """
    import winreg

    out: dict = {}
    for short, key, name in _REG_READS:
        out[short] = None
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
                value, _kind = winreg.QueryValueEx(handle, name)
                out[short] = int(value) if str(value).isdigit() else value
        except FileNotFoundError:
            pass                                  # absent: the default
        except OSError:
            pass
    return out


def _windows_services() -> list[dict]:
    try:
        import psutil
    except ImportError:
        return []
    out = []
    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
            out.append({"name": info.get("name"),
                        "path": info.get("binpath"),
                        "account": info.get("username")})
        except Exception:
            continue
    return out


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _linux_sudoers() -> str:
    text = _read("/etc/sudoers")
    drop_in = "/etc/sudoers.d"
    if os.path.isdir(drop_in):
        for name in sorted(os.listdir(drop_in)):
            text += "\n" + _read(os.path.join(drop_in, name))
    return text


def _modes(paths: Iterable[str]) -> dict:
    out = {}
    for path in paths:
        try:
            out[path] = os.stat(path).st_mode
        except OSError:
            out[path] = None
    return out


def collect() -> list[Finding]:
    """Every finding for this host, whichever platform it is."""
    findings: list[Finding] = []

    if platform.system().lower() == "windows":
        findings += evaluate_registry(_windows_registry())
        services = _windows_services()
        findings += evaluate_service_paths(services)
        findings += evaluate_service_accounts(services)
        facts = _windows_facts()
        findings += evaluate_firewall(facts.get("firewall") or {})
        findings += evaluate_local_accounts(facts.get("users") or [],
                                            facts.get("admins") or [])
    else:
        findings += evaluate_sshd_config(_read("/etc/ssh/sshd_config"))
        findings += evaluate_sudoers(_linux_sudoers())
        findings += evaluate_passwd(_read("/etc/passwd"))
        findings += evaluate_file_modes(
            _modes(["/etc/shadow", "/etc/passwd", "/etc/sudoers"]))

    return findings


def main() -> None:
    """Write what is new, and say how many were already known.

    Deduplicated against what is already stored rather than inserted blindly:
    these are states, so every row would otherwise be rewritten on every
    cycle. `dup_fp` is set by the module, not by `insert_record_enc`, because
    the identity of a finding excludes its details - see `Finding.fingerprint`.
    """
    from modules.enc_db import insert_record_enc
    from modules.db import fetch_where

    findings = collect()
    if not findings:
        print("[security_audit] no findings", flush=True)
        return

    try:
        rows = fetch_where(TABLE, "dup_fp IS NOT NULL", ())
        known = {r["dup_fp"] for r in rows or [] if r.get("dup_fp")}
    except Exception as exc:
        # A first run before the table exists, or a schema that has not caught
        # up. Writing the findings matters more than deduplicating them.
        print(f"[security_audit] could not read existing findings ({exc}); "
              f"writing without deduplication", flush=True)
        known = set()

    written = 0
    for finding in findings:
        fp = finding.fingerprint()
        if fp in known:
            continue
        try:
            insert_record_enc(TABLE, {
                "category": finding.category,
                "finding": finding.finding,
                "severity": finding.severity,
                "details": finding.details,
                "dup_fp": fp,
                "sent": False,
            })
            known.add(fp)
            written += 1
        except Exception as exc:
            print(f"[security_audit] {finding.finding!r} not stored: "
                  f"{type(exc).__name__}: {exc}", flush=True)

    print(f"[security_audit] {len(findings)} finding(s), {written} new", flush=True)


if __name__ == "__main__":
    for f in collect():
        print(f"{f.severity:<8} [{f.category}] {f.finding}")
        if f.details:
            print(f"         {f.details}")
