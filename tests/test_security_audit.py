"""The posture collector, and the false positives it had to stop making.

`security_audit` existed in both schemas, in the server's ingest lists and in
its encrypted-field map from the beginning, and nothing ever wrote a row to it.
Three modules were documented as producing it and none did, so it shipped empty
every cycle and read as a broken sensor. This is the collector's test.

Every decision in the module is a pure function taking already-gathered data,
which is what makes these tests worth anything: the alternative is asserting
against whatever the developer's own machine is configured like, which passes
everywhere and proves nothing.

Two of these tests exist because the first run of the collector on a real host
produced findings that were wrong, and wrong in the way that gets a whole
category ignored.
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "Sentora"))

from modules import security_audit as sa        # noqa: E402


# --------------------------------------------------------------------------
# An absent setting is the default, and the default is the safe side
# --------------------------------------------------------------------------

def test_a_hardened_host_produces_nothing():
    """The test that matters most, and the one a posture scanner usually fails.

    `DisableRealtimeMonitoring`, `AutoAdminLogon`, `UseLogonCredential` and
    `SMB1` do not exist in the registry on a correctly configured machine.
    Treating absent as "could not determine" gives four findings on a host
    with nothing wrong with it — and four wrong findings is how the category
    stops being read.
    """
    assert sa.evaluate_registry({
        "EnableLUA": 1,
        "fDenyTSConnections": 1,
        "DisableRealtimeMonitoring": None,
        "SMB1": None,
        "AutoAdminLogon": None,
        "UseLogonCredential": None,
        "LimitBlankPasswordUse": 1,
    }) == []


def test_an_empty_registry_read_produces_nothing():
    """Every value absent is the shape of a fresh Windows install."""
    assert sa.evaluate_registry({}) == []


@pytest.mark.parametrize("values,expected", [
    ({"EnableLUA": 0}, "User Account Control is disabled"),
    ({"DisableRealtimeMonitoring": 1}, "Defender real-time protection is disabled"),
    ({"SMB1": 1}, "SMBv1 is enabled"),
    ({"AutoAdminLogon": 1}, "Automatic logon is configured"),
    ({"UseLogonCredential": 1}, "WDigest is caching plaintext credentials"),
    ({"LimitBlankPasswordUse": 0}, "Blank passwords may be used remotely"),
    ({"fDenyTSConnections": 0}, "Remote Desktop is enabled"),
])
def test_each_setting_is_reported_when_it_is_actually_set(values, expected):
    findings = sa.evaluate_registry(values)
    assert [f.finding for f in findings] == [expected]


def test_autologon_is_caught_whether_it_is_a_string_or_a_number():
    """Winlogon writes `AutoAdminLogon` as REG_SZ on some versions and DWORD
    on others, so the value arrives as `"1"` or `1`."""
    assert sa.evaluate_registry({"AutoAdminLogon": "1"})
    assert sa.evaluate_registry({"AutoAdminLogon": 1})


# --------------------------------------------------------------------------
# The false positive that accused the anti-malware service
# --------------------------------------------------------------------------

def test_defenders_own_services_are_not_reported_as_persistence():
    """The first run of this check reported WinDefend, WdNisSvc and MDCoreSvc
    as CRITICAL persistence, because `\\programdata\\` was in the list of
    writable directories.

    That root is writable by users, which is what makes it the textbook
    example - but the vendor subdirectories under it are not, and Defender
    lives at `C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\...`.
    It is the worst false positive available: it accuses the anti-malware
    service of being the malware, and one of those is enough for an operator
    to stop reading the category.
    """
    services = [
        {"name": "WinDefend", "account": "LocalSystem",
         "path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25080.5-0\MsMpEng.exe"},
        {"name": "MDCoreSvc", "account": "LocalSystem",
         "path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25080.5-0\MpDefenderCoreService.exe"},
    ]
    assert sa.evaluate_service_accounts(services) == []


def test_a_service_binary_in_temp_is_still_reported():
    """The narrowing must not empty the check. This is the shape it is for."""
    findings = sa.evaluate_service_accounts([
        {"name": "WinHelpSvc", "account": "LocalSystem",
         "path": r"C:\Windows\Temp\svc.exe"},
    ])
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "WinHelpSvc" in findings[0].finding


def test_a_user_profile_service_is_reported_and_the_account_sets_severity():
    """SYSTEM from a writable path is persistence; a user account from one is
    odd but not the same thing."""
    as_system = sa.evaluate_service_accounts([
        {"name": "a", "account": "LocalSystem", "path": r"C:\Users\jdoe\AppData\Local\x.exe"}])
    as_user = sa.evaluate_service_accounts([
        {"name": "a", "account": "CORP\\jdoe", "path": r"C:\Users\jdoe\AppData\Local\x.exe"}])
    assert as_system[0].severity == "CRITICAL"
    assert as_user[0].severity == "HIGH"


# --------------------------------------------------------------------------
# Unquoted service paths, and why they are not all the same
# --------------------------------------------------------------------------

def test_an_unquoted_path_under_program_files_is_medium_not_high():
    """The textbook privilege escalation, and exploiting it needs write access
    to a directory that is admin-only on a default install. Calling it
    CRITICAL is how a finding gets muted, and a muted finding is worse than an
    absent one because the console still counts it as coverage."""
    findings = sa.evaluate_service_paths([
        {"name": "vgc", "path": r"C:\Program Files\Riot Vanguard\vgc.exe"}])
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "administrators" in findings[0].details.lower()


def test_an_unquoted_path_outside_the_protected_roots_is_high():
    findings = sa.evaluate_service_paths([
        {"name": "x", "path": r"C:\Tools\My App\svc.exe"}])
    assert findings[0].severity == "HIGH"


def test_a_quoted_path_is_not_a_finding():
    assert sa.evaluate_service_paths([
        {"name": "ok", "path": r'"C:\Program Files\App\svc.exe"'}]) == []


def test_a_path_with_no_space_is_not_a_finding():
    assert sa.evaluate_service_paths([
        {"name": "ok", "path": r"C:\Windows\System32\svchost.exe -k netsvcs"}]) == []


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------

def test_a_disabled_guest_account_is_not_a_finding():
    assert sa.evaluate_local_accounts(
        [{"name": "Guest", "enabled": False}], ["Administrator"]) == []


def test_an_enabled_guest_account_is():
    findings = sa.evaluate_local_accounts(
        [{"name": "Guest", "enabled": True}], [])
    assert any("Guest account is enabled" in f.finding for f in findings)


def test_password_not_required_is_not_claimed_to_be_a_blank_password():
    """The first draft said the account "can authenticate with an empty
    password". `PasswordRequired=False` means it is *permitted* to have one -
    this host's account has the flag clear and a password set since July. A
    finding that overstates is one an operator learns to dismiss, along with
    the next one.
    """
    findings = sa.evaluate_local_accounts(
        [{"name": "pc", "enabled": True, "password_required": False}], [])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert "permitted" in finding.details
    assert "can authenticate with an empty password" not in finding.details


def test_two_administrators_are_not_reported_and_three_are():
    assert sa.evaluate_local_accounts([], ["Administrator", "pc"]) == []
    findings = sa.evaluate_local_accounts([], ["Administrator", "pc", "svc"])
    assert any("More than two local administrators" in f.finding for f in findings)


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------

def test_a_commented_sshd_directive_is_not_a_setting():
    """`#PermitRootLogin yes` is the shipped default line in every
    sshd_config, commented out. Reading it as a setting reports a finding on
    a file nobody has touched."""
    assert sa.evaluate_sshd_config(
        "#PermitRootLogin yes\n#PasswordAuthentication yes\n") == []


def test_the_first_live_sshd_directive_wins():
    """sshd takes the first occurrence, which is the opposite of what a reader
    assumes - so a parse that takes the last one reports the wrong answer on
    exactly the file where it matters."""
    findings = sa.evaluate_sshd_config(
        "PermitRootLogin no\nPermitRootLogin yes\n")
    assert findings == []


def test_root_login_with_a_password_is_worse_than_key_only():
    with_password = sa.evaluate_sshd_config("PermitRootLogin yes\n")
    key_only = sa.evaluate_sshd_config("PermitRootLogin prohibit-password\n")
    assert with_password[0].severity == "HIGH"
    assert key_only[0].severity == "LOW"


def test_empty_ssh_passwords_are_critical():
    findings = sa.evaluate_sshd_config("PermitEmptyPasswords yes\n")
    assert findings[0].severity == "CRITICAL"


def test_nopasswd_sudo_is_found_and_a_commented_one_is_not():
    assert sa.evaluate_sudoers("# deploy ALL=(ALL) NOPASSWD: ALL\n") == []
    findings = sa.evaluate_sudoers("deploy ALL=(ALL) NOPASSWD: ALL\n")
    assert len(findings) == 1
    assert "deploy" in findings[0].details


def test_a_second_uid_zero_account_is_critical():
    passwd = ("root:x:0:0:root:/root:/bin/bash\n"
              "backdoor:x:0:0::/tmp:/bin/bash\n"
              "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
    findings = sa.evaluate_passwd(passwd)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "backdoor" in findings[0].details


def test_root_alone_at_uid_zero_is_not_a_finding():
    assert sa.evaluate_passwd("root:x:0:0:root:/root:/bin/bash\n") == []


def test_a_world_readable_shadow_file_is_critical():
    findings = sa.evaluate_file_modes({"/etc/shadow": 0o100644})
    assert findings[0].severity == "CRITICAL"


def test_a_correctly_moded_shadow_file_is_not():
    assert sa.evaluate_file_modes({"/etc/shadow": 0o100640}) == []


# --------------------------------------------------------------------------
# Deduplication: these are states, not events
# --------------------------------------------------------------------------

def test_the_fingerprint_ignores_the_details():
    """The same misconfiguration must be one row, for ever.

    `details` drifts - "2 members: Administrator, pc" becomes "3 members: …" -
    and a fingerprint that covers it re-inserts the same finding whenever the
    count changes. `send_alert` learned the general version of this the hard
    way: a state-reporting detector without deduplication produced the
    identical alert 288 times a day.
    """
    a = sa.Finding("User", "More than two local administrators", "LOW", "2 members")
    b = sa.Finding("User", "More than two local administrators", "LOW", "5 members")
    assert a.fingerprint() == b.fingerprint()


def test_different_findings_do_not_collide():
    a = sa.Finding("User", "The Guest account is enabled", "HIGH")
    b = sa.Finding("Host", "SMBv1 is enabled", "HIGH")
    assert a.fingerprint() != b.fingerprint()


def test_the_category_is_part_of_the_identity():
    a = sa.Finding("User", "same text", "LOW")
    b = sa.Finding("Host", "same text", "LOW")
    assert a.fingerprint() != b.fingerprint()


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

def test_the_collector_is_scheduled():
    """A module nothing calls is the state this table was already in. The
    table existed for the life of the product with no writer."""
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    assert "security_audit_main" in main
    assert re.search(r"args=\(security_audit_main,\s*\d+", main), \
        "imported but never given to periodic_wrapped"


def test_the_table_is_shipped():
    main = (ROOT / "Sentora" / "main.py").read_text(encoding="utf-8")
    block = re.search(r"^TABLES = \[(.*?)^\]", main, re.S | re.M)
    assert block and "'security_audit'" in block.group(1)


def test_the_findings_are_encrypted_at_rest():
    """`finding` and `details` name the misconfiguration and where it is,
    which is a map for anyone who reads the database."""
    enc = (ROOT / "Sentora" / "modules" / "enc_db.py").read_text(encoding="utf-8")
    assert re.search(r'"security_audit":\s*\["finding",\s*"details"\]', enc)


def test_nothing_here_changes_the_host():
    """This module reports; `soar` acts. A posture checker that fixes things
    is one nobody can run twice."""
    src = (ROOT / "Sentora" / "modules" / "security_audit.py").read_text(encoding="utf-8")
    for forbidden in ("winreg.SetValue", "winreg.DeleteValue", "os.remove",
                      "os.chmod", "shutil.rmtree", "Set-ItemProperty",
                      "Set-LocalUser", "Stop-Service"):
        assert forbidden not in src, f"{forbidden} modifies the host"
