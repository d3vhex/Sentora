"""Load a directory of Sigma rules, and map events into the fields they name.

Two jobs that belong together because they fail together: a rule that loads
but never matches because the field names differ is indistinguishable, from
the console, from a rule that was never written.

Field mapping
-------------
Sigma rules address named fields - `CommandLine`, `Image`, `TargetObject`.
The Windows event log gives `StringInserts`, a positional array whose meaning
depends on the event ID, so the names have to be supplied. `WINDOWS_FIELDS`
below does that for the event IDs this agent collects.

An event ID with no mapping is not dropped. Its inserts are still exposed
under generic names and the whole assembled message under `Message`, so a
rule matching on `Message|contains` still works. That is weaker than a field
match and it is stated rather than hidden: `unmapped_event_ids()` reports
which IDs are arriving without one.

Sysmon gets its own table. Its event IDs are small numbers - 1, 11, 13 - that
mean something entirely different on the System and Application channels, so
the table is selected by channel. Reading a System event through Sysmon's
layout would put arbitrary text into `Image` and `CommandLine`, inventing
evidence for whichever rule then matched it.

Linux
-----
The two Linux paths are not equally capable, and the difference is a property
of the logs rather than of the rules:

- `journal_event_fields` maps a systemd entry, which genuinely carries the
  process, its command line and the unit. Field-matching rules work here the
  way they do on Windows.
- `text_event_fields` handles a plain log line, which is text. Only `Message`
  and whatever the enricher extracted exist, so a rule matching `CommandLine`
  will not fire - not because the event is uninteresting, but because the
  field is not there to match.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from core.sigma import SigmaError, SigmaRule, parse

# EventID -> the Sigma field name for each StringInserts position.
#
# Taken from the Windows event schemas. Positions are stable per event ID;
# what varies is the Windows version, and where a version added a field the
# extra positions simply go unmapped rather than shifting the earlier ones.
WINDOWS_FIELDS: dict[int, list[str]] = {
    4688: [  # A new process has been created
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType",
        "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName",
        "TargetDomainName", "TargetLogonId", "ParentProcessName",
        "MandatoryLabel",
    ],
    4624: [  # An account was successfully logged on
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "TargetUserSid", "TargetUserName", "TargetDomainName",
        "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName",
        "WorkstationName", "LogonGuid", "TransmittedServices", "LmPackageName",
        "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort",
    ],
    4625: [  # An account failed to log on
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "TargetUserSid", "TargetUserName", "TargetDomainName",
        "Status", "FailureReason", "SubStatus", "LogonType", "LogonProcessName",
        "AuthenticationPackageName", "WorkstationName", "TransmittedServices",
        "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress",
        "IpPort",
    ],
    4648: [  # A logon was attempted using explicit credentials
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "LogonGuid", "TargetUserName", "TargetDomainName",
        "TargetLogonGuid", "TargetServerName", "TargetInfo", "ProcessId",
        "ProcessName", "IpAddress", "IpPort",
    ],
    4672: [  # Special privileges assigned to new logon
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "PrivilegeList",
    ],
    4698: [  # A scheduled task was created
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "TaskName", "TaskContent",
    ],
    4699: [  # A scheduled task was deleted
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "TaskName",
    ],
    4720: [  # A user account was created
        "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid",
        "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
    ],
    7045: [  # A service was installed in the system
        "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",
    ],
    4104: [  # PowerShell script block logging
        "ScriptBlockText", "Path", "MessageNumber", "MessageTotal",
        "ScriptBlockId",
    ],
    4657: [  # A registry value was modified
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId", "ObjectName", "ObjectValueName", "HandleId",
        "OperationType", "OldValueType", "OldValue", "NewValueType", "NewValue",
    ],
    1102: [  # The audit log was cleared
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
        "SubjectLogonId",
    ],
}

# Sigma names the process image `Image`; the Windows 4688 schema calls the
# same thing `NewProcessName`, and `ParentImage` is `ParentProcessName`.
# Aliases rather than renames, so a rule written either way matches.
FIELD_ALIASES = {
    "NewProcessName": "Image",
    "ParentProcessName": "ParentImage",
    "TargetUserName": "User",
    "IpAddress": "SourceIp",
    # A 4104 script block and a 4688 command line are the same question -
    # "what was run" - asked of two different event IDs. Aliasing them means a
    # rule written against CommandLine still fires when the estate has script
    # block logging on and the command never appeared as a process at all.
    "ScriptBlockText": "CommandLine",
    "TaskContent": "TaskCommand",
}


# Sysmon's event IDs are small numbers that mean something entirely different
# on the System and Application channels - EventID 1 there is not a process
# creation. Keeping them in a separate table, selected by channel, is what
# stops a System event being read through Sysmon's field layout and matching a
# rule it has nothing to do with.
SYSMON_FIELDS: dict[int, list[str]] = {
    1: [  # Sysmon process creation
        "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
        "FileVersion", "Description", "Product", "Company", "OriginalFileName",
        "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId",
        "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid",
        "ParentProcessId", "ParentImage", "ParentCommandLine",
    ],
    11: [  # Sysmon file created
        "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
        "TargetFilename", "CreationUtcTime",
    ],
    13: [  # Sysmon registry value set
        "RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId",
        "Image", "TargetObject", "Details",
    ],
}

SYSMON_CHANNEL = "sysmon"


_unmapped: dict[int, int] = {}


def unmapped_event_ids() -> dict[int, int]:
    """Event IDs seen without a field mapping, and how often.

    A rule matching on named fields cannot fire for these - it falls back to
    the assembled message - so this is the size of the gap rather than a
    reassuring silence.
    """
    return dict(sorted(_unmapped.items(), key=lambda kv: -kv[1]))


def windows_event_fields(event_id: int, inserts, message: str = "",
                         channel: str = "", provider: str = "") -> dict:
    """Turn a Windows event into the field names Sigma rules address."""
    out: dict[str, str] = {
        "EventID": str(event_id),
        "Message": message or " | ".join(str(i) for i in (inserts or [])),
        "Channel": channel,
        "Provider_Name": provider,
    }

    table = SYSMON_FIELDS if SYSMON_CHANNEL in (channel or "").lower() else WINDOWS_FIELDS
    names = table.get(int(event_id))
    values = [str(i) for i in (inserts or [])]
    if names is None:
        _unmapped[int(event_id)] = _unmapped.get(int(event_id), 0) + 1
        # Still addressable, just not by name.
        for i, value in enumerate(values):
            out[f"Insert{i}"] = value
        return out

    for name, value in zip(names, values):
        out[name] = value
        alias = FIELD_ALIASES.get(name)
        if alias and alias not in out:
            out[alias] = value
    return out


@dataclass
class LoadResult:
    rules: list[SigmaRule] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    @property
    def techniques(self) -> set[str]:
        return {t for r in self.rules for t in r.techniques}

    def summary(self) -> str:
        line = (f"{len(self.rules)} Sigma rule(s) loaded, "
                f"{len(self.techniques)} ATT&CK technique(s) covered")
        if self.rejected:
            line += f", {len(self.rejected)} rejected"
        return line


def load_dir(path, recursive: bool = True) -> LoadResult:
    """Load every Sigma rule under a directory.

    A rule that cannot be compiled is recorded with its reason rather than
    skipped in silence: `rejected` is what tells an operator that the rule
    they installed is not running. One bad file must not stop the rest from
    loading, which is why the exception is caught per rule and not per
    directory.
    """
    root = pathlib.Path(path)
    result = LoadResult()
    if not root.exists():
        return result

    pattern = "**/*.yml" if recursive else "*.yml"
    files = sorted(list(root.glob(pattern)) + list(root.glob(pattern[:-3] + "yaml")))
    for file in files:
        try:
            result.rules.append(parse(file.read_text(encoding="utf-8"), str(file)))
        except SigmaError as e:                    # UnsupportedRule included
            result.rejected.append((str(file), str(e)))
        except Exception as e:                     # a malformed file, not a bad rule
            result.rejected.append((str(file), f"{type(e).__name__}: {e}"))
    return result


def match_all(rules: list[SigmaRule], event: dict) -> list[SigmaRule]:
    """Every rule that fires, not the first.

    `conf/rules.yaml` stops at the first regex that matches, which is why a
    single broad pattern could label every event COMMAND INJECTION and hide
    everything behind it. Techniques accumulate across rules, so stopping
    early would also lose the ATT&CK coverage that makes this worth having.
    """
    return [r for r in rules if r.matches(event)]


# systemd journal field -> the name Sigma rules for Linux address.
# The journal is genuinely structured, so rules matching on a process name
# work there the same way they do on Windows.
JOURNAL_FIELDS = {
    "_COMM": "Image",
    "_EXE": "ImagePath",
    "_CMDLINE": "CommandLine",
    "SYSLOG_IDENTIFIER": "ServiceName",
    "_PID": "ProcessId",
    "_UID": "UserId",
    "_SYSTEMD_UNIT": "Unit",
    "_HOSTNAME": "Computer",
    "MESSAGE": "Message",
}


def journal_event_fields(entry: dict) -> dict:
    """A systemd journal entry, in the names Sigma rules use.

    Worth doing separately from the plain-file path: the journal carries the
    process, its command line and the unit as real fields, so a rule matching
    `Image|endswith` behaves here as it does on Windows. A syslog line cannot
    offer that.
    """
    out: dict[str, str] = {}
    for key, value in (entry or {}).items():
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        out[str(key)] = text
        mapped = JOURNAL_FIELDS.get(str(key).upper())
        if mapped and mapped not in out:
            out[mapped] = text
    out.setdefault("Message", str(entry.get("MESSAGE", "") if entry else ""))
    return out


def text_event_fields(line: str, source: str = "", ip: str = "",
                      user: str = "") -> dict:
    """A plain log line, with whatever could be pulled out of it.

    Deliberately thin, and the limit is worth stating rather than papering
    over: a syslog line is text, so only `Message|contains` style rules can
    fire here. A Sigma rule matching `Image|endswith` will not match, not
    because the event is uninteresting but because the field does not exist.

    Anything richer would mean parsing every log format, which is what the
    journal and the Windows event log already do properly.
    """
    fields = {"Message": str(line or ""), "LogFile": str(source or "")}
    if ip:
        fields["SourceIp"] = ip
    if user:
        fields["User"] = user
    return fields
