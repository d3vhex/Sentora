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

An event ID with no mapping is not dropped: its inserts stay reachable under
generic names and the assembled text under `Message`. That is weaker than a
field match, and `unmapped_event_ids()` reports which IDs arrive that way
rather than leaving the gap silent.

Sysmon gets its own table, selected by channel. Its IDs are small numbers - 1,
11, 13 - that mean something entirely different on System and Application, and
reading one through Sysmon's layout would put arbitrary text into `Image`.

Linux
-----
The two paths are not equally capable, and the difference belongs to the logs
rather than the rules. `journal_event_fields` maps a systemd entry, which
carries the process, its command line and the unit. `text_event_fields`
handles a plain line, where only `Message` and what the enricher extracted
exist - so a rule matching `CommandLine` cannot fire there.
"""

from __future__ import annotations

import pathlib
import re
from re import error
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

# Sigma calls the process image `Image`; the 4688 schema calls it
# `NewProcessName`. Aliases rather than renames, so either spelling matches.
FIELD_ALIASES = {
    "NewProcessName": "Image",
    "ParentProcessName": "ParentImage",
    "TargetUserName": "User",
    "IpAddress": "SourceIp",
    # A 4104 script block and a 4688 command line answer the same question.
    # Aliasing them keeps CommandLine rules working on an estate that has
    # script block logging on and never sees the process event.
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

    Named-field rules cannot fire for these, so this is the size of the gap
    rather than a reassuring silence.
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

    Separate from the plain-file path because the journal carries the process,
    its command line and the unit as real fields.
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


# Syslog is text, but it is not *arbitrary* text. A handful of daemons write
# almost everything worth correlating on a Linux host, and each writes in a
# fixed shape. Parsing those shapes is the difference between a rule that can
# say "Image endswith sshd" and one that can only grep the line.
#
# Each entry is (compiled pattern, {capture group -> Sigma field name}). Every
# pattern that matches contributes; they are not mutually exclusive, because a
# sudo line carries both a user and a command and both are worth having.
#
# What this deliberately does not do is try to parse every format. These are
# the ones that carry authentication and execution - the two things the
# detections here are about.
_SYSLOG_PATTERNS: list[tuple[re.Pattern, dict[str, str]]] = [
    # sshd: the single most useful line on an internet-facing host.
    (re.compile(r"sshd\[\d+\]:\s+Failed (?:password|publickey) for "
                r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)", re.I),
     {"user": "TargetUserName", "ip": "IpAddress"}),
    (re.compile(r"sshd\[\d+\]:\s+Accepted (?:password|publickey|keyboard-interactive)"
                r"(?:/\S+)? for (?P<user>\S+) from (?P<ip>\S+)", re.I),
     {"user": "TargetUserName", "ip": "IpAddress"}),
    # sudo: the command is in the line, which is why the Linux Sigma rules can
    # match on a plain file at all.
    (re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.+)$", re.I),
     {"user": "SubjectUserName", "cmd": "CommandLine"}),
    (re.compile(r"sudo:.*?USER=(?P<target>\S+)", re.I),
     {"target": "TargetUserName"}),
    # PAM, which is where su and login failures land. `user=` is matched
    # separately rather than as an optional tail: PAM writes its fields in
    # no fixed order, and an optional group after `.*?` matches empty every
    # time - which is why the su line came back with no account at all.
    (re.compile(r"pam_unix\((?P<svc>[^:]+):auth\):\s+authentication failure",
                re.I),
     {"svc": "ServiceName"}),
    (re.compile(r"\buser=(?P<user>\S+)", re.I), {"user": "TargetUserName"}),
    (re.compile(r"\brhost=(?P<ip>\S+)", re.I), {"ip": "IpAddress"}),
    # cron.
    (re.compile(r"CRON\[\d+\]:\s+\((?P<user>[^)]+)\)\s+CMD\s+\((?P<cmd>.+)\)"),
     {"user": "SubjectUserName", "cmd": "CommandLine"}),
    # auditd, if it is forwarded to a file.
    (re.compile(r'\bcomm="(?P<comm>[^"]+)"'), {"comm": "Image"}),
    (re.compile(r'\bexe="(?P<exe>[^"]+)"'), {"exe": "ImagePath"}),
    # The daemon that wrote the line, when nothing more specific matched.
    (re.compile(r"^\w{3}\s+\d+\s[\d:]+\s+\S+\s+(?P<prog>[\w./-]+)(?:\[\d+\])?:"),
     {"prog": "ServiceName"}),
]

# Whether the line is an authentication attempt, and how it went. Synthesised
# rather than parsed: Linux has no equivalent of EventID 4624/4625, so the
# correlation rules need something stable to key on that is not "does this
# text contain the word failed".
_AUTH_FAILURE = re.compile(
    r"Failed (?:password|publickey)|authentication failure|"
    r"Invalid user|Failed none for|maximum authentication attempts", re.I)
_AUTH_SUCCESS = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive)|"
    r"session opened for user", re.I)


def text_event_fields(line: str, source: str = "", ip: str = "",
                      user: str = "") -> dict:
    """A plain log line, with whatever could be pulled out of it.

    This used to return `Message` and nothing else, on the reasoning that
    parsing every log format is not worth it. That reasoning was half right:
    parsing *every* format is not worth it, and parsing the handful that carry
    authentication and command execution is - it is the difference between a
    host on rsyslog getting field-matching rules and correlation, and getting
    neither.

    What still cannot be had here is anything the line does not contain. An
    auditd SYSCALL record names the binary; a bare `sshd` line does not name
    the command. Fields absent from the text stay absent rather than being
    guessed at, because a wrong `Image` is worse than a missing one - it
    matches rules the event has nothing to do with.

    `ip` and `user` are what the enricher already extracted, and they lose to
    anything parsed out of the line here, which is more specific.
    """
    text = str(line or "")
    fields: dict[str, str] = {"Message": text, "LogFile": str(source or "")}
    if ip:
        fields["SourceIp"] = ip
    if user:
        fields["User"] = user

    for pattern, mapping in _SYSLOG_PATTERNS:
        found = pattern.search(text)
        if not found:
            continue
        for group, name in mapping.items():
            try:
                value = found.group(group)
            except (IndexError, error):
                continue
            if value and name not in fields:
                fields[name] = value.strip()

    if "IpAddress" in fields:
        fields.setdefault("SourceIp", fields["IpAddress"])
    if "TargetUserName" in fields:
        fields.setdefault("User", fields["TargetUserName"])

    if _AUTH_FAILURE.search(text):
        fields["AuthResult"] = "failure"
    elif _AUTH_SUCCESS.search(text):
        fields["AuthResult"] = "success"
    return fields


# The agent flattens a Windows event to
#
#     [Provider] EID=4625, Cat=12544 | Failed Logon | insert0 | insert1 | ...
#
# where the inserts are `' | '.join(StringInserts)` and the human label exists
# only for the handful of event IDs the agent captions. Everything needed to
# put the named fields back is therefore present - it is the same positional
# array, joined.
_AGENT_ENVELOPE = re.compile(
    r"^\[(?P<provider>[^\]]*)\]\s*EID=(?P<eid>\d+)(?:,\s*Cat=(?P<cat>\d+))?\s*(?P<rest>.*)$",
    re.S)

# Captions the agent adds after the EID. They occupy a segment that is not an
# insert, so they have to be recognised rather than counted.
_AGENT_CAPTIONS = {
    "Successful Logon", "Failed Logon", "Logon explicit credentials",
    "User account created", "User account enabled", "User account disabled",
    "New Process", "A scheduled task was created", "A service was installed",
    "The audit log was cleared", "Registry value set",
}


def agent_event_fields(message: str) -> dict:
    """Named fields from an event as the *server* receives it.

    The agent has the StringInserts and maps them; the server gets one joined
    string. Correlation across hosts happens here, so the mapping has to be
    reversible - and it is, because the join is positional and this is our own
    format on both ends rather than something being guessed at.

    Falls through to the Linux text parsing when the envelope does not match,
    which is what a syslog-sourced event looks like by the time it arrives.
    """
    text = str(message or "")
    found = _AGENT_ENVELOPE.match(text.strip())
    if not found:
        return text_event_fields(text)

    eid = int(found.group("eid"))
    # Split on the bare pipe and strip, rather than on " | ". The envelope's
    # first separator loses its leading space to the regex, so splitting on
    # the padded form left `"| Failed Logon"` as segment zero - the caption
    # then failed to match, nothing was dropped, and every field landed one
    # position late. `TargetUserName` came back as a SID.
    segments = [s.strip() for s in (found.group("rest") or "").split("|")]
    while segments and (not segments[0] or segments[0] in _AGENT_CAPTIONS):
        segments.pop(0)

    fields = windows_event_fields(eid, segments, message=text,
                                  provider=found.group("provider") or "")
    # A Sysmon event arrives with the provider naming it, not a channel.
    if SYSMON_CHANNEL in (found.group("provider") or "").lower():
        fields = windows_event_fields(eid, segments, message=text,
                                      channel="sysmon",
                                      provider=found.group("provider") or "")
    return fields
