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
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from core.sigma import SigmaError, SigmaRule, UnsupportedRule, parse

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
    4720: [  # A user account was created
        "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid",
        "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
    ],
    7045: [  # A service was installed in the system
        "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",
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
}

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

    names = WINDOWS_FIELDS.get(int(event_id))
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
        except (SigmaError, UnsupportedRule) as e:
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
