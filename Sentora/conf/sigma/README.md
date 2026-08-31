# Sigma rules

Every `.yml` under this directory is loaded at agent start. A rule that cannot
be compiled is **named in the log with its reason** rather than skipped, so a
rule you installed and believe is running, but is not, is visible on the next
start rather than after an incident.

Rules are additive. `conf/rules.yaml` still runs for events no Sigma rule
addresses.

## What ships in `builtin/`

A baseline of 37 rules covering 38 ATT&CK techniques. It exists because the
alternative was worse: this directory was empty by design, on the argument
that a detection nobody reviewed is not an improvement — which is true, and
which produced zero ATT&CK coverage on every install and a coverage page with
nothing to draw. "No detections" is not a defensible default for a product
whose job is detection.

The baseline is scoped to what the agent actually collects, so every rule can
fire on a stock install rather than waiting for telemetry nobody enabled:

| Area | Windows | Linux |
| --- | --- | --- |
| Credential access | LSASS dump, registry hive export | — |
| Impact | Shadow copy deletion | — |
| Execution | Encoded PowerShell | Script piped to a shell, reverse shell |
| Persistence | Scheduled task, service install, local account, Run key | cron, systemd unit, SSH keys, LD_PRELOAD, kernel module |
| Lateral movement | Service installed from ADMIN$ | — |
| Defense evasion | Defender exclusion, audit log cleared | Shell history cleared, auditd/SELinux disabled |
| Privilege escalation | — | Sudoers outside visudo, SUID shell, container escape |

Linux started at four rules against Windows' twelve, which left cron
persistence, systemd units, LD_PRELOAD, kernel modules and container escape
entirely blind. Each Linux rule carries **both** a `CommandLine` and a
`Message` selection: the journal supplies the first, a plain syslog line
supplies only the second, and a rule written for one path is dead on the
other.

Measured against the eval corpus in `tests/test_sigma_builtin_rules.py`: **9 of
10 attacks caught by Sigma alone, 0 of 9 hard negatives falsely flagged.** The
miss is password spray, which is a shape across several events — one password,
many accounts, one source — and stateless Sigma cannot express it. That is
noted in the test rather than left as an unexplained failure.

Two of those hard negatives are worth knowing about, because both caught a
real bug in this baseline before it shipped:

- a management agent installing a service from `\\corp-sccm01\SoftwareDist$`,
  which an earlier rule flagged by matching any UNC path. ADMIN$ and C$ exist
  on every host without anybody creating them; a vendor's own share does not.
- `[Convert]::FromBase64String($env:APP_CONFIG)` from a developer's terminal.
  Base64 on a PowerShell command line is not an indicator by itself.

## Adding community rules

    git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
    cp -r /tmp/sigma/rules/windows/process_creation/*.yml conf/sigma/

Put them beside `builtin/`, not inside it — the baseline is replaced on
upgrade. Read the load summary on the next agent start: anything using a
construct this evaluator does not implement is rejected by name, and rejected
rules contribute no ATT&CK coverage, which is the one direction that number
must never be wrong in.

## What a Sigma rule gets you that a regex does not

`conf/rules.yaml` matches text in the assembled message. Sigma matches named
fields, which means:

- `Image|endswith: '\vssadmin.exe'` cannot be defeated by the word "vssadmin"
  appearing in an unrelated message, and
- `OriginalFileName: 'VSSADMIN.EXE'` still fires when the binary has been
  copied to `svchost.exe`, which the regex list cannot see at all.

It can also read inside an encoded payload.
`CommandLine|utf16le|base64offset|contains: 'Net.WebClient'` matches a
download cradle that has been base64'd into `-EncodedCommand`, where the
plaintext command line shows only the wrapper. That is the difference between
detecting *that* something was encoded and detecting *what* it was.

Rules also carry `tags: attack.t1490`, which is where the ATT&CK coverage in
the console comes from. Nothing has to be mapped by hand.

## Field mapping

Sigma addresses `CommandLine`, `Image`, `TargetObject`. The Windows event log
supplies `StringInserts`, a positional array whose meaning depends on the
event ID. `core/sigma_loader.WINDOWS_FIELDS` supplies the names for the event
IDs this agent collects, and `SYSMON_FIELDS` does the same for Sysmon.

Sysmon is kept in a separate table selected by channel, because its event IDs
are small numbers — `1`, `11`, `13` — that mean something entirely different
on the System and Application channels. Reading a System event through
Sysmon's layout would put arbitrary text into `Image` and `CommandLine` and
invent evidence for whichever rule then matched it.

An event ID with no mapping is not dropped: its inserts stay reachable and the
assembled text is available as `Message`. But a rule matching on named fields
cannot fire for it, and those IDs are counted and reported rather than passed
over in silence.

### Linux

Both Linux collection paths run Sigma, and they are not equally capable:

- **systemd journal** carries the process, its command line and the unit as
  real fields, so a rule matching `Image|endswith` behaves as it does on
  Windows. `JOURNAL_FIELDS` maps them.
- **plain log files** are text, but not arbitrary text. sshd, sudo, PAM, cron
  and auditd each write in a fixed shape, so `SYSLOG_PATTERNS` pulls
  `TargetUserName`, `IpAddress`, `CommandLine` and `Image` back out of them,
  plus a synthesised `AuthResult` — Linux has no equivalent of EventID
  4624/4625, and the correlation rules need something stabler to key on than
  "does this text contain the word failed".

  Fields the line does not contain stay absent rather than being guessed at. A
  wrong `Image` is worse than a missing one: it matches rules the event has
  nothing to do with. The Windows rules, which match named fields only, still
  cannot fire on a syslog line, and a test pins that so the distinction cannot
  quietly reverse.
