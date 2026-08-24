# Sigma rules

Empty by default, and that is deliberate: a detection nobody has reviewed is
not an improvement on a detection nobody has reviewed. Choose what to install.

    git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
    cp -r /tmp/sigma/rules/windows/process_creation/*.yml conf/sigma/

Every `.yml` under this directory is loaded at agent start. A rule that cannot
be compiled is **named in the log with its reason** rather than skipped, so a
rule you installed and believe is running, but is not, is visible on the next
start rather than after an incident.

Rules are additive. `conf/rules.yaml` still runs for events no Sigma rule
addresses, so installing none changes nothing.

## What a Sigma rule gets you that a regex does not

`conf/rules.yaml` matches text in the assembled message. Sigma matches named
fields, which means:

- `Image|endswith: '\vssadmin.exe'` cannot be defeated by the word "vssadmin"
  appearing in an unrelated message, and
- `OriginalFileName: 'VSSADMIN.EXE'` still fires when the binary has been
  copied to `svchost.exe`, which the regex list cannot see at all.

They also carry `tags: attack.t1490`, which is where the ATT&CK coverage in
the console comes from. Nothing has to be mapped by hand.

## Field mapping

Sigma addresses `CommandLine`, `Image`, `TargetObject`. The Windows event log
supplies `StringInserts`, a positional array whose meaning depends on the
event ID. `core/sigma_loader.WINDOWS_FIELDS` supplies the names for the event
IDs this agent collects.

An event ID with no mapping is not dropped - its inserts stay reachable and
the assembled text is available as `Message` - but a rule matching on named
fields cannot fire for it. Those IDs are counted and reported rather than
passed over in silence.
