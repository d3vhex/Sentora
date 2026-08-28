"""Installer scripts handed to a new endpoint.

420 lines of PowerShell and shell templating that lived in app.py, which is
where most of its bulk came from. Both functions are pure - they take
(server_url, server_ip, token) and return a string - so they are testable
without a server, which they were not before.

What they generate is the riskiest text in the product: it runs as SYSTEM or
root on a machine that has no Sentora on it yet, and a mistake here is a
broken endpoint rather than a stack trace. Notes on the specific traps are
kept with the code.
"""

from __future__ import annotations


def _render_linux_install(server_url: str, server_ip: str, token: str) -> str:
    return f"""#!/usr/bin/env bash
# Sentora Agent — Token-Based Installer
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Please run as root (use: curl ... | sudo bash)"
  exit 1
fi

TOKEN="{token}"
SERVER_URL="{server_url}"
SERVER_IP="{server_ip}"
INSTALL_DIR="/opt/sentora-agent"
HOSTNAME_VAL="$(hostname)"
OS_TYPE="linux"

echo "[*] Sentora Agent Installer"
echo "[*] Server : $SERVER_URL"
echo "[*] Host   : $HOSTNAME_VAL"

# Dependencies
#
# Docker belongs in this list. The agent keeps its state in a local postgres
# that ships as docker-compose.yml inside the download, and without it the
# binary starts, fails to reach 127.0.0.1:5432, and is restarted forever by
# systemd - while this script has already printed "installed and running".
#
# The Windows installer has always brought that database up. This one did not,
# and said nothing about it, which is the whole failure: a green install and
# an agent that never reports.
if ! command -v curl >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y curl
fi
if ! command -v unzip >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y unzip
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "[*] Installing Docker (the agent's local database runs in it)..."
  apt-get update -y
  apt-get install -y docker.io || {{
    echo "[!] Could not install Docker."
    echo "    The agent needs a local postgres on 127.0.0.1:5432 and will not"
    echo "    start without one. Install Docker and re-run this installer."
    exit 1
  }}
  systemctl enable --now docker >/dev/null 2>&1 || true
fi

# `docker.io` is the daemon and nothing else. Compose v2 is a separate package
# on Debian and Ubuntu, so installing Docker alone leaves `docker compose`
# unavailable - and the failure arrives later, at the point the database is
# meant to start, reported as a Docker problem.
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  echo "[*] Installing the Docker Compose plugin..."
  apt-get install -y docker-compose-v2 >/dev/null 2>&1 \\
    || apt-get install -y docker-compose-plugin >/dev/null 2>&1 \\
    || apt-get install -y docker-compose >/dev/null 2>&1 \\
    || true
fi
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  echo "[!] No Docker Compose available, and the agent's database is defined"
  echo "    as a compose file. Install one of docker-compose-v2 /"
  echo "    docker-compose-plugin / docker-compose and re-run."
  exit 1
fi

# Allow overriding token via --token (for local execution)
for arg in "$@"; do
  case "$arg" in
    --token=*) TOKEN="${{arg#--token=}}" ;;
  esac
done
if [ -z "$TOKEN" ]; then
  echo "[!] Missing enrollment token"; exit 1
fi

echo "[*] Registering with server..."
REG_RESP="$(curl -fsSL -X POST "$SERVER_URL/api/agents/register" \\
  -H 'Content-Type: application/json' \\
  -d "{{\\"token\\":\\"$TOKEN\\",\\"hostname\\":\\"$HOSTNAME_VAL\\",\\"os_type\\":\\"$OS_TYPE\\"}}")"

AGENT_NAME="$(echo "$REG_RESP" | sed -n 's/.*"agent_name"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')"
AGENT_KEY="$(echo "$REG_RESP"  | sed -n 's/.*"agent_key"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')"

if [ -z "$AGENT_NAME" ] || [ -z "$AGENT_KEY" ]; then
  echo "[!] Registration failed: $REG_RESP"
  exit 1
fi

echo "[+] Enrolled as: $AGENT_NAME"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[*] Downloading agent binary..."
curl -fsSL -H "X-Agent-Key: $AGENT_KEY" -o agent.zip "$SERVER_URL/api/agent/download/linux"
unzip -q -o agent.zip
chmod +x main 2>/dev/null || true

# Write identity config
umask 077
cat > "$INSTALL_DIR/config.json" <<EOF
{{
  "agent_name": "$AGENT_NAME",
  "agent_key":  "$AGENT_KEY",
  "server_url": "$SERVER_URL",
  "server_ip":  "$SERVER_IP"
}}
EOF
chmod 600 "$INSTALL_DIR/config.json"

# ── the agent's local database ───────────────────────────────────────────────
# Brought up before the service, not after. Starting the agent first means it
# crash-loops until postgres happens to be ready, filling the journal with
# connection errors that describe a race rather than the actual state.
if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
  echo "[*] Starting the agent's local database (postgres on 127.0.0.1:5432)..."
  ( cd "$INSTALL_DIR" && ( docker compose up -d || docker-compose up -d ) ) || {{
    echo "[!] Could not start the local database."
    echo "    Run:  cd $INSTALL_DIR && docker compose up -d"
    exit 1
  }}

  echo "[*] Waiting for postgres..."
  DB_READY=0
  for _ in $(seq 1 60); do
    if docker exec sentora-db-agent pg_isready -q -U sentorauser -d sentora >/dev/null 2>&1; then
      DB_READY=1; break
    fi
    sleep 1
  done
  if [ "$DB_READY" != "1" ]; then
    # Refusing here rather than starting anyway. An agent that cannot reach
    # its database reports nothing, and an install that claims success while
    # that is true is worse than one that stops.
    echo "[!] Postgres did not become ready within 60s."
    echo "    Check: docker logs sentora-db-agent"
    exit 1
  fi
  echo "[+] Database ready."
else
  echo "[!] docker-compose.yml is missing from the download."
  echo "    The agent has nowhere to store state and will not run."
  exit 1
fi

# ── let the server reach the agent's API ─────────────────────────────────────
# The agent listens on 0.0.0.0:9099 and the server calls it there for config
# reads, SOAR dispatch and the screen stream. A host running ufw drops that,
# and the symptom is a `Connection refused` against a process that is plainly
# listening - which reads as a broken agent rather than a closed port.
#
# Only when a firewall is actually active: adding rules to an inactive ufw
# quietly enables nothing, and running `ufw allow` on a host that does not use
# ufw is noise in someone else's configuration.
#
# Scoped to private networks. The listener requires X-Agent-Key on every
# route, but a firewall rule is a second thing that has to be wrong before an
# endpoint's management API is reachable from anywhere.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "[*] ufw is active - allowing inbound 9099 from private networks..."
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    ufw allow from "$net" to any port 9099 proto tcp >/dev/null 2>&1 || true
  done
  if ufw status | grep -q "9099"; then
    echo "[+] Firewall: inbound TCP 9099 allowed from private networks."
  else
    # Not fatal - telemetry is agent-initiated and keeps flowing. What breaks
    # is the server calling in, so this has to be visible rather than assumed.
    echo "[!] Could not confirm the ufw rule for 9099."
    echo "    The agent will still send telemetry, but the server cannot reach"
    echo "    it for config, SOAR or the screen stream. Add it by hand:"
    echo "    ufw allow from 192.168.0.0/16 to any port 9099 proto tcp"
  fi
fi

SERVICE_FILE="/etc/systemd/system/sentora-agent.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sentora Agent
# docker.service, not just the network: after a reboot the agent would
# otherwise start before its database and spend RestartSec cycles failing.
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/main --config $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentora-agent
systemctl restart sentora-agent

rm -f agent.zip

# Verified, not assumed. `systemctl restart` returns success once systemd has
# forked the process; a binary that exits immediately still leaves this script
# printing "installed and running".
sleep 3
if systemctl is-active --quiet sentora-agent; then
  echo "[+] Sentora Agent installed and running as: $AGENT_NAME"
else
  echo "[!] The service was installed but is not running."
  echo "    journalctl -u sentora-agent -n 50 --no-pager"
  systemctl status sentora-agent --no-pager -n 20 || true
  exit 1
fi
"""


def _render_windows_install(server_url: str, server_ip: str, token: str) -> str:
    return f"""# Sentora Agent - Token-Based Installer (Windows)
& {{
    $ErrorActionPreference = "Stop"
    $Token     = "{token}"
    $ServerUrl = "{server_url}"
    $ServerIp  = "{server_ip}"
    $InstallDir = "C:\\Program Files\\Sentora-Agent"
    $Hostname  = $env:COMPUTERNAME
    $OsType    = "windows"
    # Set $env:SENTORA_REENROLL=1 before running to discard the existing
    # identity and take a new one. Only needed when the agent's key has been
    # revoked; a plain upgrade keeps the identity it already has.
    #
    # Compared against explicit values, not cast with [bool]: in PowerShell
    # any non-empty string is true, so [bool]"0" is $true and setting the
    # variable to 0 to mean "no" would have forced a re-enrolment.
    $ReEnroll  = ($env:SENTORA_REENROLL -in @("1", "true", "yes", "on"))
    $LogPath   = Join-Path $env:TEMP "sentora-install.log"
    Start-Transcript -Path $LogPath -Force | Out-Null

    try {{
        Write-Host "[*] Sentora Agent Installer" -ForegroundColor Cyan
        Write-Host "[*] Server : $ServerUrl"
        Write-Host "[*] Host   : $Hostname"
        Write-Host "[*] Log    : $LogPath"

        # Elevation: if not admin, relaunch the one-liner in an elevated window
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {{
            Write-Host "[!] Not elevated. Relaunching in an Administrator window..." -ForegroundColor Yellow
            $url = "$ServerUrl/api/agent/deploy/windows?token=$Token"
            $cmd = "iwr -useb '$url' | iex; Read-Host 'Press Enter to close'"
            try {{
                Start-Process -FilePath "powershell.exe" `
                    -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-NoExit","-Command",$cmd `
                    -Verb RunAs | Out-Null
                Write-Host "[*] A new elevated window has opened. Follow installation there." -ForegroundColor Green
            }} catch {{
                Write-Host "[!] Could not auto-elevate: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    Please open PowerShell as Administrator and run the one-liner again." -ForegroundColor Yellow
            }}
            return
        }}

        # An upgrade is not an enrolment. This used to call /register
        # unconditionally, and the server allocates a fresh name whenever the
        # requested one is taken - so re-running this one-liner on a machine
        # that already had an agent produced DESKTOP-X-2, then -3, then -4.
        # One physical host ended up as four "agents": telemetry split across
        # four databases, the fleet view counting it four times, and
        # deduplication running separately in each.
        #
        # If this machine already holds credentials, keep them. Enrolment is
        # for machines that have none.
        $AgentName = $null
        $AgentKey  = $null
        $ExistingConfig = Join-Path $InstallDir "config.json"
        if ((Test-Path $ExistingConfig) -and -not $ReEnroll) {{
            try {{
                $Prev = Get-Content $ExistingConfig -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($Prev.agent_name -and $Prev.agent_key) {{
                    $AgentName = $Prev.agent_name
                    $AgentKey  = $Prev.agent_key
                    Write-Host "[+] Upgrading existing agent: $AgentName" -ForegroundColor Green
                    Write-Host "    Identity kept. Set SENTORA_REENROLL=1 to force a new one." -ForegroundColor DarkGray

                    # Close out the token anyway: skipping this left it
                    # unused forever and the Deploy page reporting "waiting".
                    #
                    # The reply is used, not discarded. A machine whose
                    # identity outlived the server's database gets enrolled
                    # afresh with a NEW key, and throwing that away left the
                    # installer downloading with a credential the server had
                    # just declared dead - a bare 403 with nothing explaining
                    # why.
                    $UpBody = @{{ token = $Token; agent_name = $AgentName; agent_key = $AgentKey; hostname = $Hostname; os_type = $OsType }} | ConvertTo-Json -Compress
                    try {{
                        $UpResp = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/agents/register" -ContentType "application/json" -Body $UpBody
                        if ($UpResp.agent_key -and $UpResp.agent_key -ne $AgentKey) {{
                            $AgentName = $UpResp.agent_name
                            $AgentKey  = $UpResp.agent_key
                            Write-Host "    Server did not recognise the stored key; re-enrolled as $AgentName." -ForegroundColor Yellow
                        }}
                    }} catch {{
                        # Not fatal: the agent already holds working credentials.
                        Write-Host "    (could not mark the enrolment token used: $($_.Exception.Message))" -ForegroundColor DarkGray
                    }}
                }}
            }} catch {{
                Write-Host "[!] Existing config.json is unreadable, enrolling fresh." -ForegroundColor Yellow
            }}
        }}

        if (-not $AgentName) {{
            Write-Host "[*] Registering with server..." -ForegroundColor Cyan
            $RegBody = @{{ token = $Token; hostname = $Hostname; os_type = $OsType }} | ConvertTo-Json -Compress
            try {{
                $Reg = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/agents/register" -ContentType "application/json" -Body $RegBody
            }} catch {{
                Write-Host "[!] Registration call failed: $($_.Exception.Message)" -ForegroundColor Red
                return
            }}

            if (-not $Reg.agent_name -or -not $Reg.agent_key) {{
                Write-Host "[!] Registration response missing identity: $($Reg | ConvertTo-Json -Compress)" -ForegroundColor Red
                return
            }}

            $AgentName = $Reg.agent_name
            $AgentKey  = $Reg.agent_key
            Write-Host "[+] Enrolled as: $AgentName" -ForegroundColor Green
        }}

        if (!(Test-Path $InstallDir)) {{ New-Item -ItemType Directory -Path $InstallDir | Out-Null }}
        Set-Location $InstallDir

        Write-Host "[*] Downloading agent binary..." -ForegroundColor Cyan
        try {{
            Invoke-WebRequest -Uri "$ServerUrl/api/agent/download/windows" `
                -Headers @{{ "X-Agent-Key" = $AgentKey }} -OutFile "agent.zip" -UseBasicParsing
        }} catch {{
            $srv = ""
            try {{ $srv = (New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() }} catch {{}}
            Write-Host "[!] Binary download failed: $($_.Exception.Message)" -ForegroundColor Red
            if ($srv) {{ Write-Host "    Server said: $srv" -ForegroundColor Yellow }}
            return
        }}

        # Stop any previously installed agent BEFORE extracting, otherwise the
        # running main.exe locks itself and Expand-Archive blows up with
        # UnauthorizedAccessException. This is the upgrade-in-place path.
        $existingExe = Join-Path $InstallDir "main.exe"
        if (Test-Path $existingExe) {{
            Write-Host "[*] Stopping previous agent to release main.exe..." -ForegroundColor Cyan
            try {{
                $prevTask = Get-ScheduledTask -TaskName "SentoraAgent" -ErrorAction SilentlyContinue
                if ($prevTask) {{
                    Stop-ScheduledTask -TaskName "SentoraAgent" -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName "SentoraAgent" -Confirm:$false -ErrorAction SilentlyContinue
                }}
            }} catch {{}}
            try {{
                Get-Process -Name "main" -ErrorAction SilentlyContinue | Where-Object {{
                    try {{ $_.Path -eq $existingExe }} catch {{ $false }}
                }} | Stop-Process -Force -ErrorAction SilentlyContinue
            }} catch {{}}

            # Wait until the file is no longer locked. Up to 10s — Windows
            # releases the handle a beat after the process exits.
            for ($i = 0; $i -lt 20; $i++) {{
                try {{
                    $fs = [System.IO.File]::Open($existingExe, 'Open', 'ReadWrite', 'None')
                    $fs.Close()
                    break
                }} catch {{
                    Start-Sleep -Milliseconds 500
                }}
            }}
        }}

        try {{
            Expand-Archive -Path "agent.zip" -DestinationPath "." -Force
        }} catch {{
            Write-Host "[!] Failed to extract agent.zip: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    The previous agent may still be locking main.exe." -ForegroundColor Yellow
            Write-Host "    Manually stop it and retry: Stop-ScheduledTask -TaskName SentoraAgent; Get-Process main | Stop-Process -Force" -ForegroundColor Yellow
            return
        }}

        if (-not (Test-Path (Join-Path $InstallDir "main.exe"))) {{
            Write-Host "[!] main.exe missing after extraction. Server did not ship a binary." -ForegroundColor Red
            return
        }}

        $Config = @{{
            agent_name      = $AgentName
            agent_key       = $AgentKey
            server_url      = $ServerUrl
            server_ip       = $ServerIp
            ingest_port     = 5001
        }} | ConvertTo-Json -Depth 3
        $ConfigPath = Join-Path $InstallDir "config.json"
        # PS5.1 `Set-Content -Encoding UTF8` writes a BOM which Python's
        # json.load rejects with "Unexpected UTF-8 BOM". Use .NET to write
        # BOM-less UTF-8.
        [System.IO.File]::WriteAllText($ConfigPath, $Config, (New-Object System.Text.UTF8Encoding $false))

        # Bootstrap the agent's local postgres. Sentora/docker-compose.yml is
        # shipped inside the zip and defines the `sentora-db-agent` container
        # on localhost:5432 — modules/db.py hard-connects to that. Without it
        # every insert_record/fetch_unsent raises "connection refused".
        $composePath = Join-Path $InstallDir "docker-compose.yml"
        if (Test-Path $composePath) {{
            if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {{
                Write-Host "[!] Docker not found on PATH. Install Docker Desktop and retry." -ForegroundColor Red
                Write-Host "    The agent needs a local postgres (sentora-db-agent) to store its state." -ForegroundColor Yellow
                return
            }}
            Write-Host "[*] Starting local agent database (postgres on :5432)..." -ForegroundColor Cyan
            # NOTE: do NOT redirect stderr with 2>&1. PowerShell 5.1 + Stop
            # action turns every native-cmd stderr line into a NativeCommandError
            # — and `docker compose` writes progress ("Network ... Creating",
            # "Container ... Started") to stderr. We check $LASTEXITCODE instead.
            Push-Location $InstallDir
            $prevEA = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & docker compose up -d
            $composeExit = $LASTEXITCODE
            $ErrorActionPreference = $prevEA
            Pop-Location
            if ($composeExit -ne 0) {{
                Write-Host "[!] docker compose up failed (exit $composeExit)." -ForegroundColor Red
                Write-Host "    Run manually: cd `"$InstallDir`" ; docker compose up -d" -ForegroundColor Yellow
                return
            }}

            Write-Host "[*] Waiting for postgres on localhost:5432..." -ForegroundColor Cyan
            $dbReady = $false
            for ($i = 0; $i -lt 30; $i++) {{
                if (Test-NetConnection -ComputerName localhost -Port 5432 -InformationLevel Quiet -WarningAction SilentlyContinue) {{
                    $dbReady = $true
                    break
                }}
                Start-Sleep -Seconds 2
            }}
            if (-not $dbReady) {{
                Write-Host "[!] Postgres did not become reachable within 60s." -ForegroundColor Red
                Write-Host "    Check: docker logs sentora-db-agent" -ForegroundColor Yellow
                return
            }}
            Write-Host "[+] Agent database ready (sentora-db-agent)." -ForegroundColor Green
        }} else {{
            Write-Host "[!] docker-compose.yml missing in $InstallDir — agent will crash on DB connect." -ForegroundColor Red
            return
        }}

        # Persistence via Scheduled Task (SYSTEM, AtStartup). main.py is a plain
        # console app — it does not implement the Windows Service Control
        # Protocol, so sc.exe create + Start-Service silently fails. Scheduled
        # Task runs the binary as SYSTEM at every boot and we kick it off now.
        $taskName = "SentoraAgent"
        $exePath  = Join-Path $InstallDir "main.exe"
        $workDir  = $InstallDir

        # Let the server reach the agent's API.
        #
        # The agent listens on 0.0.0.0:9099 and the server calls it there for
        # config reads, SOAR dispatch and the screen stream. Windows blocks
        # inbound connections to a program that has not been allowed, and the
        # prompt that would normally ask cannot appear here: the agent runs as
        # SYSTEM in session 0, which has no desktop to show it on. So the port
        # stayed shut with nothing anywhere saying so - every server-to-agent
        # call came back `Connection refused` against a process that was
        # listening, which reads as a broken agent rather than a closed port.
        #
        # Scoped by remote address, not by network profile.
        #
        # `-Profile Domain,Private` is the obvious way to write this and it
        # does not work where it is most needed: Windows classifies the
        # Hyper-V / WSL virtual adapter - the one Docker Desktop's traffic
        # arrives on - as Public. A profile-scoped rule therefore does not
        # apply to it, and the port stays shut with a rule sitting there
        # looking correct.
        #
        # Remote address is the property actually being reasoned about, and it
        # does not depend on how Windows happened to classify an adapter. The
        # listener requires X-Agent-Key on every route regardless; this is the
        # second thing that has to be wrong before an endpoint's management API
        # is reachable from a coffee shop network.
        $agentPort = 9099
        try {{
            Get-NetFirewallRule -DisplayName "Sentora Agent API" -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Sentora Agent API" `
                -Direction Inbound -Action Allow -Protocol TCP `
                -LocalPort $agentPort -Profile Any `
                -RemoteAddress LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 `
                -Program $exePath `
                -Description "Lets the Sentora server reach this agent's API." | Out-Null
            Write-Host "[+] Firewall: inbound TCP $agentPort allowed from private networks." -ForegroundColor Green
        }} catch {{
            # Not fatal: telemetry is agent-initiated and keeps flowing. What
            # breaks is the server calling *in*, so this must be visible rather
            # than swallowed - it is the difference between "the agent is down"
            # and "the port is shut".
            Write-Host "[!] Could not add the firewall rule: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    The agent will still send telemetry, but the server" -ForegroundColor Yellow
            Write-Host "    cannot reach it for config, SOAR or the screen stream." -ForegroundColor Yellow
            Write-Host "    Add it by hand:" -ForegroundColor Yellow
            Write-Host "    New-NetFirewallRule -DisplayName 'Sentora Agent API' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $agentPort -Profile Any -RemoteAddress LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" -ForegroundColor Yellow
        }}

        # Remove legacy sc.exe service if it exists from a previous install
        $legacy = Get-Service -Name $taskName -ErrorAction SilentlyContinue
        if ($legacy) {{
            Stop-Service -Name $taskName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $taskName | Out-Null
        }}

        # Remove previous scheduled task (if any) so we can re-register cleanly
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {{
            try {{ Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }} catch {{}}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }}

        try {{
            $action    = New-ScheduledTaskAction -Execute $exePath -Argument "--config `"$ConfigPath`"" -WorkingDirectory $workDir

            # Two triggers. AtStartup is the normal path. The repeating one is
            # a watchdog: if the agent is ever not running -- crash, manual
            # stop, a failed upgrade -- the next tick starts it again. Without
            # it, a single unhandled exit left the endpoint blind until
            # somebody noticed, which is the worst failure mode a sensor has.
            #
            # MultipleInstances=IgnoreNew below makes the watchdog a no-op
            # while the agent is already up, so this costs nothing when
            # everything is fine.
            $bootTrigger  = New-ScheduledTaskTrigger -AtStartup
            $watchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
                                -RepetitionInterval (New-TimeSpan -Minutes 15)
            $triggers = @($bootTrigger, $watchTrigger)

            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

            # RestartCount is deliberately generous: the agent now retries its
            # own server bootstrap internally, so a restart here means the
            # process actually died, and a sensor that gives up after three
            # tries is a sensor you cannot rely on.
            $settings = New-ScheduledTaskSettingsSet `
                            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                            -StartWhenAvailable `
                            -ExecutionTimeLimit ([TimeSpan]::Zero) `
                            -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) `
                            -MultipleInstances IgnoreNew

            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
        }} catch {{
            Write-Host "[!] Failed to register scheduled task: $($_.Exception.Message)" -ForegroundColor Red
            return
        }}

        # Kill any stale main.exe before starting
        Get-Process -Name "main" -ErrorAction SilentlyContinue | Where-Object {{
            try {{ $_.Path -eq $exePath }} catch {{ $false }}
        }} | Stop-Process -Force -ErrorAction SilentlyContinue

        try {{
            Start-ScheduledTask -TaskName $taskName
            Start-Sleep -Seconds 3
        }} catch {{
            Write-Host "[!] Failed to start scheduled task: $($_.Exception.Message)" -ForegroundColor Red
            return
        }}

        # Verify the agent process is actually running
        $proc = Get-Process -Name "main" -ErrorAction SilentlyContinue | Where-Object {{
            try {{ $_.Path -eq $exePath }} catch {{ $false }}
        }} | Select-Object -First 1
        if (-not $proc) {{
            Write-Host "[!] Agent process did not start. Check $InstallDir\\agent.log" -ForegroundColor Red
            Write-Host "    You can also inspect: Get-ScheduledTaskInfo -TaskName $taskName" -ForegroundColor Yellow
            return
        }}

        Remove-Item -Path "agent.zip" -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Sentora Agent installed and running as: $AgentName" -ForegroundColor Green
        Write-Host "    Task   : $taskName (PID $($proc.Id))"
        Write-Host "    Config : $ConfigPath"
        Write-Host "    Log    : $InstallDir\\agent.log"
    }} catch {{
        Write-Host "[!] Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }} finally {{
        Stop-Transcript | Out-Null
    }}
}}
"""
