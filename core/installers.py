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
if ! command -v curl >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y curl
fi
if ! command -v unzip >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y unzip
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

SERVICE_FILE="/etc/systemd/system/sentora-agent.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sentora Agent
After=network.target

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
echo "[+] Sentora Agent installed and running as: $AGENT_NAME"
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

                    # Close out the token anyway. Skipping the call left it
                    # unused forever, so the Deploy page kept reporting
                    # "waiting" after a deployment that had already succeeded.
                    # The server verifies the key before accepting this.
                    $UpBody = @{{ token = $Token; agent_name = $AgentName; agent_key = $AgentKey; hostname = $Hostname; os_type = $OsType }} | ConvertTo-Json -Compress
                    try {{
                        Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/agents/register" -ContentType "application/json" -Body $UpBody | Out-Null
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
