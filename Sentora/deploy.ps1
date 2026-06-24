# Sentora Agent - Token-Based Installer (Windows)
#
# Usage:
#   .\deploy.ps1 -Token <ENROLLMENT_TOKEN> -Server <SERVER_URL>
#
# Or one-liner:
#   iwr -useb "<SERVER_URL>/api/agent/deploy/windows?token=<TOKEN>" | iex
#
param(
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$Server,
    [string]$Name = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Must be run as Administrator." -ForegroundColor Red
    exit 1
}

$Server     = $Server.TrimEnd('/')
$ServerIp   = ($Server -replace '^https?://','' -replace ':.*$','')
$InstallDir = "C:\Program Files\Sentora-Agent"

Write-Host "[*] Registering with $Server ..." -ForegroundColor Yellow
$RegBody = @{ token = $Token; hostname = $Name; os_type = "windows" } | ConvertTo-Json -Compress
try {
    $Reg = Invoke-RestMethod -Method Post -Uri "$Server/api/agents/register" -ContentType "application/json" -Body $RegBody
} catch {
    Write-Host "[!] Registration failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if (-not $Reg.agent_name -or -not $Reg.agent_key) {
    Write-Host "[!] Registration response missing identity." -ForegroundColor Red
    exit 1
}
$AgentName = $Reg.agent_name
$AgentKey  = $Reg.agent_key
Write-Host "[+] Enrolled as: $AgentName" -ForegroundColor Green

if (!(Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }

# If installing from the unpacked ZIP, copy alongside binary
$local = Join-Path (Split-Path -Parent $PSCommandPath) "main.exe"
if ((Test-Path $local) -and (-not (Test-Path (Join-Path $InstallDir "main.exe")))) {
    Copy-Item $local -Destination $InstallDir -Force
}
if (-not (Test-Path (Join-Path $InstallDir "main.exe"))) {
    Write-Host "[*] Downloading binary..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "$Server/api/agent/download/windows" `
        -Headers @{ "X-Agent-Key" = $AgentKey } `
        -OutFile (Join-Path $InstallDir "agent.zip")
    Expand-Archive -Path (Join-Path $InstallDir "agent.zip") -DestinationPath $InstallDir -Force
    Remove-Item (Join-Path $InstallDir "agent.zip") -Force
}

$ConfigPath = Join-Path $InstallDir "config.json"
@{
    agent_name = $AgentName
    agent_key  = $AgentKey
    server_url = $Server
    server_ip  = $ServerIp
} | ConvertTo-Json -Depth 3 | Set-Content -Path $ConfigPath -Encoding UTF8

$svcName = "SentoraAgent"
$binPath = "`"$InstallDir\main.exe`" --config `"$ConfigPath`""
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 2
}
sc.exe create $svcName binPath= $binPath start= auto DisplayName= "Sentora Agent" | Out-Null
Start-Service -Name $svcName

Write-Host "[+] Sentora Agent installed and running as: $AgentName" -ForegroundColor Green
