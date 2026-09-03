# Sentora Agent - PyInstaller build script (Windows)
#
# Builds Sentora/main.py into a single main.exe that the server ships via
# /api/agent/download/windows and the token-based installer consumes.
#
# Usage:
#   .\build_agent.ps1                # full clean build
#   .\build_agent.ps1 -NoClean       # keep build/dist/main.spec (faster rebuilds)
#   .\build_agent.ps1 -SkipDeps      # skip `pip install` (use current env as-is)
#
# Output:
#   Sentora\main.exe                (one-file bundle, ~30-45 MB after excludes)
#   Prints SHA-256 so the server-side download endpoint can be verified.

[CmdletBinding()]
param(
    [switch]$NoClean,
    [switch]$SkipDeps
)

$ErrorActionPreference = "Stop"

# ─────────────────────── helpers ───────────────────────
function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok  ($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[x] $msg" -ForegroundColor Red;  exit 1 }

$ScriptDir = Split-Path -Parent $PSCommandPath
Set-Location $ScriptDir

Write-Host "[*] Sentora Agent Builder (Windows / PyInstaller)" -ForegroundColor White
Write-Step "Working dir: $ScriptDir"

# ─────────────────────── prerequisites ───────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Fail "python not found on PATH (need 3.10+)."
}

$pyVer = (& python -c "import sys; print('%d.%d' % sys.version_info[:2])").Trim()
$pyOk  = (& python -c "import sys; print(1 if sys.version_info >= (3,10) else 0)").Trim()
if ($pyOk -ne "1") {
    Write-Fail "Python $pyVer is too old - agent requires 3.10+."
}
Write-Step "Python $pyVer detected."

foreach ($p in @("main.py", "conf", "modules", "requirements.txt")) {
    $full = Join-Path $ScriptDir $p
    if (-not (Test-Path $full)) { Write-Fail "Required path missing: $p" }
}

# ─────────────────────── deps ───────────────────────
if (-not $SkipDeps) {
    Write-Step "Installing pip dependencies..."
    & python -m pip install --upgrade --quiet pip
    if ($LASTEXITCODE -ne 0) { Write-Fail "pip self-upgrade failed." }
    & python -m pip install --quiet -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Fail "pip install -r requirements.txt failed." }
    & python -m pip install --quiet pyinstaller
    if ($LASTEXITCODE -ne 0) { Write-Fail "pip install pyinstaller failed." }
    Write-Ok "Dependencies ready."
} else {
    Write-Warn "Skipping dependency install (-SkipDeps)."
}

# ─────────────────────── clean ───────────────────────
if (-not $NoClean) {
    Write-Step "Cleaning previous build artifacts..."
    Remove-Item -Recurse -Force (Join-Path $ScriptDir "build")     -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $ScriptDir "dist")      -ErrorAction SilentlyContinue
    Remove-Item -Force          (Join-Path $ScriptDir "main.spec") -ErrorAction SilentlyContinue
    Remove-Item -Force          (Join-Path $ScriptDir "main.exe")  -ErrorAction SilentlyContinue
}

# ─────────────────────── build ───────────────────────
# NOTE: absolute paths for --add-data so PyInstaller resolves them against
# the CWD (not the specpath). The dest;src separator on Windows is `;`.
#
# --collect-all pulls package data + hidden submodules + binaries. Required
# for PIL/mss, whose native libs the static scanner misses.
#
# sanic, sanic_cors, sanic_routing, tracerite and html5tagger were here for
# the agent's HTTP listener. The agent dials the server now and serves
# nothing, so the whole web stack left the binary with it.

$confPath    = Join-Path $ScriptDir "conf"
$modulesPath = Join-Path $ScriptDir "modules"
# db/init.sql ships with the binary so the agent can bring its own database up
# to date on start. Postgres only runs docker-entrypoint-initdb.d on an empty
# data directory, so without this a column added in a later release never
# appeared on a machine where the agent had run before - every insert then
# failed into agent.log while the platform still reported the agent healthy.
$dbPath      = Join-Path $ScriptDir "db"

$addData = @(
    "${confPath};conf",
    "${modulesPath};modules",
    "${dbPath};db"
)

$collectAll = @(
    "PIL",
    "mss"
)

# Agent does NOT use any ML / GUI / scientific stack. If the user's
# global Python env happens to have these installed, PyInstaller will
# eagerly try to bundle them (and torch in particular triggers a long
# chain of failing DLL lookups). Exclude them explicitly — keeps the
# binary lean (~30-45 MB instead of 300 MB) and silences spurious
# torch / transformers / kivy hook errors.
$excludeModules = @(
    # PyTorch family
    "torch", "torchaudio", "torchvision", "torchtext", "torchdata",
    # HuggingFace stack (pulls torch as a transitive)
    "transformers", "tokenizers", "safetensors", "huggingface_hub",
    "datasets", "accelerate",
    # Kivy / KivyMD (mobile UI toolkit — totally unrelated to the agent)
    "kivy", "kivymd",
    "kivy_deps", "kivy_deps.angle", "kivy_deps.glew", "kivy_deps.sdl2",
    # Browser automation
    "playwright",
    # Scientific stack
    "scipy", "sklearn", "scikit-learn",
    # Other ML frameworks
    "tensorflow", "keras",
    # Plotting
    "matplotlib", "seaborn", "plotly",
    # Notebook stack
    "jupyter", "IPython", "notebook", "ipykernel", "ipywidgets",
    # Test runners
    "pytest", "_pytest"
)

$hiddenImports = @(
    # third-party
    "cryptography",
    "requests",
    "psutil",
    "watchdog",
    "docker",
    "yaml",
    "psycopg2",
    "pandas",
    # screen-streaming stack
    "mss",
    "mss.windows",
    "PIL",
    "PIL.Image",
    "PIL.JpegImagePlugin",
    # Windows service helpers
    "win32serviceutil",
    "win32service",
    "win32event",
    "servicemanager",
    # in-tree agent modules - PyInstaller's static analyser usually catches
    # these from top-level imports in main.py, but listing them explicitly
    # makes the bundle robust against late/conditional imports.
    "modules.find_vulns.info_collector",
    "modules.find_vulns.find_vuln",
    "modules.alert.alert",
    "modules.portscanner.portscanner",
    "modules.edr_enforcer",
    "modules.docker_monitor.docker_monitor",
    "modules.fim",
    "modules.inventory",
    "modules.lateral_movement",
    "modules.persistence_hunter",
    "modules.log_extractor.log_extractor",
    "modules.check_permissions.check_permissions",
    "modules.resource_checker.resource_checker",
    "modules.resource_checker.disks",
    "modules.soar.soar",
    "modules.soar.vnc_manager",
    "modules.enc_db",
    "modules.agent_paths",
    "modules.screen_capture",
    "modules.console",
    "modules.link",
    # `modules.link` is itself a hidden import, so PyInstaller never walks its
    # imports statically - and this is the one it needs. Left out, the binary
    # builds cleanly and dies on the first channel connect, which is the worst
    # place to find it.
    "modules.version",
    "modules.telemetry_health",
    "websocket",
    "winpty",
    "winpty.ptyprocess",
    "modules.db"
)

$piArgs = @(
    "--onefile",
    "--clean",
    "--noconfirm",
    "--log-level", "WARN",
    "--name", "main",
    "--console",
    "--distpath", $ScriptDir,
    "--workpath", (Join-Path $ScriptDir "build"),
    "--specpath", $ScriptDir
)
foreach ($d in $addData)       { $piArgs += @("--add-data",      $d) }
foreach ($c in $collectAll)    { $piArgs += @("--collect-all",   $c) }
foreach ($h in $hiddenImports) { $piArgs += @("--hidden-import", $h) }
foreach ($e in $excludeModules){ $piArgs += @("--exclude-module", $e) }
$piArgs += (Join-Path $ScriptDir "main.py")

Write-Step "Running PyInstaller..."
& python -m PyInstaller @piArgs
if ($LASTEXITCODE -ne 0) {
    Write-Fail "PyInstaller exited with code $LASTEXITCODE."
}

# ─────────────────────── verify ───────────────────────
$artifact = Join-Path $ScriptDir "main.exe"
if (-not (Test-Path $artifact)) {
    Write-Fail "Build failed: main.exe not produced. Inspect PyInstaller output above."
}

$sizeMb = (Get-Item $artifact).Length / 1MB
$sha    = (Get-FileHash -Algorithm SHA256 $artifact).Hash.ToLower()

Write-Ok ("Built main.exe  ({0:N1} MB)" -f $sizeMb)
Write-Host "    sha256: $sha"
Write-Host "    Ship it via /api/agent/download/windows (restart the server container to pick it up)."

# ─────────────────────── post-build cleanup ───────────────────────
# Drop the intermediate PyInstaller artifacts so the working tree
# stays clean. Only main.exe is needed downstream. -NoClean preserves
# everything for faster incremental rebuilds.
if (-not $NoClean) {
    Write-Step "Cleaning intermediate build artifacts..."
    Remove-Item -Recurse -Force (Join-Path $ScriptDir "build")     -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $ScriptDir "dist")      -ErrorAction SilentlyContinue
    Remove-Item -Force          (Join-Path $ScriptDir "main.spec") -ErrorAction SilentlyContinue
    Get-ChildItem -Path $ScriptDir -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Cleaned build/, dist/, main.spec, __pycache__/."
}
