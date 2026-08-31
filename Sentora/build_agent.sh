#!/usr/bin/env bash
# Sentora Agent — PyInstaller build script (Linux)
#
# Builds Sentora/main.py into a single 'main' binary that the server ships
# via /api/agent/download/linux and the token-based installer consumes.
#
# Usage:
#   ./build_agent.sh                # full clean build
#   ./build_agent.sh --no-clean     # keep build/ + dist/ + main.spec (faster rebuilds)
#   ./build_agent.sh --skip-deps    # skip `pip install` — use the current env as-is
#   ./build_agent.sh -h | --help
#
# Output:
#   Sentora/main                   (one-file bundle, ~22-40 MB after excludes)
#   Prints SHA-256 so the server-side download endpoint can be verified.

set -euo pipefail

# ───────────────────────── colours ─────────────────────────
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=; GREEN=; YELLOW=; CYAN=; BOLD=; NC=
fi

step() { printf "%s[*]%s %s\n"  "$CYAN"   "$NC" "$*"; }
ok()   { printf "%s[+]%s %s\n"  "$GREEN"  "$NC" "$*"; }
warn() { printf "%s[!]%s %s\n"  "$YELLOW" "$NC" "$*"; }
fail() { printf "%s[x]%s %s\n"  "$RED"    "$NC" "$*" >&2; exit 1; }

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# ───────────────────────── args ─────────────────────────
DO_CLEAN=1
DO_DEPS=1
while [ $# -gt 0 ]; do
    case "$1" in
        --no-clean)  DO_CLEAN=0; shift ;;
        --skip-deps) DO_DEPS=0;  shift ;;
        -h|--help)   usage ;;
        *) fail "Unknown option: $1 (try --help)" ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

printf "%s[*] Sentora Agent Builder (Linux / PyInstaller)%s\n" "$BOLD" "$NC"
step "Working dir: $SCRIPT_DIR"

# ─────────────────────── prerequisites ───────────────────────
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH (need 3.10+)."

PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')"
[ "$PY_OK" = "1" ] || fail "Python $PY_VER is too old — agent requires 3.10+."
step "Python $PY_VER detected."

[ -f "$SCRIPT_DIR/main.py" ]         || fail "main.py not found in $SCRIPT_DIR."
[ -d "$SCRIPT_DIR/conf" ]            || fail "conf/ directory missing."
[ -d "$SCRIPT_DIR/modules" ]         || fail "modules/ directory missing."
[ -f "$SCRIPT_DIR/requirements.txt" ] || fail "requirements.txt missing."

# ─────────────────────── deps ───────────────────────
#
# A stock Ubuntu image has none of this, and the script used to assume all of
# it. `python3 -m pip` is not present until `python3-pip` is installed - the
# first thing a fresh EC2 box says is "No module named pip" - and on 24.04 and
# newer, installing into the system interpreter is refused outright by PEP 668
# even once pip exists.
#
# So: apt for what only apt can provide, then a build venv for the Python
# side. The venv also keeps the build from touching the system interpreter of
# a machine that is probably running something else.
#
# `cysystemd` is the reason the compiler and headers are needed. It has no
# wheel and builds against libsystemd; without those four packages the install
# fails several minutes in, with a compiler error that does not mention them.

APT_PACKAGES="python3-venv python3-dev gcc pkg-config libsystemd-dev binutils"

ensure_system_packages() {
    command -v apt-get >/dev/null 2>&1 || return 0

    local missing=""
    dpkg -s python3-venv   >/dev/null 2>&1 || missing="$missing python3-venv"
    dpkg -s python3-dev    >/dev/null 2>&1 || missing="$missing python3-dev"
    dpkg -s gcc            >/dev/null 2>&1 || missing="$missing gcc"
    dpkg -s pkg-config     >/dev/null 2>&1 || missing="$missing pkg-config"
    dpkg -s libsystemd-dev >/dev/null 2>&1 || missing="$missing libsystemd-dev"
    dpkg -s binutils       >/dev/null 2>&1 || missing="$missing binutils"
    [ -n "$missing" ] || return 0

    if [ "$(id -u)" != "0" ]; then
        fail "Need to install:$missing
    Re-run with sudo:  sudo bash $0"
    fi

    step "Installing system packages:$missing"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing >/dev/null
    ok "System packages ready."
}

VENV="$SCRIPT_DIR/.venv-build"
PY="python3"

if [ "$DO_DEPS" = "1" ]; then
    ensure_system_packages

    if [ ! -x "$VENV/bin/python" ]; then
        step "Creating build virtualenv..."
        python3 -m venv "$VENV" || fail "Could not create a virtualenv at $VENV.
    Install python3-venv and re-run:  sudo apt-get install -y python3-venv"
    fi
    PY="$VENV/bin/python"

    step "Installing pip dependencies..."
    "$PY" -m pip install --upgrade --quiet pip setuptools wheel
    "$PY" -m pip install --quiet -r requirements.txt
    "$PY" -m pip install --quiet pyinstaller
    ok "Dependencies ready."
else
    # --skip-deps still prefers the build venv when one exists, so a rebuild
    # does not silently fall back to a system interpreter that has none of
    # this installed and fail on the first import.
    [ -x "$VENV/bin/python" ] && PY="$VENV/bin/python"
    warn "Skipping dependency install (--skip-deps). Using: $PY"
fi

"$PY" -c "import PyInstaller" 2>/dev/null || fail "PyInstaller is not installed in $PY.
    Re-run without --skip-deps."

# ─────────────────────── clean ───────────────────────
if [ "$DO_CLEAN" = "1" ]; then
    step "Cleaning previous build artifacts..."
    # Deliberately not .venv-build: re-resolving and recompiling cysystemd on
    # every build turns a two-minute rebuild into a ten-minute one.
    rm -rf "$SCRIPT_DIR/build" "$SCRIPT_DIR/dist" "$SCRIPT_DIR/main.spec" "$SCRIPT_DIR/main"
fi

# ─────────────────────── build ───────────────────────
# NOTE: absolute paths for --add-data so PyInstaller resolves them against the
# CWD, not the specpath. The dest;src separator on Linux is `:`.
#
# --collect-all pulls package data + hidden submodules + binaries. Required
# for PIL/mss, whose native libs the static scanner misses.
#
# sanic, sanic_cors, sanic_routing, tracerite and html5tagger were here for
# the agent's HTTP listener. The agent dials the server now and serves
# nothing, so the whole web stack left the binary with it.

step "Running PyInstaller..."
"$PY" -m PyInstaller \
    --onefile \
    --clean \
    --noconfirm \
    --log-level WARN \
    --name main \
    --console \
    --distpath "$SCRIPT_DIR" \
    --workpath "$SCRIPT_DIR/build" \
    --specpath "$SCRIPT_DIR" \
    --add-data "$SCRIPT_DIR/conf:conf" \
    --add-data "$SCRIPT_DIR/modules:modules" \
    --collect-all PIL \
    --collect-all mss \
    --hidden-import cryptography \
    --hidden-import requests \
    --hidden-import psutil \
    --hidden-import watchdog \
    --hidden-import docker \
    --hidden-import yaml \
    --hidden-import psycopg2 \
    --hidden-import pandas \
    --hidden-import mss \
    --hidden-import mss.linux \
    --hidden-import PIL \
    --hidden-import PIL.Image \
    --hidden-import PIL.JpegImagePlugin \
    --hidden-import modules.find_vulns.info_collector \
    --hidden-import modules.find_vulns.find_vuln \
    --hidden-import modules.alert.alert \
    --hidden-import modules.portscanner.portscanner \
    --hidden-import modules.edr_enforcer \
    --hidden-import modules.docker_monitor.docker_monitor \
    --hidden-import modules.fim \
    --hidden-import modules.inventory \
    --hidden-import modules.lateral_movement \
    --hidden-import modules.persistence_hunter \
    --hidden-import modules.log_extractor.log_extractor \
    --hidden-import modules.check_permissions.check_permissions \
    --hidden-import modules.resource_checker.resource_checker \
    --hidden-import modules.resource_checker.disks \
    --hidden-import modules.soar.soar \
    --hidden-import modules.soar.vnc_manager \
    --hidden-import modules.enc_db \
    --hidden-import modules.agent_paths \
    --hidden-import modules.screen_capture \
    --hidden-import modules.console \
    --hidden-import modules.link \
    --hidden-import modules.version \
    --hidden-import websocket \
    --hidden-import modules.db \
    --exclude-module torch \
    --exclude-module torchaudio \
    --exclude-module torchvision \
    --exclude-module torchtext \
    --exclude-module torchdata \
    --exclude-module transformers \
    --exclude-module tokenizers \
    --exclude-module safetensors \
    --exclude-module huggingface_hub \
    --exclude-module datasets \
    --exclude-module accelerate \
    --exclude-module kivy \
    --exclude-module kivymd \
    --exclude-module kivy_deps \
    --exclude-module kivy_deps.angle \
    --exclude-module kivy_deps.glew \
    --exclude-module kivy_deps.sdl2 \
    --exclude-module playwright \
    --exclude-module scipy \
    --exclude-module sklearn \
    --exclude-module scikit-learn \
    --exclude-module tensorflow \
    --exclude-module keras \
    --exclude-module matplotlib \
    --exclude-module seaborn \
    --exclude-module plotly \
    --exclude-module jupyter \
    --exclude-module IPython \
    --exclude-module notebook \
    --exclude-module ipykernel \
    --exclude-module ipywidgets \
    --exclude-module pytest \
    --exclude-module _pytest \
    "$SCRIPT_DIR/main.py"

# ─────────────────────── verify ───────────────────────
ARTIFACT="$SCRIPT_DIR/main"
[ -f "$ARTIFACT" ] || fail "Build failed: '$ARTIFACT' not produced. Inspect PyInstaller output above."

SIZE="$(du -h "$ARTIFACT" | cut -f1)"
if command -v sha256sum >/dev/null 2>&1; then
    SHA="$(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
else
    SHA="$(shasum -a 256 "$ARTIFACT" | cut -d' ' -f1)"
fi

# Built as root under sudo, which leaves an artifact its invoker cannot
# replace on the next run - and that failure surfaces as a permission error
# from PyInstaller rather than as anything about ownership.
if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" = "0" ]; then
    _grp="$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")"
    chown "$SUDO_USER":"$_grp" "$ARTIFACT" 2>/dev/null || true
    chown -R "$SUDO_USER":"$_grp" "$VENV" 2>/dev/null || true
fi

ok "Built main ($SIZE)"
printf "    sha256: %s\n" "$SHA"
printf "    Ship it via /api/agent/download/linux (restart the server container to pick it up).\n"

# ─────────────────────── post-build cleanup ───────────────────────
# Drop the intermediate PyInstaller artifacts so the working tree
# stays clean. Only ./main is needed downstream. --no-clean preserves
# everything for faster incremental rebuilds.
if [ "$DO_CLEAN" = "1" ]; then
    step "Cleaning intermediate build artifacts..."
    rm -rf "$SCRIPT_DIR/build" "$SCRIPT_DIR/dist" "$SCRIPT_DIR/main.spec"
    find "$SCRIPT_DIR" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
    ok "Cleaned build/, dist/, main.spec, __pycache__/."
fi
