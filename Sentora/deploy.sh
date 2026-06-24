#!/usr/bin/env bash
# Sentora Agent — Token-Based Installer (Linux)
#
# Usage:
#   sudo ./deploy.sh --token <ENROLLMENT_TOKEN> --server <SERVER_URL>
#
# Or pipe via one-liner:
#   curl -fsSL <SERVER_URL>/api/agent/deploy/linux?token=<TOKEN> | sudo bash
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: sudo $0 --token <TOKEN> --server <SERVER_URL>"
    echo "  --token, -t   Enrollment token issued by the server"
    echo "  --server, -s  Server base URL (e.g. https://sentora.example.com)"
    echo "  --name        Optional agent name (default: hostname)"
    exit 1
}

TOKEN=""
SERVER_URL=""
AGENT_NAME="$(hostname)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token|-t) TOKEN="$2"; shift 2 ;;
        --server|-s) SERVER_URL="$2"; shift 2 ;;
        --name) AGENT_NAME="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must be run as root (try sudo).${NC}"; exit 1
fi
if [ -z "$TOKEN" ] || [ -z "$SERVER_URL" ]; then
    usage
fi

SERVER_URL="${SERVER_URL%/}"
SERVER_IP="$(echo "$SERVER_URL" | sed -E 's|https?://([^:/]+).*|\1|')"
INSTALL_DIR="/opt/sentora-agent"

echo -e "${YELLOW}[*] Registering with $SERVER_URL ...${NC}"
REG_RESP="$(curl -fsSL -X POST "$SERVER_URL/api/agents/register" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$TOKEN\",\"hostname\":\"$AGENT_NAME\",\"os_type\":\"linux\"}")"

AGENT_KEY="$(echo "$REG_RESP" | sed -n 's/.*"agent_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
REG_NAME="$(echo "$REG_RESP"  | sed -n 's/.*"agent_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

if [ -z "$AGENT_KEY" ] || [ -z "$REG_NAME" ]; then
    echo -e "${RED}[!] Registration failed: $REG_RESP${NC}"; exit 1
fi
AGENT_NAME="$REG_NAME"
echo -e "${GREEN}[+] Enrolled as: $AGENT_NAME${NC}"

echo -e "${YELLOW}[*] Installing into $INSTALL_DIR ...${NC}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Copy current directory contents if running from the unpacked ZIP
if [ -f "$(pwd -P)/../main" ] && [ ! -f "$INSTALL_DIR/main" ]; then
    cp -f "$(pwd -P)/../main" "$INSTALL_DIR/main"
fi
# If binary still missing, download it
if [ ! -f "$INSTALL_DIR/main" ]; then
    echo -e "${YELLOW}[*] Downloading binary...${NC}"
    curl -fsSL -H "X-Agent-Key: $AGENT_KEY" -o agent.zip "$SERVER_URL/api/agent/download/linux"
    command -v unzip >/dev/null 2>&1 || apt-get update -y >/dev/null && apt-get install -y unzip
    unzip -q -o agent.zip
    rm -f agent.zip
fi

chmod +x "$INSTALL_DIR/main" 2>/dev/null || true

umask 077
cat > "$INSTALL_DIR/config.json" <<EOF
{
  "agent_name": "$AGENT_NAME",
  "agent_key":  "$AGENT_KEY",
  "server_url": "$SERVER_URL",
  "server_ip":  "$SERVER_IP"
}
EOF
chmod 600 "$INSTALL_DIR/config.json"

SERVICE_NAME="sentora-agent"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
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
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo -e "${GREEN}[+] Sentora Agent installed and running as: $AGENT_NAME${NC}"
