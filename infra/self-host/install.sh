#!/usr/bin/env bash
# Tracelane self-host installer
# Usage: curl -fsSL https://install.tracelane.dev | bash
#
# What this does:
#   1. Checks Docker + Docker Compose are available
#   2. Downloads docker-compose.yml + .env.example to ./tracelane/
#   3. Generates TRACELANE_MASTER_KEY and CLICKHOUSE_PASSWORD
#   4. Starts the stack
#   5. Prints the endpoint URL

set -euo pipefail

INSTALL_DIR="${TRACELANE_DIR:-./tracelane}"
GITHUB_RAW="https://raw.githubusercontent.com/tracelane/tracelane/main/infra/self-host"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        red "Error: $1 not found. Please install it first."
        case "$1" in
            docker)   echo "  https://docs.docker.com/get-docker/" ;;
        esac
        exit 1
    fi
}

bold "Tracelane self-host installer"
echo ""

check_dep docker
check_dep curl

# Docker Compose: either plugin (docker compose) or standalone (docker-compose)
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    red "Error: Docker Compose not found."
    echo "  https://docs.docker.com/compose/install/"
    exit 1
fi

mkdir -p "$INSTALL_DIR/clickhouse"

yellow "Downloading configuration files..."

curl -fsSL "$GITHUB_RAW/docker-compose.yml"          -o "$INSTALL_DIR/docker-compose.yml"
curl -fsSL "$GITHUB_RAW/.env.example"                -o "$INSTALL_DIR/.env.example"
curl -fsSL "$GITHUB_RAW/clickhouse/config.xml"       -o "$INSTALL_DIR/clickhouse/config.xml"
curl -fsSL "$GITHUB_RAW/clickhouse/schema.sql"       -o "$INSTALL_DIR/clickhouse/schema.sql"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"

    # Generate secrets
    MASTER_KEY=$(openssl rand -base64 32)
    CH_PASSWORD=$(openssl rand -hex 16)

    # Inject into .env (portable sed)
    sed -i.bak "s|^TRACELANE_MASTER_KEY=.*|TRACELANE_MASTER_KEY=${MASTER_KEY}|" "$INSTALL_DIR/.env"
    sed -i.bak "s|^CLICKHOUSE_PASSWORD=.*|CLICKHOUSE_PASSWORD=${CH_PASSWORD}|"   "$INSTALL_DIR/.env"
    rm -f "$INSTALL_DIR/.env.bak"

    yellow "Generated TRACELANE_MASTER_KEY and CLICKHOUSE_PASSWORD → $INSTALL_DIR/.env"
    yellow "Add your provider API key(s) to .env before starting:"
    echo "  ANTHROPIC_API_KEY=sk-ant-..."
    echo "  OPENAI_API_KEY=sk-..."
    echo ""
    read -r -p "Press Enter to continue after editing .env, or Ctrl-C to exit..."
fi

cd "$INSTALL_DIR"
yellow "Starting Tracelane stack..."
$COMPOSE pull --quiet
$COMPOSE up -d

echo ""
green "✓ Tracelane is running!"
echo ""
bold "Endpoint:"
echo "  http://$(hostname -I | awk '{print $1}'):8080/v1/chat/completions"
echo ""
bold "Quick test:"
echo '  curl -s http://localhost:8080/health | jq .'
echo ""
bold "Logs:"
echo "  cd $INSTALL_DIR && docker compose logs -f gateway"
echo ""
bold "Docs:"
echo "  https://tracelane.dev/docs/self-host"
