#!/bin/bash
export LANG=en_US.UTF-8
printf "\033]0;AI-SEC-CHECK - Install\007"

echo "============================================================"
echo "  AI-SEC-CHECK v1.0.0 - Installation"
echo "  All plugins: Go native, zero external dependencies"
echo "============================================================"
echo ""

# 获取脚本所在目录，切换到根目录
ROOTDIR=$(cd "$(dirname "$0")" && pwd)
cd "${ROOTDIR}" || exit 1

echo "[1/3] Checking main binary ..."
if [ -f "./ai-sec-check" ]; then
    echo "[OK] ai-sec-check found."
else
    echo "[ERROR] ai-sec-check not found!"
    echo "Please build the project first: ./build.sh"
    read -p "Press Enter to exit..."
    exit 1
fi

echo ""
echo "[2/3] Checking configuration ..."
if [ -f "configs/config.yaml" ]; then
    echo "[OK] configs/config.yaml found."
else
    echo "[WARN] configs/config.yaml not found, creating default ..."
    mkdir -p configs
    cat > configs/config.yaml <<EOF
server:
  addr: "127.0.0.1:8088"

plugins:
  sensitive_word:
    enabled: true
    algorithm: "dfa"
  garak:
    enabled: true
  infra_scan:
    enabled: true
  mcpsec:
    enabled: true
  autoswagger:
    enabled: true
  ratelimit:
    enabled: true

ai:
  enabled: false
  provider: "openai"
  base_url: ""
  api_key: ""
  model: ""
  fallback_to_template: true

database:
  type: "sqlite"
  path: "data/aig.db"
EOF
    echo "[OK] Default config created."
fi

echo ""
echo "[3/3] Creating data directories ..."
mkdir -p data reports uploads logs
echo "[OK] Data directories created."

echo ""
echo "============================================================"
echo "  Installation Complete!"
echo ""
echo "  Quick Start:"
echo "    ./start.sh          - Start web server (default: 127.0.0.1:8088)"
echo "    ./start.sh 0.0.0.0:9090  - Start on custom address"
echo "    ./stop.sh           - Stop the server"
echo ""
echo "  CLI Usage:"
echo "    ./ai-sec-check ai status     - Check AI assistant status"
echo "    ./ai-sec-check plugins list  - List available plugins"
echo "    ./ai-sec-check scan -t URL   - Run infrastructure scan"
echo ""
echo "  Web UI: http://127.0.0.1:8088"
echo "============================================================"
read -p "Press Enter to exit..."
