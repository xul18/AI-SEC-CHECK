#!/bin/bash
# 编码设置、窗口标题（Kali/bash 终端）
export LANG=en_US.UTF-8
printf "\033]0;AI-SEC-CHECK - Start\007"

echo "============================================================"
echo "  AI-SEC-CHECK v1.0.0 - AI Security Assessment Platform"
echo "  Based on AI-Infra-Guard by Tencent Zhuque Lab"
echo "============================================================"
echo ""

BINARY="./ai-sec-check"
ADDR="127.0.0.1:8088"

# 判断程序是否存在
if [ ! -f "${BINARY}" ]; then
    echo "[ERROR] ${BINARY} not found in current directory."
    echo "Please run install.sh first or build the project."
    read -p "Press Enter to exit..."
    exit 1
fi

# 接收传参，不传则使用默认地址
if [ -n "$1" ]; then
    ADDR="$1"
fi

echo "[INFO] Starting AI-SEC-CHECK on ${ADDR} ..."
echo "[INFO] Web UI: http://${ADDR}"
echo "[INFO] Press Ctrl+C to stop."
echo ""

# 启动服务
${BINARY} webserver --server "${ADDR}"
