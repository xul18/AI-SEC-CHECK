#!/bin/bash
# 设置UTF-8编码
export LANG=en_US.UTF-8
# 设置终端标题
printf "\033]0;AI-SEC-CHECK - Stop\007"

echo "[INFO] Stopping AI-SEC-CHECK ..."

# 查找监听8088端口的进程PID
PID=$(lsof -t -i:8088)
if [ -n "$PID" ]; then
    kill -9 "$PID" 2>/dev/null
    echo "[OK] Process $PID stopped."
else
    echo "[WARN] No process listening on port 8088 found."
fi

echo "[OK] AI-SEC-CHECK stopped."
