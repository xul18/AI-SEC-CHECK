@echo off
chcp 65001 >nul 2>&1
title AI-SEC-CHECK - Stop

echo [INFO] Stopping AI-SEC-CHECK ...

for /f "tokens=5" %%a in ('netstat -aon ^| findstr "8088" ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
    if not errorlevel 1 (
        echo [OK] Process %%a stopped.
    )
)

echo [OK] AI-SEC-CHECK stopped.
