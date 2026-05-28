@echo off
chcp 65001 >nul 2>&1
title AI-SEC-CHECK - Install

echo ============================================================
echo   AI-SEC-CHECK v1.0.0 - Installation
echo   All plugins: Go native, zero external dependencies
echo ============================================================
echo.

set "ROOTDIR=%~dp0"
cd /d "%ROOTDIR%"

echo [1/3] Checking main binary ...
if exist "ai-sec-check.exe" (
    echo [OK] ai-sec-check.exe found.
) else (
    echo [ERROR] ai-sec-check.exe not found!
    echo Please build the project first: build.bat
    pause
    exit /b 1
)

echo.
echo [2/3] Checking configuration ...
if exist "configs\config.yaml" (
    echo [OK] configs\config.yaml found.
) else (
    echo [WARN] configs\config.yaml not found, creating default ...
    if not exist "configs" mkdir configs
    (
        echo server:
        echo   addr: "127.0.0.1:8088"
        echo.
        echo plugins:
        echo   sensitive_word:
        echo     enabled: true
        echo     algorithm: "dfa"
        echo   garak:
        echo     enabled: true
        echo   infra_scan:
        echo     enabled: true
        echo   mcpsec:
        echo     enabled: true
        echo   autoswagger:
        echo     enabled: true
        echo   ratelimit:
        echo     enabled: true
        echo.
        echo ai:
        echo   enabled: false
        echo   provider: "openai"
        echo   base_url: ""
        echo   api_key: ""
        echo   model: ""
        echo   fallback_to_template: true
        echo.
        echo database:
        echo   type: "sqlite"
        echo   path: "data\aig.db"
    ) > configs\config.yaml
    echo [OK] Default config created.
)

echo.
echo [3/3] Creating data directories ...
if not exist "data" mkdir data
if not exist "reports" mkdir reports
if not exist "uploads" mkdir uploads
if not exist "logs" mkdir logs
echo [OK] Data directories created.

echo.
echo ============================================================
echo   Installation Complete!
echo.
echo   Quick Start:
echo     start.bat          - Start web server (default: 127.0.0.1:8088)
echo     start.bat 0.0.0.0:9090  - Start on custom address
echo     stop.bat           - Stop the server
echo.
echo   CLI Usage:
echo     ai-sec-check.exe ai status     - Check AI assistant status
echo     ai-sec-check.exe plugins list  - List available plugins
echo     ai-sec-check.exe scan -t URL   - Run infrastructure scan
echo.
echo   Web UI: http://127.0.0.1:8088
echo ============================================================
pause
