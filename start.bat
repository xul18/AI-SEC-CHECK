@echo off
chcp 65001 >nul 2>&1
title AI-SEC-CHECK - Start

echo ============================================================
echo   AI-SEC-CHECK v1.0.0 - AI Security Assessment Platform
echo   Based on AI-Infra-Guard by Tencent Zhuque Lab
echo ============================================================
echo.

set "ROOTDIR=%~dp0"
cd /d "%ROOTDIR%"

set "BINARY=ai-sec-check.exe"
set "ADDR=127.0.0.1:8088"

if not exist "%BINARY%" (
    echo [ERROR] %BINARY% not found in current directory.
    echo Please run install.bat first or build the project.
    pause
    exit /b 1
)

if "%1"=="" (
    set "ADDR=127.0.0.1:8088"
) else (
    set "ADDR=%1"
)

echo [INFO] Starting AI-SEC-CHECK on %ADDR% ...
echo [INFO] Web UI: http://%ADDR%
echo [INFO] Press Ctrl+C to stop.
echo.

%BINARY% webserver --server %ADDR%
