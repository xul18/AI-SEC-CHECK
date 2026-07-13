@echo off
chcp 65001 >nul 2>&1
title AI-SEC-CHECK - Build

echo ============================================================
echo   AI-SEC-CHECK v1.0.5 - Build Script
echo   All plugins: Go native, zero external dependencies
echo ============================================================
echo.

set "VERSION=v1.0.5"
set "BINARY=ai-sec-check.exe"
set "LDFLAGS=-X ai-sec-check/internal/options.version=%VERSION% -s -w"

echo [1/4] Checking Go environment ...
go version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go is not installed or not in PATH.
    echo        Download from: https://go.dev/dl/
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('go version') do echo [OK] %%v

echo.
echo [2/4] Building static binary (CGO_ENABLED=0) ...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags "%LDFLAGS%" -o %BINARY% ./cmd/cli
if errorlevel 1 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
echo [OK] Build successful.

for %%A in (%BINARY%) do echo       Size: %%~zA bytes

echo.
echo [3/4] Creating distribution package ...
if exist "dist" rmdir /s /q "dist"
mkdir "dist\ai-sec-check"

copy %BINARY% "dist\ai-sec-check\" >nul
echo [OK] Binary copied.

xcopy configs "dist\ai-sec-check\configs\" /E /I /Y >nul 2>&1
echo [OK] Configs copied.

xcopy data "dist\ai-sec-check\data\" /E /I /Y >nul 2>&1
echo [OK] Data files copied.

copy start.bat "dist\ai-sec-check\" >nul
copy stop.bat "dist\ai-sec-check\" >nul
copy install.bat "dist\ai-sec-check\" >nul
echo [OK] Batch scripts copied.

if exist "trpc_go.yaml" (
    copy trpc_go.yaml "dist\ai-sec-check\" >nul
    echo [OK] trpc_go.yaml copied.
)

if exist "LICENSE" (
    copy LICENSE "dist\ai-sec-check\" >nul
    echo [OK] License copied.
)

if exist "NOTICE" (
    copy NOTICE "dist\ai-sec-check\" >nul
    echo [OK] Notice copied.
)

echo.
echo [4/4] Creating ZIP archive ...
powershell -Command "Compress-Archive -Path 'dist\ai-sec-check' -DestinationPath 'dist\ai-sec-check-%VERSION%-windows-amd64.zip' -Force"
if errorlevel 1 (
    echo [WARN] ZIP creation failed. Package is available at dist\ai-sec-check\
) else (
    echo [OK] ZIP created: dist\ai-sec-check-%VERSION%-windows-amd64.zip
)

echo.
echo ============================================================
echo   Build Complete!
echo.
echo   Binary:     %BINARY%
echo   Package:    dist\ai-sec-check\
echo   Archive:    dist\ai-sec-check-%VERSION%-windows-amd64.zip
echo.
echo   To deploy: Copy dist\ai-sec-check\ to target machine,
echo              then run install.bat
echo ============================================================
pause
