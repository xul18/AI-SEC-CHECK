#!/bin/bash
# AI-SEC-CHECK Linux Build Script
set -euo pipefail

# 配置参数，和Windows脚本保持一致
VERSION="v1.0.5"
BINARY="ai-sec-check"
LDFLAGS="-X ai-sec-check/internal/options.version=${VERSION} -s -w"

echo "============================================================"
echo "  AI-SEC-CHECK ${VERSION} - Build Script (Linux amd64)"
echo "  All plugins: Go native, zero external dependencies"
echo "============================================================"
echo ""

# [1/4] 检查Go环境
echo "[1/4] Checking Go environment ..."
if ! command -v go &> /dev/null; then
    echo "[ERROR] Go is not installed or not in PATH."
    echo "        Download from: https://go.dev/dl/"
    read -p "Press Enter to exit..."
    exit 1
fi
go_version=$(go version)
echo "[OK] ${go_version}"

echo ""
# [2/4] 静态编译 CGO_ENABLED=0 linux amd64
echo "[2/4] Building static binary (CGO_ENABLED=0) ..."
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

go build -ldflags "${LDFLAGS}" -o "${BINARY}" ./cmd/cli

echo "[OK] Build successful."
bin_size=$(du -b "${BINARY}" | awk '{print $1}')
echo "      Size: ${bin_size} bytes"

echo ""
# [3/4] 构建dist分发目录
echo "[3/4] Creating distribution package ..."
rm -rf dist
mkdir -p dist/ai-sec-check

# 复制主程序
cp "${BINARY}" dist/ai-sec-check/
echo "[OK] Binary copied."

# 复制配置、数据目录
cp -r configs dist/ai-sec-check/configs
echo "[OK] Configs copied."
cp -r data dist/ai-sec-check/data
echo "[OK] Data files copied."

# 复制部署脚本
cp start.sh stop.sh install.sh dist/ai-sec-check/
echo "[OK] Shell scripts copied."

# 复制配置文件
[ -f "trpc_go.yaml" ] && cp trpc_go.yaml dist/ai-sec-check/ && echo "[OK] trpc_go.yaml copied."
[ -f "LICENSE" ] && cp LICENSE dist/ai-sec-check/ && echo "[OK] License copied."
[ -f "NOTICE" ] && cp NOTICE dist/ai-sec-check/ && echo "[OK] Notice copied."

echo ""
# [4/4] 生成zip压缩包
echo "[4/4] Creating ZIP archive ..."
zip_file="dist/ai-sec-check-${VERSION}-linux-amd64.zip"
# 使用 zip 命令打包，没有zip则告警
if command -v zip &> /dev/null; then
    cd dist && zip -r "${zip_file#dist/}" ai-sec-check/ > /dev/null && cd ..
    echo "[OK] ZIP created: ${zip_file}"
else
    echo "[WARN] zip command not found, skip archive."
    echo "       Raw package dir: dist/ai-sec-check/"
fi

echo ""
echo "============================================================"
echo "  Build Complete!"
echo ""
echo "  Binary:     ./${BINARY}"
echo "  Package:    dist/ai-sec-check/"
echo "  Archive:    ${zip_file}"
echo ""
echo "  To deploy: Copy dist/ai-sec-check/ to target machine,"
echo "              chmod +x ./ai-sec-check && run service"
echo "============================================================"
read -p "Press Enter to exit..."
