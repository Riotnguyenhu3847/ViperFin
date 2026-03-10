#!/bin/bash
# Build script for viperfin
# Produces binaries for Linux (Kali) and Windows

set -e

BINARY="viperfin"
VERSION="1.0.0"
BUILD_DIR="./build"

echo "Building viperfin v${VERSION}..."
mkdir -p "$BUILD_DIR"

# Linux (Kali native)
echo "[1/2] Building Linux amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o "${BUILD_DIR}/${BINARY}-linux-amd64" .
echo "      -> ${BUILD_DIR}/${BINARY}-linux-amd64"

# Windows
echo "[2/2] Building Windows amd64..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o "${BUILD_DIR}/${BINARY}-windows-amd64.exe" .
echo "      -> ${BUILD_DIR}/${BINARY}-windows-amd64.exe"

echo ""
echo "Done. Binaries in ${BUILD_DIR}/"
echo ""
echo "Quick test (Linux):"
echo "  ./${BUILD_DIR}/${BINARY}-linux-amd64 client google.com:443"
echo "  ./${BUILD_DIR}/${BINARY}-linux-amd64 server --port 4443"
echo "  ./${BUILD_DIR}/${BINARY}-linux-amd64 lookup --list"
