#!/bin/bash
# Build script for loader-go-garble
# Called by Jenkinsfile with: ./build.sh <output_format> <target_arch> <obfuscation>
set -euo pipefail

OUTPUT_FORMAT="${1:-exe}"
TARGET_ARCH="${2:-amd64}"
OBFUSCATION="${3:-none}"

GOARCH="amd64"
[ "$TARGET_ARCH" = "arm64" ] && GOARCH="arm64"

GOOS=windows GOARCH=${GOARCH} \
garble -literals -tiny build \
    -o "loader.${OUTPUT_FORMAT}" -ldflags="-s -w" \
    ./cmd/loader

echo "[+] Built loader.${OUTPUT_FORMAT} (${TARGET_ARCH}, toolchain: garble)"
