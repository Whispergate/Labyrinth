#!/bin/bash
# Build script for loader-c-mingw
# Called by Jenkinsfile with: ./build.sh <output_format> <target_arch> <obfuscation>
set -euo pipefail

OUTPUT_FORMAT="${1:-exe}"
TARGET_ARCH="${2:-amd64}"
OBFUSCATION="${3:-none}"

EXT="${OUTPUT_FORMAT}"
SHARED_FLAG=""
[ "$OUTPUT_FORMAT" = "dll" ] && SHARED_FLAG="-shared"

PREFIX="x86_64-w64-mingw32"
[ "$TARGET_ARCH" = "arm64" ] && PREFIX="aarch64-w64-mingw32"

SOURCES=$(find src -name '*.c' -o -name '*.S' | sort | tr '\n' ' ')

${PREFIX}-gcc -o "loader.${EXT}" \
    ${SOURCES} \
    -Isrc ${SHARED_FLAG} \
    -lntdll -lkernel32 -mwindows -s -O2

echo "[+] Built loader.${EXT} (${TARGET_ARCH}, toolchain: ${PREFIX}-gcc)"
