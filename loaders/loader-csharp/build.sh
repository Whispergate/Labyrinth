#!/bin/bash
# Build script for loader-csharp
# Called by Jenkinsfile with: ./build.sh <output_format> <target_arch> <obfuscation>
set -euo pipefail

OUTPUT_FORMAT="${1:-exe}"
TARGET_ARCH="${2:-amd64}"
OBFUSCATION="${3:-none}"

RID="win-x64"
[ "$TARGET_ARCH" = "arm64" ] && RID="win-arm64"

dotnet publish src/Loader.csproj \
    -c Release -r "${RID}" \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:PublishTrimmed=true \
    -o .

mv loader "loader.${OUTPUT_FORMAT}" 2>/dev/null || true

echo "[+] Built loader.${OUTPUT_FORMAT} (${TARGET_ARCH}, toolchain: dotnet, rid: ${RID})"
