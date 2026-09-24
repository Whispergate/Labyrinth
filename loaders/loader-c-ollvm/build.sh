#!/bin/bash
# Build script for loader-c-ollvm
# Called by Jenkinsfile with: ./build.sh <output_format> <target_arch> <obfuscation>
set -euo pipefail

OUTPUT_FORMAT="${1:-exe}"
TARGET_ARCH="${2:-amd64}"
OBFUSCATION="${3:-none}"

EXT="${OUTPUT_FORMAT}"
SHARED_FLAG=""
[ "$OUTPUT_FORMAT" = "dll" ] && SHARED_FLAG="-shared"

GCC_PREFIX="x86_64-w64-mingw32"
CLANG_TARGET="x86_64-w64-mingw32"
[ "$TARGET_ARCH" = "arm64" ] && GCC_PREFIX="aarch64-w64-mingw32" && CLANG_TARGET="aarch64-w64-mingw32"

OLLVM_FLAGS=""
if [[ "$OBFUSCATION" == ollvm* ]]; then
    if [ -f /opt/ollvm/lib/libOLLVMPipeline.so ]; then
        OLLVM_FLAGS="-fpass-plugin=/opt/ollvm/lib/libOLLVMPipeline.so"
    else
        echo "[!] WARNING: OLLVM pass plugin not found - building without obfuscation"
    fi
fi

SOURCES=$(find src -name '*.c' | sort | tr '\n' ' ')
ASM_SOURCES=$(find src -name '*.S' | sort | tr '\n' ' ')

rm -f *.o
mkdir -p obj && rm -f obj/*.o

clang --target=${CLANG_TARGET} ${OLLVM_FLAGS} \
    -c ${SOURCES} ${ASM_SOURCES} -Isrc -O1
mv *.o obj/

${GCC_PREFIX}-gcc -o "loader.${EXT}" \
    obj/*.o ${SHARED_FLAG} \
    -lntdll -lkernel32 -s

echo "[+] Built loader.${EXT} (${TARGET_ARCH}, toolchain: clang+${GCC_PREFIX}-gcc)"
