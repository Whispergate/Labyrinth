#!/bin/bash
# Build script for loader-rust
# Called by Jenkinsfile with: ./build.sh <output_format> <target_arch> <obfuscation>
set -euo pipefail

OUTPUT_FORMAT="${1:-exe}"
TARGET_ARCH="${2:-amd64}"
OBFUSCATION="${3:-none}"

RUST_TARGET="x86_64-pc-windows-gnu"
[ "$TARGET_ARCH" = "arm64" ] && RUST_TARGET="aarch64-pc-windows-gnullvm"

cargo build --release --target "${RUST_TARGET}"
cp "target/${RUST_TARGET}/release/loader.exe" "loader.${OUTPUT_FORMAT}"

echo "[+] Built loader.${OUTPUT_FORMAT} (${TARGET_ARCH}, toolchain: cargo, target: ${RUST_TARGET})"
