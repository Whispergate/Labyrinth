#!/usr/bin/env bash
# payload-version.sh - Shell wrapper for payload-version.py
#
# Intended for pipeline use where Python invocation details may vary.
# Passes all arguments through and handles common pipeline patterns.
#
# Usage:
#   payload-version.sh --source-dir . --shellcode payload.bin \
#       --obfuscation ollvm-full --flags "-O2" --profile evasive-c \
#       --output manifest.json
#
#   # Version-only mode (prints hash to stdout)
#   VERSION=$(payload-version.sh --source-dir . --shellcode payload.bin --version-only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_SCRIPT="${SCRIPT_DIR}/payload-version.py"

if [ ! -f "$VERSION_SCRIPT" ]; then
    echo "[-] payload-version.py not found at: ${VERSION_SCRIPT}" >&2
    exit 1
fi

# Find a working Python 3
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[-] Python 3 not found" >&2
    exit 1
fi

exec "$PYTHON" "$VERSION_SCRIPT" "$@"
