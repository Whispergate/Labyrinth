#!/usr/bin/env python3
"""
Generate payload version hash and build manifest from build inputs.

Produces a deterministic version ID from the combination of source commit,
shellcode content, obfuscation profile, and build flags. This ensures
identical inputs always produce the same version string, enabling
deduplication and reliable rollback.

Usage:
    payload-version.py --source-dir . --shellcode payload.bin \
        --obfuscation ollvm-full --flags "-O2" --profile evasive-c \
        --output manifest.json
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys


def file_hash(path):
    """SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except FileNotFoundError:
        return None
    return h.hexdigest()


def git_commit(source_dir):
    """Get the current git HEAD commit in source_dir."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "unknown"


def compute_version(source_dir, shellcode_file, obfuscation, build_flags):
    """
    Deterministic version hash from build inputs.

    Hash of (source commit + shellcode hash + obfuscation + flags).
    Returns the first 12 hex characters.
    """
    h = hashlib.sha256()

    # Source commit
    commit = git_commit(source_dir)
    h.update(commit.encode("utf-8"))

    # Shellcode file hash
    sc_hash = file_hash(shellcode_file)
    if sc_hash:
        h.update(sc_hash.encode("utf-8"))
    else:
        h.update(b"no-shellcode")

    # Obfuscation profile name
    h.update((obfuscation or "none").encode("utf-8"))

    # Build flags string
    h.update((build_flags or "").encode("utf-8"))

    return h.hexdigest()[:12]


def create_manifest(version, **kwargs):
    """Create build manifest dictionary."""
    return {
        "version": version,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source_commit": kwargs.get("commit"),
        "shellcode_hash": kwargs.get("sc_hash"),
        "obfuscation": kwargs.get("obfuscation"),
        "build_flags": kwargs.get("flags"),
        "profile": kwargs.get("profile"),
        "pe_hash": kwargs.get("pe_hash"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate payload version hash and build manifest"
    )
    parser.add_argument(
        "--source-dir",
        default=".",
        help="Path to source directory (for git commit)",
    )
    parser.add_argument(
        "--shellcode",
        default="shellcode/payload.bin",
        help="Path to shellcode binary",
    )
    parser.add_argument(
        "--obfuscation",
        default="none",
        help="Obfuscation profile name",
    )
    parser.add_argument(
        "--flags",
        default="",
        help="Build flags string",
    )
    parser.add_argument(
        "--profile",
        default="",
        help="Build profile name from build-profiles.yml",
    )
    parser.add_argument(
        "--pe-file",
        default="",
        help="Path to final PE file (for output hash)",
    )
    parser.add_argument(
        "--output",
        default="manifest.json",
        help="Output manifest file path",
    )
    parser.add_argument(
        "--version-only",
        action="store_true",
        help="Print only the version hash, no manifest",
    )

    args = parser.parse_args()

    # Compute version
    version = compute_version(
        args.source_dir, args.shellcode, args.obfuscation, args.flags
    )

    if args.version_only:
        print(version)
        return

    # Gather metadata
    commit = git_commit(args.source_dir)
    sc_hash = file_hash(args.shellcode)
    pe_hash = file_hash(args.pe_file) if args.pe_file else None

    manifest = create_manifest(
        version,
        commit=commit,
        sc_hash=sc_hash,
        obfuscation=args.obfuscation,
        flags=args.flags,
        profile=args.profile,
        pe_hash=pe_hash,
    )

    # Write manifest
    with open(args.output, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Version: {version}")
    print(f"[+] Manifest written to: {args.output}")


if __name__ == "__main__":
    main()
