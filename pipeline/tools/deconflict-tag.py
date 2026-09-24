#!/usr/bin/env python3
"""Embed deconfliction tags in PE metadata for operator attribution.

Tags are appended as a PE overlay (after the last section), which does
not affect execution.  Each tag contains the operator ID, campaign name,
timestamp, and a truncated SHA-256 hash for quick verification.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import time

MARKER_START = b"MAAS_TAG_START"
MARKER_END = b"MAAS_TAG_END"


def generate_tag(operator_id, campaign, timestamp=None):
    """Generate a unique deconfliction tag."""
    ts = timestamp or int(time.time())
    raw = f"{operator_id}:{campaign}:{ts}"
    tag_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return {
        "operator": operator_id,
        "campaign": campaign,
        "timestamp": ts,
        "tag": tag_hash,
        "full": raw,
    }


def embed_pe_trailer(pe_path, tag_data):
    """Append tag as a PE overlay (after the last section).

    The overlay data does not affect execution.
    Format: MAAS_TAG_START + JSON + MAAS_TAG_END
    """
    # Validate the file exists and looks like a PE
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(f"File not found: {pe_path}")

    with open(pe_path, "rb") as f:
        magic = f.read(2)
    if magic != b"MZ":
        raise ValueError(f"Not a valid PE file (bad MZ magic): {pe_path}")

    # Strip any existing tag first
    strip_pe_tag(pe_path)

    payload = MARKER_START + json.dumps(tag_data, separators=(",", ":")).encode() + MARKER_END

    with open(pe_path, "ab") as f:
        f.write(payload)

    return len(payload)


def read_pe_tag(pe_path):
    """Read deconfliction tag from PE overlay.

    Returns the tag dict if found, or None if no tag is present.
    """
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(f"File not found: {pe_path}")

    with open(pe_path, "rb") as f:
        data = f.read()

    start = data.find(MARKER_START)
    end = data.find(MARKER_END)
    if start == -1 or end == -1:
        return None

    tag_json = data[start + len(MARKER_START):end]
    try:
        return json.loads(tag_json)
    except json.JSONDecodeError:
        return None


def strip_pe_tag(pe_path):
    """Remove existing deconfliction tag from PE overlay."""
    if not os.path.isfile(pe_path):
        return False

    with open(pe_path, "rb") as f:
        data = f.read()

    start = data.find(MARKER_START)
    if start == -1:
        return False

    # Find the end marker after the start marker
    end = data.find(MARKER_END, start)
    if end == -1:
        # Malformed tag - truncate at start marker
        with open(pe_path, "wb") as f:
            f.write(data[:start])
        return True

    # Remove the tag (start marker through end marker inclusive)
    cleaned = data[:start] + data[end + len(MARKER_END):]
    with open(pe_path, "wb") as f:
        f.write(cleaned)
    return True


def verify_tag(pe_path, operator_id=None, campaign=None):
    """Verify deconfliction tag matches expected values.

    Returns (success: bool, message: str, tag_data: dict or None).
    """
    tag = read_pe_tag(pe_path)
    if tag is None:
        return False, "No deconfliction tag found", None

    # Re-derive hash to verify integrity
    raw = f"{tag['operator']}:{tag['campaign']}:{tag['timestamp']}"
    expected_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
    if tag.get("tag") != expected_hash:
        return False, "Tag integrity check failed (hash mismatch)", tag

    # Check operator match if specified
    if operator_id and tag.get("operator") != operator_id:
        return False, f"Operator mismatch: expected '{operator_id}', got '{tag.get('operator')}'", tag

    # Check campaign match if specified
    if campaign and tag.get("campaign") != campaign:
        return False, f"Campaign mismatch: expected '{campaign}', got '{tag.get('campaign')}'", tag

    return True, "Tag verified OK", tag


def format_tag(tag):
    """Format tag data for display."""
    lines = []
    lines.append(f"  Operator:  {tag.get('operator', 'N/A')}")
    lines.append(f"  Campaign:  {tag.get('campaign', 'N/A')}")
    ts = tag.get("timestamp")
    if ts:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        lines.append(f"  Timestamp: {dt.isoformat()} ({ts})")
    else:
        lines.append(f"  Timestamp: N/A")
    lines.append(f"  Tag Hash:  {tag.get('tag', 'N/A')}")
    lines.append(f"  Raw:       {tag.get('full', 'N/A')}")
    return "\n".join(lines)


def cmd_tag(args):
    """Tag subcommand: embed a deconfliction tag in a PE file."""
    tag_data = generate_tag(args.operator, args.campaign)
    size = embed_pe_trailer(args.input, tag_data)
    print(f"[+] Tagged {args.input}")
    print(format_tag(tag_data))
    print(f"  Overlay:   {size} bytes appended")

    if args.output and args.output != args.input:
        import shutil
        shutil.copy2(args.input, args.output)
        print(f"[+] Copied to {args.output}")


def cmd_read(args):
    """Read subcommand: read deconfliction tag from a PE file."""
    tag = read_pe_tag(args.input)
    if tag is None:
        print(f"[-] No deconfliction tag found in {args.input}")
        sys.exit(1)
    else:
        print(f"[+] Tag found in {args.input}")
        print(format_tag(tag))

        if args.json:
            print(f"\n  JSON: {json.dumps(tag)}")


def cmd_verify(args):
    """Verify subcommand: verify tag matches expected values."""
    success, message, tag = verify_tag(args.input, args.operator, args.campaign)
    if success:
        print(f"[+] {message}")
        print(format_tag(tag))
    else:
        print(f"[-] {message}")
        if tag:
            print(format_tag(tag))
        sys.exit(1)


def cmd_strip(args):
    """Strip subcommand: remove deconfliction tag from a PE file."""
    if strip_pe_tag(args.input):
        print(f"[+] Tag removed from {args.input}")
    else:
        print(f"[*] No tag found in {args.input}")


def main():
    parser = argparse.ArgumentParser(
        description="Embed deconfliction tags in PE metadata for operator attribution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s tag --input loader.exe --operator ALPHA --campaign EXERCISE-2024
  %(prog)s read --input loader.exe
  %(prog)s read --input loader.exe --json
  %(prog)s verify --input loader.exe --operator ALPHA
  %(prog)s verify --input loader.exe --operator ALPHA --campaign EXERCISE-2024
  %(prog)s strip --input loader.exe
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # tag subcommand
    tag_parser = subparsers.add_parser("tag", help="Embed a deconfliction tag in a PE file")
    tag_parser.add_argument("--input", "-i", required=True, help="Path to PE file")
    tag_parser.add_argument("--operator", required=True, help="Operator callsign/ID")
    tag_parser.add_argument("--campaign", required=True, help="Campaign tag")
    tag_parser.add_argument("--output", "-o", help="Output path (default: tag in-place)")

    # read subcommand
    read_parser = subparsers.add_parser("read", help="Read deconfliction tag from a PE file")
    read_parser.add_argument("--input", "-i", required=True, help="Path to PE file")
    read_parser.add_argument("--json", action="store_true", help="Also print raw JSON")

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify tag matches expected values")
    verify_parser.add_argument("--input", "-i", required=True, help="Path to PE file")
    verify_parser.add_argument("--operator", help="Expected operator ID")
    verify_parser.add_argument("--campaign", help="Expected campaign tag")

    # strip subcommand
    strip_parser = subparsers.add_parser("strip", help="Remove deconfliction tag from a PE file")
    strip_parser.add_argument("--input", "-i", required=True, help="Path to PE file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "tag": cmd_tag,
        "read": cmd_read,
        "verify": cmd_verify,
        "strip": cmd_strip,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
