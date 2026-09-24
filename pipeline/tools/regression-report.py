#!/usr/bin/env python3
"""
Regression report generator for MAAS pipeline.

Compares current LitterBox scan results against a stored baseline and produces
a markdown report showing per-profile detection deltas.

Exit codes:
    0  All profiles within threshold (or no baseline to compare)
    1  One or more profiles regressed beyond the allowed threshold
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def load_json(path):
    """Load and return parsed JSON from a file path."""
    with open(path, "r") as f:
        return json.load(f)


def get_detection_count(profile_data):
    """Extract the detection count from a profile result, handling key variants."""
    if isinstance(profile_data, dict):
        for key in ("detections", "detection_count", "count"):
            if key in profile_data:
                try:
                    return int(profile_data[key])
                except (ValueError, TypeError):
                    pass
    return 0


def compare_profiles(baseline, current, threshold):
    """
    Compare baseline and current results profile by profile.

    Returns a list of dicts, one per profile, each containing:
        profile, baseline_detections, current_detections, delta, status
    Also returns a boolean indicating whether any regression was found.
    """
    baseline_profiles = baseline.get("profiles", {})
    current_profiles = current.get("profiles", {})

    all_profile_names = sorted(
        set(list(baseline_profiles.keys()) + list(current_profiles.keys()))
    )

    rows = []
    has_regressions = False

    for name in all_profile_names:
        bp = baseline_profiles.get(name, {})
        cp = current_profiles.get(name, {})

        # Skip profiles that were skipped in both runs
        if bp.get("skipped") and cp.get("skipped"):
            continue

        baseline_det = get_detection_count(bp)
        current_det = get_detection_count(cp)
        delta = current_det - baseline_det

        if name not in baseline_profiles:
            status = "NEW"
        elif name not in current_profiles:
            status = "REMOVED"
        elif cp.get("skipped"):
            status = "SKIPPED"
        elif delta > threshold:
            status = "REGRESSED"
            has_regressions = True
        elif delta < 0:
            status = "IMPROVED"
        else:
            status = "PASS"

        rows.append({
            "profile": name,
            "baseline_detections": baseline_det,
            "current_detections": current_det,
            "delta": delta,
            "status": status,
        })

    return rows, has_regressions


def format_markdown_report(rows, threshold, baseline_meta, current_meta):
    """Render the comparison as a markdown table with summary."""
    lines = []
    lines.append("# Regression Test Report")
    lines.append("")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"**Generated:** {ts}")
    lines.append(f"**Threshold:** +{threshold} detections")
    if baseline_meta.get("build_number"):
        lines.append(f"**Baseline build:** #{baseline_meta['build_number']}")
    if current_meta.get("build_number"):
        lines.append(f"**Current build:** #{current_meta['build_number']}")
    lines.append("")

    # Summary counts
    statuses = [r["status"] for r in rows]
    passed = statuses.count("PASS")
    improved = statuses.count("IMPROVED")
    regressed = statuses.count("REGRESSED")
    new_profiles = statuses.count("NEW")

    if regressed > 0:
        lines.append(f"**Result: FAILED** - {regressed} profile(s) regressed")
    else:
        lines.append("**Result: PASSED** - all profiles within threshold")
    lines.append("")

    lines.append(f"| Passed | Improved | Regressed | New |")
    lines.append(f"|--------|----------|-----------|-----|")
    lines.append(f"| {passed} | {improved} | {regressed} | {new_profiles} |")
    lines.append("")

    # Detail table
    lines.append("## Per-Profile Results")
    lines.append("")
    lines.append("| Profile | Baseline | Current | Delta | Status |")
    lines.append("|---------|----------|---------|-------|--------|")

    for r in rows:
        delta_str = f"+{r['delta']}" if r["delta"] > 0 else str(r["delta"])
        status_marker = ""
        if r["status"] == "REGRESSED":
            status_marker = " :x:"
        elif r["status"] == "IMPROVED":
            status_marker = " :white_check_mark:"

        lines.append(
            f"| {r['profile']} "
            f"| {r['baseline_detections']} "
            f"| {r['current_detections']} "
            f"| {delta_str} "
            f"| {r['status']}{status_marker} |"
        )

    lines.append("")

    # Show regressed details if any
    regressed_rows = [r for r in rows if r["status"] == "REGRESSED"]
    if regressed_rows:
        lines.append("## Regressions")
        lines.append("")
        for r in regressed_rows:
            lines.append(
                f"- **{r['profile']}**: {r['baseline_detections']} -> "
                f"{r['current_detections']} (+{r['delta']}, "
                f"threshold was +{threshold})"
            )
        lines.append("")

    # Show improvements
    improved_rows = [r for r in rows if r["status"] == "IMPROVED"]
    if improved_rows:
        lines.append("## Improvements")
        lines.append("")
        for r in improved_rows:
            lines.append(
                f"- **{r['profile']}**: {r['baseline_detections']} -> "
                f"{r['current_detections']} ({r['delta']})"
            )
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Compare LitterBox scan results against a regression baseline"
    )
    parser.add_argument(
        "--baseline", required=True,
        help="Path to baseline JSON file"
    )
    parser.add_argument(
        "--current", required=True,
        help="Path to current results JSON file"
    )
    parser.add_argument(
        "--threshold", type=int, default=2,
        help="Max allowed detection increase before flagging regression (default: 2)"
    )
    parser.add_argument(
        "--output", default="regression-report.md",
        help="Output path for the markdown report (default: regression-report.md)"
    )
    parser.add_argument(
        "--json-output", default="regression-comparison.json",
        help="Output path for the structured JSON comparison (default: regression-comparison.json)"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.baseline):
        print(f"[!] Baseline file not found: {args.baseline}", file=sys.stderr)
        print("[!] Run the pipeline with UPDATE_BASELINE=true to create one.", file=sys.stderr)
        sys.exit(0)

    if not os.path.isfile(args.current):
        print(f"[!] Current results file not found: {args.current}", file=sys.stderr)
        sys.exit(1)

    baseline = load_json(args.baseline)
    current = load_json(args.current)

    rows, has_regressions = compare_profiles(baseline, current, args.threshold)

    # Write markdown report
    report = format_markdown_report(
        rows, args.threshold,
        baseline_meta=baseline,
        current_meta=current,
    )
    with open(args.output, "w") as f:
        f.write(report)
    print(f"[+] Markdown report written to {args.output}")

    # Write structured JSON
    regressions = [r for r in rows if r["status"] == "REGRESSED"]
    comparison = {
        "has_regressions": has_regressions,
        "threshold": args.threshold,
        "total_profiles": len(rows),
        "passed": sum(1 for r in rows if r["status"] == "PASS"),
        "improved": sum(1 for r in rows if r["status"] == "IMPROVED"),
        "regressed": len(regressions),
        "regressions": regressions,
        "profiles": rows,
    }
    with open(args.json_output, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"[+] JSON comparison written to {args.json_output}")

    if has_regressions:
        print(f"\n[!] REGRESSION DETECTED in {len(regressions)} profile(s):", file=sys.stderr)
        for r in regressions:
            print(
                f"    {r['profile']}: {r['baseline_detections']} -> "
                f"{r['current_detections']} (+{r['delta']})",
                file=sys.stderr,
            )
        sys.exit(1)
    else:
        print(f"\n[+] All {len(rows)} profiles within threshold (+{args.threshold})")
        sys.exit(0)


if __name__ == "__main__":
    main()
