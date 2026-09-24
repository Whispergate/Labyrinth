#!/usr/bin/env python3
"""
Track payload shelf life - time from build to first detection.

Maintains a JSON database of payload builds and their scan history over time.
Records when each AV engine first detects each payload variant, enabling
shelf-life analysis across build profiles.

Usage:
    # Register a new payload build
    shelf-life.py register --version abc123 --profile evasive-c \
                           --build-time "2024-01-01T00:00:00"

    # Record a LitterBox scan result
    shelf-life.py scan --version abc123 --results scan.json

    # Generate shelf-life reports
    shelf-life.py report --output shelf-life-report.json
    shelf-life.py report --format markdown --output shelf-life-report.md

    # Show status of a specific payload
    shelf-life.py status --version abc123

    # List all tracked payloads
    shelf-life.py list
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

DEFAULT_DB_PATH = os.path.join("payloads", "shelf-life", "shelf-life.json")


class ShelfLifeTracker:
    """Track payload shelf life from build to first detection."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db = self._load_db()

    def _load_db(self):
        """Load or initialise the shelf-life database."""
        if os.path.exists(self.db_path):
            with open(self.db_path) as f:
                return json.load(f)
        return {
            "version": 1,
            "payloads": {},
            "metadata": {
                "created": datetime.utcnow().isoformat() + "Z",
                "last_updated": None,
            },
        }

    def save(self):
        """Persist the database to disk."""
        self.db["metadata"]["last_updated"] = datetime.utcnow().isoformat() + "Z"
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with open(self.db_path, 'w') as f:
            json.dump(self.db, f, indent=2)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_payload(self, version_hash, profile, build_time, notes=None):
        """Register a new payload build.

        Args:
            version_hash: Unique identifier for this build (e.g. git short hash).
            profile: Build profile name (e.g. 'evasive-c', 'loader-go-garble').
            build_time: ISO-8601 build timestamp.
            notes: Optional free-text notes.
        """
        if version_hash in self.db["payloads"]:
            print(f"Warning: payload {version_hash} already registered. Skipping.",
                  file=sys.stderr)
            return False

        self.db["payloads"][version_hash] = {
            "profile": profile,
            "build_time": build_time,
            "notes": notes or "",
            "first_seen": {},       # engine_name -> timestamp of first detection
            "scan_history": [],     # list of scan records
            "shelf_life_days": None,  # days from build to first ANY detection
            "status": "clean",      # clean | detected | burned
        }
        return True

    # ------------------------------------------------------------------
    # Scan Recording
    # ------------------------------------------------------------------

    def record_scan(self, version_hash, scan_time=None, results=None,
                    results_file=None):
        """Record a LitterBox scan result.

        Args:
            version_hash: Payload identifier.
            scan_time: ISO-8601 timestamp of the scan (default: now).
            results: Dict of {engine_name: detected_bool} or
                     {engine_name: {"detected": bool, "result": str}}.
            results_file: Path to LitterBox JSON results file (alternative to results).
        """
        payload = self.db["payloads"].get(version_hash)
        if not payload:
            print(f"Error: payload {version_hash} not registered.", file=sys.stderr)
            return False

        if scan_time is None:
            scan_time = datetime.utcnow().isoformat() + "Z"

        if results_file:
            results = self._parse_scan_file(results_file)
        if results is None:
            print("Error: provide either --results or --results-file.", file=sys.stderr)
            return False

        # Normalise results to {engine: bool}
        normalised = {}
        for engine, value in results.items():
            if isinstance(value, dict):
                normalised[engine] = bool(value.get("detected", False))
            elif isinstance(value, bool):
                normalised[engine] = value
            elif isinstance(value, str):
                normalised[engine] = bool(value)
            else:
                normalised[engine] = bool(value)

        detecting_engines = {e for e, v in normalised.items() if v}
        total_engines = len(normalised)

        # Append to scan history
        payload["scan_history"].append({
            "time": scan_time,
            "total_engines": total_engines,
            "detections": len(detecting_engines),
            "detection_rate": round(
                100.0 * len(detecting_engines) / max(total_engines, 1), 1
            ),
            "detecting_engines": sorted(detecting_engines),
        })

        # Update first_seen for newly detecting engines
        newly_detected = []
        for engine in detecting_engines:
            if engine not in payload["first_seen"]:
                payload["first_seen"][engine] = scan_time
                newly_detected.append(engine)

        # Update shelf life (days from build to first ANY detection)
        if detecting_engines and payload["shelf_life_days"] is None:
            try:
                build_dt = datetime.fromisoformat(
                    payload["build_time"].replace("Z", "+00:00").replace("+00:00", "")
                )
                detect_dt = datetime.fromisoformat(
                    scan_time.replace("Z", "+00:00").replace("+00:00", "")
                )
                delta = (detect_dt - build_dt).total_seconds()
                payload["shelf_life_days"] = round(delta / 86400, 2)
            except (ValueError, TypeError):
                payload["shelf_life_days"] = 0

        # Update status
        if detecting_engines:
            detection_rate = len(detecting_engines) / max(total_engines, 1)
            if detection_rate >= 0.5:
                payload["status"] = "burned"
            else:
                payload["status"] = "detected"

        return {
            "new_detections": newly_detected,
            "total_detecting": len(detecting_engines),
            "total_engines": total_engines,
        }

    @staticmethod
    def _parse_scan_file(path):
        """Parse a LitterBox scan results file into {engine: detected_bool}."""
        with open(path) as f:
            data = json.load(f)

        results = {}

        # Handle list of scans (take the first/latest)
        if isinstance(data, list):
            data = data[-1] if data else {}

        detections = data.get("detections", data.get("results", data.get("scans", {})))

        for engine, info in detections.items():
            if isinstance(info, dict):
                results[engine] = bool(info.get("detected", False))
            elif isinstance(info, bool):
                results[engine] = info
            elif isinstance(info, str):
                results[engine] = bool(info)

        return results

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_report(self):
        """Generate a shelf-life analysis report.

        Returns a dict with:
            payloads        - per-payload summary
            by_profile      - aggregated stats per build profile
            engine_rankings - which engines detect earliest
            trends          - detection rate over time
        """
        payloads_summary = {}
        profile_stats = defaultdict(lambda: {
            "count": 0,
            "shelf_lives": [],
            "clean_count": 0,
            "detected_count": 0,
            "burned_count": 0,
        })
        engine_first_detect_deltas = defaultdict(list)  # engine -> [days_to_detect]

        for version, payload in self.db["payloads"].items():
            profile = payload["profile"]
            shelf_life = payload["shelf_life_days"]
            status = payload["status"]

            # Per-payload summary
            latest_scan = payload["scan_history"][-1] if payload["scan_history"] else None
            payloads_summary[version] = {
                "profile": profile,
                "build_time": payload["build_time"],
                "status": status,
                "shelf_life_days": shelf_life,
                "total_scans": len(payload["scan_history"]),
                "engines_detecting": len(payload["first_seen"]),
                "latest_detection_rate": (
                    latest_scan["detection_rate"] if latest_scan else 0
                ),
            }

            # Profile aggregation
            ps = profile_stats[profile]
            ps["count"] += 1
            if shelf_life is not None:
                ps["shelf_lives"].append(shelf_life)
            if status == "clean":
                ps["clean_count"] += 1
            elif status == "detected":
                ps["detected_count"] += 1
            elif status == "burned":
                ps["burned_count"] += 1

            # Engine first-detect deltas
            if payload["build_time"]:
                try:
                    build_dt = datetime.fromisoformat(
                        payload["build_time"].replace("Z", "").replace("+00:00", "")
                    )
                    for engine, detect_time in payload["first_seen"].items():
                        try:
                            detect_dt = datetime.fromisoformat(
                                detect_time.replace("Z", "").replace("+00:00", "")
                            )
                            delta_days = (detect_dt - build_dt).total_seconds() / 86400
                            engine_first_detect_deltas[engine].append(delta_days)
                        except (ValueError, TypeError):
                            pass
                except (ValueError, TypeError):
                    pass

        # Aggregate profile stats
        by_profile = {}
        for profile, stats in sorted(profile_stats.items()):
            lives = stats["shelf_lives"]
            by_profile[profile] = {
                "total_payloads": stats["count"],
                "clean": stats["clean_count"],
                "detected": stats["detected_count"],
                "burned": stats["burned_count"],
                "avg_shelf_life_days": (
                    round(sum(lives) / len(lives), 2) if lives else None
                ),
                "min_shelf_life_days": round(min(lives), 2) if lives else None,
                "max_shelf_life_days": round(max(lives), 2) if lives else None,
                "survival_rate_pct": round(
                    100.0 * stats["clean_count"] / max(stats["count"], 1), 1
                ),
            }

        # Engine rankings (which detect earliest on average)
        engine_rankings = []
        for engine, deltas in sorted(engine_first_detect_deltas.items()):
            engine_rankings.append({
                "engine": engine,
                "payloads_detected": len(deltas),
                "avg_days_to_detect": round(sum(deltas) / len(deltas), 2),
                "min_days_to_detect": round(min(deltas), 2),
                "max_days_to_detect": round(max(deltas), 2),
            })
        engine_rankings.sort(key=lambda e: e["avg_days_to_detect"])

        # Detection trend: detection rate per scan across all payloads over time
        all_scans = []
        for version, payload in self.db["payloads"].items():
            for scan in payload["scan_history"]:
                all_scans.append({
                    "time": scan["time"],
                    "version": version,
                    "profile": payload["profile"],
                    "detection_rate": scan["detection_rate"],
                    "detections": scan["detections"],
                    "total_engines": scan["total_engines"],
                })
        all_scans.sort(key=lambda s: s["time"])

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_payloads": len(self.db["payloads"]),
            "payloads": payloads_summary,
            "by_profile": by_profile,
            "engine_rankings": engine_rankings,
            "scan_trend": all_scans[-50:],  # last 50 scans
        }

    def generate_report_file(self, output_path, fmt="json"):
        """Write a report to disk in JSON or Markdown format."""
        report = self.get_report()

        if fmt == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        elif fmt == "markdown":
            lines = self._render_markdown(report)
            with open(output_path, 'w') as f:
                f.write('\n'.join(lines))
        else:
            print(f"Error: unknown format '{fmt}'. Use 'json' or 'markdown'.",
                  file=sys.stderr)
            return None

        return output_path

    @staticmethod
    def _render_markdown(report):
        lines = [
            "# Payload Shelf-Life Report",
            "",
            f"Generated: {report['generated_at']}",
            f"Total tracked payloads: {report['total_payloads']}",
            "",
        ]

        # Profile summary
        lines.extend(["## Performance by Build Profile", ""])
        if report["by_profile"]:
            lines.append("| Profile | Payloads | Clean | Detected | Burned "
                         "| Avg Shelf Life | Survival Rate |")
            lines.append("|---------|----------|-------|----------|--------"
                         "|----------------|---------------|")
            for profile, stats in report["by_profile"].items():
                avg = (f"{stats['avg_shelf_life_days']}d"
                       if stats["avg_shelf_life_days"] is not None else "-")
                lines.append(
                    f"| {profile} | {stats['total_payloads']} | {stats['clean']} "
                    f"| {stats['detected']} | {stats['burned']} | {avg} "
                    f"| {stats['survival_rate_pct']}% |"
                )
        else:
            lines.append("_No payloads registered yet._")
        lines.append("")

        # Engine rankings
        lines.extend(["## Fastest Detecting Engines", ""])
        if report["engine_rankings"]:
            lines.append("| Engine | Payloads Detected | Avg Days to Detect "
                         "| Min Days | Max Days |")
            lines.append("|--------|-------------------|--------------------"
                         "|----------|----------|")
            for eng in report["engine_rankings"][:15]:
                lines.append(
                    f"| {eng['engine']} | {eng['payloads_detected']} "
                    f"| {eng['avg_days_to_detect']} | {eng['min_days_to_detect']} "
                    f"| {eng['max_days_to_detect']} |"
                )
        else:
            lines.append("_No detections recorded yet._")
        lines.append("")

        # Payload detail
        lines.extend(["## Payload Details", ""])
        if report["payloads"]:
            lines.append("| Version | Profile | Status | Shelf Life | Scans "
                         "| Engines Detecting | Latest Rate |")
            lines.append("|---------|---------|--------|------------|-------"
                         "|-------------------|-------------|")
            for version, info in sorted(report["payloads"].items(),
                                         key=lambda x: x[1]["build_time"],
                                         reverse=True):
                sl = (f"{info['shelf_life_days']}d"
                      if info["shelf_life_days"] is not None else "-")
                lines.append(
                    f"| {version[:12]} | {info['profile']} | {info['status']} "
                    f"| {sl} | {info['total_scans']} "
                    f"| {info['engines_detecting']} | {info['latest_detection_rate']}% |"
                )
        else:
            lines.append("_No payloads registered yet._")
        lines.append("")

        return lines

    # ------------------------------------------------------------------
    # Convenience queries
    # ------------------------------------------------------------------

    def get_status(self, version_hash):
        """Get current status of a single payload."""
        payload = self.db["payloads"].get(version_hash)
        if not payload:
            return None

        latest_scan = payload["scan_history"][-1] if payload["scan_history"] else None

        return {
            "version": version_hash,
            "profile": payload["profile"],
            "build_time": payload["build_time"],
            "status": payload["status"],
            "shelf_life_days": payload["shelf_life_days"],
            "total_scans": len(payload["scan_history"]),
            "engines_detecting": sorted(payload["first_seen"].keys()),
            "latest_scan": latest_scan,
        }

    def list_payloads(self):
        """List all tracked payloads with summary info."""
        entries = []
        for version, payload in self.db["payloads"].items():
            entries.append({
                "version": version,
                "profile": payload["profile"],
                "build_time": payload["build_time"],
                "status": payload["status"],
                "shelf_life_days": payload["shelf_life_days"],
                "scans": len(payload["scan_history"]),
            })
        entries.sort(key=lambda e: e["build_time"], reverse=True)
        return entries


def parse_args():
    parser = argparse.ArgumentParser(
        description="Track payload shelf life from build to first detection."
    )
    parser.add_argument("--db", default=DEFAULT_DB_PATH,
                        help=f"Path to shelf-life database (default: {DEFAULT_DB_PATH})")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # register
    reg = sub.add_parser("register", help="Register a new payload build")
    reg.add_argument("--version", required=True, help="Unique build identifier (hash)")
    reg.add_argument("--profile", required=True, help="Build profile name")
    reg.add_argument("--build-time", required=True, help="Build timestamp (ISO-8601)")
    reg.add_argument("--notes", help="Optional notes")

    # scan
    sc = sub.add_parser("scan", help="Record a LitterBox scan result")
    sc.add_argument("--version", required=True, help="Payload version hash")
    sc.add_argument("--results", help="Path to LitterBox scan results JSON")
    sc.add_argument("--scan-time", help="Scan timestamp (default: now)")

    # report
    rp = sub.add_parser("report", help="Generate shelf-life report")
    rp.add_argument("--output", "-o", default="shelf-life-report.json",
                    help="Output file path")
    rp.add_argument("--format", choices=["json", "markdown"], default="json",
                    help="Report format (default: json)")

    # status
    st = sub.add_parser("status", help="Show status of a specific payload")
    st.add_argument("--version", required=True, help="Payload version hash")

    # list
    sub.add_parser("list", help="List all tracked payloads")

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.command:
        print("Error: no command specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    tracker = ShelfLifeTracker(db_path=args.db)

    if args.command == "register":
        ok = tracker.register_payload(
            version_hash=args.version,
            profile=args.profile,
            build_time=args.build_time,
            notes=args.notes,
        )
        if ok:
            tracker.save()
            print(f"Registered payload {args.version} (profile: {args.profile})")
        else:
            sys.exit(1)

    elif args.command == "scan":
        if not args.results:
            print("Error: --results is required for scan command.", file=sys.stderr)
            sys.exit(1)

        result = tracker.record_scan(
            version_hash=args.version,
            scan_time=args.scan_time,
            results_file=args.results,
        )
        if result:
            tracker.save()
            print(f"Scan recorded for {args.version}: "
                  f"{result['total_detecting']}/{result['total_engines']} engines detecting")
            if result["new_detections"]:
                print(f"  New detections by: {', '.join(result['new_detections'])}")
        else:
            sys.exit(1)

    elif args.command == "report":
        fmt = args.format
        output = args.output

        # Auto-detect format from extension if not explicitly set
        if output.endswith(".md") and fmt == "json":
            fmt = "markdown"

        path = tracker.generate_report_file(output, fmt=fmt)
        if path:
            report = tracker.get_report()
            total = report["total_payloads"]
            profiles = len(report["by_profile"])
            print(f"Report written to {path}")
            print(f"  {total} payloads across {profiles} profiles")
        else:
            sys.exit(1)

    elif args.command == "status":
        status = tracker.get_status(args.version)
        if status is None:
            print(f"Error: payload {args.version} not found.", file=sys.stderr)
            sys.exit(1)

        print(f"Payload: {status['version']}")
        print(f"  Profile:    {status['profile']}")
        print(f"  Built:      {status['build_time']}")
        print(f"  Status:     {status['status']}")
        print(f"  Shelf life: {status['shelf_life_days'] or 'N/A'} days")
        print(f"  Scans:      {status['total_scans']}")
        if status["engines_detecting"]:
            print(f"  Detected by: {', '.join(status['engines_detecting'])}")
        if status["latest_scan"]:
            ls = status["latest_scan"]
            print(f"  Latest scan: {ls['time']} "
                  f"({ls['detections']}/{ls['total_engines']} engines, "
                  f"{ls['detection_rate']}%)")

    elif args.command == "list":
        entries = tracker.list_payloads()
        if not entries:
            print("No payloads registered yet.")
            return

        print(f"{'Version':<14} {'Profile':<20} {'Status':<10} "
              f"{'Shelf Life':<12} {'Scans':<6} {'Built'}")
        print("-" * 85)
        for e in entries:
            sl = f"{e['shelf_life_days']}d" if e["shelf_life_days"] is not None else "-"
            print(f"{e['version']:<14} {e['profile']:<20} {e['status']:<10} "
                  f"{sl:<12} {e['scans']:<6} {e['build_time']}")


if __name__ == "__main__":
    main()
