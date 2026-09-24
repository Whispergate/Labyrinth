#!/usr/bin/env python3
"""
Compare Elastic Security alerts between two payload executions.

Queries Elastic Security for alerts in two time windows (before/after a payload
change) and produces a diff showing new, removed, and common detections.
Supports both live Elastic queries and pre-saved JSON alert files.

Usage:
    # Live query mode
    edr-diff.py --elastic-url https://10.5.10.100:9200 \
                --before-start "2024-01-01T00:00:00" --before-end "2024-01-01T00:05:00" \
                --after-start "2024-01-01T01:00:00" --after-end "2024-01-01T01:05:00" \
                --output diff-report.json

    # File-based mode
    edr-diff.py --before-file alerts-v1.json --after-file alerts-v2.json \
                --output diff-report.json
"""

import argparse
import json
import os
import sys
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ElasticDiffer:
    """Compare Elastic Security alerts between two payload executions."""

    # Default Elastic signal indices
    SIGNAL_INDEX = ".siem-signals-*"
    ALERTS_INDEX = ".alerts-security.alerts-*"

    def __init__(self, elastic_url, api_key=None, username=None, password=None,
                 verify_ssl=False, index_pattern=None):
        if not HAS_REQUESTS:
            raise RuntimeError(
                "The 'requests' library is required for live Elastic queries. "
                "Install it with: pip install requests"
            )
        self.url = elastic_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if api_key:
            self.session.headers['Authorization'] = f'ApiKey {api_key}'
        elif username and password:
            self.session.auth = (username, password)

        # Try the newer alerts index first, fall back to legacy signals
        self.index = index_pattern or self.ALERTS_INDEX

    def get_alerts(self, start_time, end_time, host_filter=None,
                   process_filter=None, extra_filters=None):
        """Query Elastic for security alerts in a time window.

        Args:
            start_time: ISO-8601 start timestamp.
            end_time: ISO-8601 end timestamp.
            host_filter: Optional hostname to filter by.
            process_filter: Optional process name to filter by.
            extra_filters: Optional list of additional Elasticsearch query clauses.

        Returns:
            List of alert hits from Elasticsearch.
        """
        must_clauses = [
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        ]

        # Support both legacy signal and modern alert schema
        should_kind = [
            {"term": {"event.kind": "signal"}},
            {"term": {"event.kind": "alert"}},
        ]
        must_clauses.append({"bool": {"should": should_kind, "minimum_should_match": 1}})

        if host_filter:
            must_clauses.append({"term": {"host.name": host_filter}})
        if process_filter:
            must_clauses.append({"term": {"process.name": process_filter}})
        if extra_filters:
            must_clauses.extend(extra_filters)

        query = {
            "query": {"bool": {"must": must_clauses}},
            "size": 10000,
            "sort": [{"@timestamp": "asc"}],
        }

        resp = self.session.post(
            f"{self.url}/{self.index}/_search",
            json=query,
            headers={"Content-Type": "application/json"},
        )

        # Fall back to legacy signals index on 404
        if resp.status_code == 404 and self.index == self.ALERTS_INDEX:
            self.index = self.SIGNAL_INDEX
            resp = self.session.post(
                f"{self.url}/{self.index}/_search",
                json=query,
                headers={"Content-Type": "application/json"},
            )

        resp.raise_for_status()
        return resp.json().get("hits", {}).get("hits", [])

    def save_alerts(self, alerts, path):
        """Persist raw alert data to a JSON file for later diffing."""
        with open(path, 'w') as f:
            json.dump(alerts, f, indent=2)

    @staticmethod
    def load_alerts(path):
        """Load previously saved alert data from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        # Accept both raw list and {"hits": {"hits": [...]}} wrapper
        if isinstance(data, dict):
            return data.get("hits", {}).get("hits", data.get("alerts", []))
        return data

    # ------------------------------------------------------------------
    # Alert normalisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_rule_name(alert):
        """Extract rule name from either legacy signal or modern alert schema."""
        src = alert.get("_source", alert)
        # Modern schema
        rule_name = src.get("kibana.alert.rule.name")
        if rule_name:
            return rule_name
        # Legacy schema
        signal = src.get("signal", {})
        rule_name = signal.get("rule", {}).get("name", "")
        if rule_name:
            return rule_name
        # Fallback to rule.name
        return src.get("rule", {}).get("name", "unknown")

    @staticmethod
    def _extract_techniques(alert):
        """Extract MITRE ATT&CK technique IDs from an alert."""
        src = alert.get("_source", alert)
        techniques = set()

        # Modern schema: threat array
        for threat in src.get("threat", []):
            tech = threat.get("technique", [])
            for t in (tech if isinstance(tech, list) else [tech]):
                tid = t.get("id")
                if tid:
                    techniques.add(tid)
                for sub in t.get("subtechnique", []):
                    sid = sub.get("id")
                    if sid:
                        techniques.add(sid)

        # Legacy schema
        signal = src.get("signal", {})
        rule_threat = signal.get("rule", {}).get("threat", [])
        for threat in rule_threat:
            tech = threat.get("technique", [])
            for t in (tech if isinstance(tech, list) else [tech]):
                tid = t.get("id")
                if tid:
                    techniques.add(tid)

        return techniques

    @staticmethod
    def _extract_severity(alert):
        """Extract severity from an alert."""
        src = alert.get("_source", alert)
        sev = src.get("kibana.alert.severity")
        if sev:
            return sev
        signal = src.get("signal", {})
        return signal.get("rule", {}).get("severity", "unknown")

    @staticmethod
    def _alert_key(alert):
        """Create a composite key for deduplication."""
        src = alert.get("_source", alert)
        rule = ElasticDiffer._extract_rule_name(alert)
        host = src.get("host", {}).get("name", "")
        process = src.get("process", {}).get("name", "")
        return f"{rule}|{host}|{process}"

    # ------------------------------------------------------------------
    # Diffing
    # ------------------------------------------------------------------

    def diff_alerts(self, alerts_before, alerts_after):
        """Diff two alert sets.

        Returns a dict with:
            new       - alerts present only in 'after'
            removed   - alerts present only in 'before'
            common    - alerts present in both
            summary   - high-level statistics
        """
        before_map = {}
        for a in alerts_before:
            key = self._alert_key(a)
            before_map.setdefault(key, []).append(a)

        after_map = {}
        for a in alerts_after:
            key = self._alert_key(a)
            after_map.setdefault(key, []).append(a)

        before_keys = set(before_map.keys())
        after_keys = set(after_map.keys())

        new_keys = after_keys - before_keys
        removed_keys = before_keys - after_keys
        common_keys = before_keys & after_keys

        def _summarise(alert):
            return {
                "rule_name": self._extract_rule_name(alert),
                "severity": self._extract_severity(alert),
                "techniques": sorted(self._extract_techniques(alert)),
                "host": alert.get("_source", alert).get("host", {}).get("name", ""),
                "process": alert.get("_source", alert).get("process", {}).get("name", ""),
                "timestamp": alert.get("_source", alert).get("@timestamp", ""),
            }

        new_alerts = {k: _summarise(after_map[k][0]) for k in sorted(new_keys)}
        removed_alerts = {k: _summarise(before_map[k][0]) for k in sorted(removed_keys)}
        common_alerts = {k: _summarise(after_map[k][0]) for k in sorted(common_keys)}

        # Collect all techniques across new/removed
        new_techniques = set()
        for info in new_alerts.values():
            new_techniques.update(info["techniques"])
        removed_techniques = set()
        for info in removed_alerts.values():
            removed_techniques.update(info["techniques"])

        summary = {
            "before_total": len(alerts_before),
            "after_total": len(alerts_after),
            "new_detections": len(new_alerts),
            "removed_detections": len(removed_alerts),
            "common_detections": len(common_alerts),
            "new_techniques": sorted(new_techniques),
            "removed_techniques": sorted(removed_techniques),
            "evasion_delta": len(removed_alerts) - len(new_alerts),
        }

        return {
            "new": new_alerts,
            "removed": removed_alerts,
            "common": common_alerts,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self, diff, output_path):
        """Generate JSON and markdown diff reports.

        Writes <output_path> (JSON) and <output_path>.md (Markdown).
        """
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "diff": diff,
        }

        # JSON report
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Markdown report
        md_path = os.path.splitext(output_path)[0] + ".md"
        lines = self._render_markdown(diff)
        with open(md_path, 'w') as f:
            f.write('\n'.join(lines))

        return output_path, md_path

    @staticmethod
    def _render_markdown(diff):
        """Render a diff dict to Markdown lines."""
        summary = diff["summary"]
        lines = [
            "# EDR Telemetry Diff Report",
            "",
            f"Generated: {datetime.utcnow().isoformat()}Z",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Alerts before | {summary['before_total']} |",
            f"| Alerts after | {summary['after_total']} |",
            f"| New detections | {summary['new_detections']} |",
            f"| Removed detections | {summary['removed_detections']} |",
            f"| Common detections | {summary['common_detections']} |",
            f"| Evasion delta | {summary['evasion_delta']:+d} |",
            "",
        ]

        if summary["evasion_delta"] > 0:
            lines.append("> **Improved evasion**: more detections were removed than added.\n")
        elif summary["evasion_delta"] < 0:
            lines.append("> **Reduced evasion**: more new detections appeared.\n")
        else:
            lines.append("> **Neutral**: detection count unchanged.\n")

        # New detections
        lines.append("## New Detections (appeared after change)")
        lines.append("")
        if diff["new"]:
            lines.append("| Rule | Severity | Techniques | Host | Process |")
            lines.append("|------|----------|------------|------|---------|")
            for _key, info in diff["new"].items():
                techs = ", ".join(info["techniques"]) or "-"
                lines.append(
                    f"| {info['rule_name']} | {info['severity']} | {techs} "
                    f"| {info['host']} | {info['process']} |"
                )
        else:
            lines.append("_None_")
        lines.append("")

        # Removed detections
        lines.append("## Removed Detections (no longer triggered)")
        lines.append("")
        if diff["removed"]:
            lines.append("| Rule | Severity | Techniques | Host | Process |")
            lines.append("|------|----------|------------|------|---------|")
            for _key, info in diff["removed"].items():
                techs = ", ".join(info["techniques"]) or "-"
                lines.append(
                    f"| {info['rule_name']} | {info['severity']} | {techs} "
                    f"| {info['host']} | {info['process']} |"
                )
        else:
            lines.append("_None_")
        lines.append("")

        # Common detections
        lines.append("## Common Detections (still triggered)")
        lines.append("")
        if diff["common"]:
            lines.append("| Rule | Severity | Techniques |")
            lines.append("|------|----------|------------|")
            for _key, info in diff["common"].items():
                techs = ", ".join(info["techniques"]) or "-"
                lines.append(f"| {info['rule_name']} | {info['severity']} | {techs} |")
        else:
            lines.append("_None_")
        lines.append("")

        # Technique summary
        if summary["new_techniques"] or summary["removed_techniques"]:
            lines.append("## MITRE ATT&CK Technique Changes")
            lines.append("")
            if summary["new_techniques"]:
                lines.append(f"**Newly detected techniques:** {', '.join(summary['new_techniques'])}")
            if summary["removed_techniques"]:
                lines.append(f"**No longer detected techniques:** {', '.join(summary['removed_techniques'])}")
            lines.append("")

        return lines


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare Elastic Security alerts between two payload executions."
    )

    # Elastic connection
    conn = parser.add_argument_group("Elastic connection")
    conn.add_argument("--elastic-url", help="Elasticsearch URL (e.g. https://10.5.10.100:9200)")
    conn.add_argument("--api-key", help="Elastic API key")
    conn.add_argument("--username", default="elastic", help="Elastic username (default: elastic)")
    conn.add_argument("--password", help="Elastic password")
    conn.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    conn.add_argument("--index", help="Override alert index pattern")

    # Time-window mode
    tw = parser.add_argument_group("Time-window query mode")
    tw.add_argument("--before-start", help="Start of 'before' time window (ISO-8601)")
    tw.add_argument("--before-end", help="End of 'before' time window (ISO-8601)")
    tw.add_argument("--after-start", help="Start of 'after' time window (ISO-8601)")
    tw.add_argument("--after-end", help="End of 'after' time window (ISO-8601)")

    # File mode
    fm = parser.add_argument_group("File-based mode")
    fm.add_argument("--before-file", help="JSON file with 'before' alerts")
    fm.add_argument("--after-file", help="JSON file with 'after' alerts")

    # Filters
    filt = parser.add_argument_group("Filters")
    filt.add_argument("--host", help="Filter alerts by hostname")
    filt.add_argument("--process", help="Filter alerts by process name")

    # Output
    parser.add_argument("--output", "-o", default="diff-report.json",
                        help="Output file path (default: diff-report.json)")
    parser.add_argument("--save-alerts", action="store_true",
                        help="Save raw alert data alongside the report (live mode only)")

    return parser.parse_args()


def main():
    args = parse_args()

    file_mode = args.before_file and args.after_file
    live_mode = all([args.elastic_url, args.before_start, args.before_end,
                     args.after_start, args.after_end])

    if not file_mode and not live_mode:
        print(
            "Error: provide either --before-file/--after-file or "
            "--elastic-url with all four time-window arguments.",
            file=sys.stderr,
        )
        sys.exit(1)

    if file_mode:
        print(f"Loading before alerts from {args.before_file}")
        alerts_before = ElasticDiffer.load_alerts(args.before_file)
        print(f"Loading after alerts from {args.after_file}")
        alerts_after = ElasticDiffer.load_alerts(args.after_file)

        differ = ElasticDiffer.__new__(ElasticDiffer)
        differ.url = ""
        differ.session = None
    else:
        differ = ElasticDiffer(
            elastic_url=args.elastic_url,
            api_key=args.api_key,
            username=args.username,
            password=args.password,
            verify_ssl=args.verify_ssl,
            index_pattern=args.index,
        )
        print(f"Querying before window: {args.before_start} -> {args.before_end}")
        alerts_before = differ.get_alerts(
            args.before_start, args.before_end,
            host_filter=args.host, process_filter=args.process,
        )
        print(f"  Found {len(alerts_before)} alerts")

        print(f"Querying after window: {args.after_start} -> {args.after_end}")
        alerts_after = differ.get_alerts(
            args.after_start, args.after_end,
            host_filter=args.host, process_filter=args.process,
        )
        print(f"  Found {len(alerts_after)} alerts")

        if args.save_alerts:
            base = os.path.splitext(args.output)[0]
            differ.save_alerts(alerts_before, f"{base}-before-raw.json")
            differ.save_alerts(alerts_after, f"{base}-after-raw.json")
            print(f"  Saved raw alerts to {base}-before-raw.json / {base}-after-raw.json")

    print("Computing diff...")
    diff = differ.diff_alerts(alerts_before, alerts_after)

    json_path, md_path = differ.generate_report(diff, args.output)
    print(f"\nReports written:")
    print(f"  JSON: {json_path}")
    print(f"  Markdown: {md_path}")

    s = diff["summary"]
    print(f"\nSummary: {s['new_detections']} new, {s['removed_detections']} removed, "
          f"{s['common_detections']} common (delta: {s['evasion_delta']:+d})")


if __name__ == "__main__":
    main()
