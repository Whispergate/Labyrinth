#!/usr/bin/env python3
"""Collect MAAS pipeline metrics for Grafana.

Reads from Jenkins API and on-disk JSON files (LitterBox results, shelf-life
data, version manifests) and writes a unified metrics.json consumed by the
Grafana JSON API datasource.

Usage:
    metrics-collector.py --jenkins-url http://10.5.99.3:8080 \
                         --output-dir /var/lib/grafana/data/maas/

Typical cron entry (every 5 minutes):
    */5 * * * * /opt/maas/metrics-collector.py \
        --jenkins-url http://10.5.99.3:8080 \
        --output-dir /var/lib/grafana/data/maas/ 2>&1 | logger -t maas-metrics
"""

import argparse
import glob
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("maas-metrics")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_JENKINS_URL = "http://10.5.99.3:8080"
DEFAULT_JENKINS_USER = "admin"
DEFAULT_JENKINS_PASSWORD = "JenkinsPW1!"
DEFAULT_PAYLOADS_DIR = "/payloads"
DEFAULT_SCAN_RESULTS_DIR = "/payloads/scan-results"
DEFAULT_SHELF_LIFE_DB = "/payloads/shelf-life/shelf-life.json"
DEFAULT_ARCHIVE_DIR = "/payloads/archive"
DEFAULT_CACHE_DIRS = [
    "/var/cache/maas/gomod",
    "/var/cache/maas/gobuild",
    "/var/cache/maas/nimble",
    "/var/cache/maas/nim-cache",
    "/var/cache/maas/cargo-registry",
    "/var/cache/maas/cargo-git",
]

KNOWN_PROFILES = [
    "quick-test",
    "evasive-c",
    "evasive-c-heavy",
    "evasive-c-signed",
    "evasive-c-dll",
    "garble-go",
    "rust-loader",
    "dotnet-loader",
    "packed-c",
    "packed-ollvm",
]

KNOWN_LANGUAGES = ["c-mingw", "c-ollvm", "go-garble", "rust", "csharp"]

KNOWN_OBFUSCATIONS = [
    "none",
    "ollvm-cff",
    "ollvm-bcf-cff",
    "ollvm-full",
    "ollvm-heavy",
    "garble-literals",
    "string-encrypt",
    "calypso",
]


class MetricsCollector:
    """Gather MAAS pipeline telemetry and write a single metrics.json."""

    def __init__(
        self,
        jenkins_url: str,
        jenkins_user: str,
        jenkins_password: str,
        output_dir: str,
        payloads_dir: str = DEFAULT_PAYLOADS_DIR,
        scan_results_dir: str = DEFAULT_SCAN_RESULTS_DIR,
        shelf_life_db: str = DEFAULT_SHELF_LIFE_DB,
        archive_dir: str = DEFAULT_ARCHIVE_DIR,
    ):
        self.jenkins_url = jenkins_url.rstrip("/")
        self.jenkins_auth = (jenkins_user, jenkins_password)
        self.output_dir = Path(output_dir)
        self.payloads_dir = Path(payloads_dir)
        self.scan_results_dir = Path(scan_results_dir)
        self.shelf_life_db = Path(shelf_life_db)
        self.archive_dir = Path(archive_dir)

        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Jenkins helpers
    # ------------------------------------------------------------------
    def _jenkins_get(self, path: str, params: dict | None = None) -> dict | None:
        url = f"{self.jenkins_url}{path}"
        try:
            resp = requests.get(
                url, auth=self.jenkins_auth, params=params, timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.warning("Jenkins request failed: %s – %s", url, exc)
            return None

    # ------------------------------------------------------------------
    # 1. Build pipeline metrics
    # ------------------------------------------------------------------
    def collect_jenkins_metrics(self) -> dict[str, Any]:
        """Return build pipeline metrics from the Jenkins API."""
        metrics: dict[str, Any] = {
            "builds": [],
            "summary": {
                "total": 0,
                "success": 0,
                "failure": 0,
                "unstable": 0,
                "aborted": 0,
            },
            "builds_per_day": {},
            "duration_by_profile": {},
            "queue_depth": 0,
        }

        # --- Queue depth ---
        queue_data = self._jenkins_get("/queue/api/json")
        if queue_data:
            metrics["queue_depth"] = len(queue_data.get("items", []))

        # --- Job builds ---
        tree = "jobs[name,builds[number,result,duration,timestamp,actions[parameters[name,value]]]]"
        data = self._jenkins_get("/api/json", params={"tree": tree})
        if not data:
            return metrics

        for job in data.get("jobs", []):
            job_name = job.get("name", "")
            for build in job.get("builds", []):
                result = build.get("result")
                if result is None:
                    continue  # still running

                ts = build.get("timestamp", 0)
                duration_ms = build.get("duration", 0)
                build_date = datetime.fromtimestamp(
                    ts / 1000, tz=timezone.utc
                ).strftime("%Y-%m-%d")

                # Extract profile / language from build parameters
                profile = ""
                language = ""
                obfuscation = ""
                for action in build.get("actions", []):
                    for param in action.get("parameters", []):
                        pname = param.get("name", "")
                        pval = param.get("value", "")
                        if pname == "BUILD_PROFILE":
                            profile = pval
                        elif pname == "LANGUAGE":
                            language = pval
                        elif pname == "OBFUSCATION":
                            obfuscation = pval

                entry = {
                    "job": job_name,
                    "number": build["number"],
                    "result": result,
                    "duration_s": round(duration_ms / 1000, 1),
                    "timestamp": ts,
                    "date": build_date,
                    "profile": profile,
                    "language": language,
                    "obfuscation": obfuscation,
                }
                metrics["builds"].append(entry)

                # Summaries
                metrics["summary"]["total"] += 1
                key = result.lower()
                if key in metrics["summary"]:
                    metrics["summary"][key] += 1

                # Builds per day
                metrics["builds_per_day"].setdefault(build_date, 0)
                metrics["builds_per_day"][build_date] += 1

                # Duration by profile
                label = profile or language or job_name
                metrics["duration_by_profile"].setdefault(label, [])
                metrics["duration_by_profile"][label].append(
                    {
                        "timestamp": ts,
                        "duration_s": round(duration_ms / 1000, 1),
                    }
                )

        # Sort builds newest-first
        metrics["builds"].sort(key=lambda b: b["timestamp"], reverse=True)

        return metrics

    # ------------------------------------------------------------------
    # 2. LitterBox scan results
    # ------------------------------------------------------------------
    def collect_litterbox_results(self) -> dict[str, Any]:
        """Aggregate LitterBox scan result JSON files."""
        metrics: dict[str, Any] = {
            "scans": [],
            "detection_rate_over_time": [],
            "engine_payload_matrix": {},
            "profile_detection_rates": {},
            "detection_by_obfuscation": {},
        }

        result_files = sorted(
            glob.glob(str(self.scan_results_dir / "**/*.json"), recursive=True)
        )
        if not result_files:
            # Fallback: look inside build artifact dirs
            result_files = sorted(
                glob.glob(str(self.payloads_dir / "**/results.json"), recursive=True)
            )

        for fpath in result_files:
            try:
                with open(fpath) as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("Skipping %s: %s", fpath, exc)
                continue

            scan_entry: dict[str, Any] = {
                "file": fpath,
                "md5": data.get("md5", ""),
                "risk_level": data.get("risk_level", "unknown"),
                "timestamp": data.get("timestamp", ""),
                "engines": {},
            }

            # Aggregate per-engine detections
            static_results = data.get("static", {}).get("results", {})
            dynamic_results = data.get("dynamic", {}).get("results", {})
            edr_results = data.get("edr", {})

            total_engines = 0
            detections = 0

            for engine, verdict in static_results.items():
                detected = self._is_detected(verdict)
                scan_entry["engines"][engine] = {
                    "type": "static",
                    "detected": detected,
                }
                total_engines += 1
                if detected:
                    detections += 1

            for engine, verdict in dynamic_results.items():
                detected = self._is_detected(verdict)
                scan_entry["engines"][engine] = {
                    "type": "dynamic",
                    "detected": detected,
                }
                total_engines += 1
                if detected:
                    detections += 1

            if isinstance(edr_results, dict):
                for profile_name, profile_data in edr_results.items():
                    if isinstance(profile_data, dict):
                        alerts = profile_data.get("alerts", [])
                        detected = len(alerts) > 0
                        scan_entry["engines"][f"edr-{profile_name}"] = {
                            "type": "edr",
                            "detected": detected,
                            "alert_count": len(alerts),
                        }
                        total_engines += 1
                        if detected:
                            detections += 1

            scan_entry["total_engines"] = total_engines
            scan_entry["detections"] = detections
            scan_entry["detection_rate"] = (
                round(detections / total_engines, 4) if total_engines else 0.0
            )

            metrics["scans"].append(scan_entry)

            # Build engine-payload matrix
            payload_id = scan_entry["md5"] or os.path.basename(fpath)
            for engine, info in scan_entry["engines"].items():
                metrics["engine_payload_matrix"].setdefault(engine, {})
                metrics["engine_payload_matrix"][engine][payload_id] = info[
                    "detected"
                ]

            # Try to extract profile / obfuscation from co-located manifest
            manifest_path = os.path.join(os.path.dirname(fpath), "manifest.json")
            profile = ""
            obfuscation = ""
            if os.path.isfile(manifest_path):
                try:
                    with open(manifest_path) as mf:
                        manifest = json.load(mf)
                    profile = manifest.get("profile", "")
                    obfuscation = manifest.get("obfuscation", "")
                except Exception:
                    pass

            if profile:
                metrics["profile_detection_rates"].setdefault(profile, [])
                metrics["profile_detection_rates"][profile].append(
                    scan_entry["detection_rate"]
                )

            if obfuscation:
                metrics["detection_by_obfuscation"].setdefault(obfuscation, [])
                metrics["detection_by_obfuscation"][obfuscation].append(
                    scan_entry["detection_rate"]
                )

        # Compute averages
        for profile, rates in metrics["profile_detection_rates"].items():
            avg = round(sum(rates) / len(rates), 4) if rates else 0.0
            metrics["profile_detection_rates"][profile] = {
                "avg_rate": avg,
                "samples": len(rates),
                "rates": rates,
            }

        for obf, rates in metrics["detection_by_obfuscation"].items():
            avg = round(sum(rates) / len(rates), 4) if rates else 0.0
            metrics["detection_by_obfuscation"][obf] = {
                "avg_rate": avg,
                "samples": len(rates),
            }

        return metrics

    @staticmethod
    def _is_detected(verdict: Any) -> bool:
        if isinstance(verdict, bool):
            return verdict
        if isinstance(verdict, str):
            v = verdict.lower()
            return v not in ("clean", "undetected", "not detected", "safe", "")
        if isinstance(verdict, dict):
            return verdict.get("detected", False)
        return False

    # ------------------------------------------------------------------
    # 3. Shelf life
    # ------------------------------------------------------------------
    def collect_shelf_life(self) -> dict[str, Any]:
        """Parse shelf-life tracking database."""
        metrics: dict[str, Any] = {
            "entries": [],
            "avg_by_profile": {},
            "trend": [],
            "first_detection_engines": {},
        }

        if not self.shelf_life_db.is_file():
            log.info("Shelf-life DB not found at %s", self.shelf_life_db)
            return metrics

        try:
            with open(self.shelf_life_db) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to read shelf-life DB: %s", exc)
            return metrics

        entries = data if isinstance(data, list) else data.get("entries", [])

        for entry in entries:
            profile = entry.get("profile", "unknown")
            shelf_days = entry.get("shelf_life_days", entry.get("days_clean", 0))
            first_engine = entry.get(
                "first_detection_engine", entry.get("detected_by", "")
            )
            created = entry.get("created", entry.get("timestamp", ""))

            record = {
                "profile": profile,
                "shelf_life_days": shelf_days,
                "first_detection_engine": first_engine,
                "created": created,
            }
            metrics["entries"].append(record)

            # Per-profile average
            metrics["avg_by_profile"].setdefault(profile, [])
            metrics["avg_by_profile"][profile].append(shelf_days)

            # First detection engine counts
            if first_engine:
                metrics["first_detection_engines"].setdefault(first_engine, 0)
                metrics["first_detection_engines"][first_engine] += 1

            # Trend point
            if created:
                metrics["trend"].append(
                    {"date": created, "shelf_life_days": shelf_days}
                )

        # Compute averages
        for profile, days_list in metrics["avg_by_profile"].items():
            avg = round(sum(days_list) / len(days_list), 1) if days_list else 0
            metrics["avg_by_profile"][profile] = {
                "avg_days": avg,
                "samples": len(days_list),
            }

        # Sort trend by date
        metrics["trend"].sort(key=lambda t: t["date"])

        return metrics

    # ------------------------------------------------------------------
    # 4. Infrastructure
    # ------------------------------------------------------------------
    def collect_infrastructure(self) -> dict[str, Any]:
        """Collect runner status, cache and disk usage."""
        metrics: dict[str, Any] = {
            "runners": [],
            "cache_usage": {},
            "disk_usage": {},
        }

        # --- Jenkins node status ---
        nodes_data = self._jenkins_get(
            "/computer/api/json",
            params={"tree": "computer[displayName,offline,idle,numExecutors]"},
        )
        if nodes_data:
            for node in nodes_data.get("computer", []):
                name = node.get("displayName", "")
                if name == "Built-In Node":
                    continue
                offline = node.get("offline", True)
                idle = node.get("idle", True)
                executors = node.get("numExecutors", 0)

                if offline:
                    status = "offline"
                elif not idle:
                    status = "busy"
                else:
                    status = "online"

                metrics["runners"].append(
                    {
                        "name": name,
                        "status": status,
                        "executors": executors,
                        "offline": offline,
                        "idle": idle,
                    }
                )

        # --- Cache directory sizes ---
        for cache_dir in DEFAULT_CACHE_DIRS:
            metrics["cache_usage"][cache_dir] = self._dir_size_bytes(cache_dir)

        # --- Payload directory size ---
        metrics["disk_usage"]["payloads"] = self._dir_size_bytes(
            str(self.payloads_dir)
        )
        metrics["disk_usage"]["archive"] = self._dir_size_bytes(
            str(self.archive_dir)
        )

        return metrics

    @staticmethod
    def _dir_size_bytes(path: str) -> int:
        """Return directory size in bytes, 0 if inaccessible."""
        try:
            result = subprocess.run(
                ["du", "-sb", path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return int(result.stdout.split()[0])
        except Exception:
            pass
        return 0

    # ------------------------------------------------------------------
    # Assemble and write
    # ------------------------------------------------------------------
    def collect_all(self) -> dict[str, Any]:
        """Run all collectors and return unified metrics dict."""
        log.info("Collecting Jenkins build metrics...")
        jenkins = self.collect_jenkins_metrics()

        log.info("Collecting LitterBox scan results...")
        litterbox = self.collect_litterbox_results()

        log.info("Collecting shelf-life data...")
        shelf_life = self.collect_shelf_life()

        log.info("Collecting infrastructure metrics...")
        infra = self.collect_infrastructure()

        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collector_version": "1.0.0",
            "jenkins": jenkins,
            "litterbox": litterbox,
            "shelf_life": shelf_life,
            "infrastructure": infra,
        }

    def write_metrics(self, metrics: dict[str, Any]) -> None:
        """Atomically write metrics.json."""
        output_path = self.output_dir / "metrics.json"
        tmp_path = self.output_dir / "metrics.json.tmp"
        try:
            with open(tmp_path, "w") as fh:
                json.dump(metrics, fh, indent=2)
            shutil.move(str(tmp_path), str(output_path))
            log.info("Wrote %s", output_path)
        except OSError as exc:
            log.error("Failed to write metrics: %s", exc)
            raise

    def run(self) -> None:
        """Collect everything and write to disk."""
        metrics = self.collect_all()
        self.write_metrics(metrics)
        log.info(
            "Collection complete – %d builds, %d scans, %d shelf-life entries",
            len(metrics["jenkins"]["builds"]),
            len(metrics["litterbox"]["scans"]),
            len(metrics["shelf_life"]["entries"]),
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect MAAS pipeline metrics for Grafana"
    )
    parser.add_argument(
        "--jenkins-url",
        default=DEFAULT_JENKINS_URL,
        help="Jenkins base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--jenkins-user",
        default=DEFAULT_JENKINS_USER,
        help="Jenkins username (default: %(default)s)",
    )
    parser.add_argument(
        "--jenkins-password",
        default=DEFAULT_JENKINS_PASSWORD,
        help="Jenkins password (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="/var/lib/grafana/data/maas",
        help="Directory for metrics.json output (default: %(default)s)",
    )
    parser.add_argument(
        "--payloads-dir",
        default=DEFAULT_PAYLOADS_DIR,
        help="Root payloads directory (default: %(default)s)",
    )
    parser.add_argument(
        "--scan-results-dir",
        default=DEFAULT_SCAN_RESULTS_DIR,
        help="LitterBox scan results directory (default: %(default)s)",
    )
    parser.add_argument(
        "--shelf-life-db",
        default=DEFAULT_SHELF_LIFE_DB,
        help="Shelf-life JSON database path (default: %(default)s)",
    )
    parser.add_argument(
        "--archive-dir",
        default=DEFAULT_ARCHIVE_DIR,
        help="Payload archive directory (default: %(default)s)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    collector = MetricsCollector(
        jenkins_url=args.jenkins_url,
        jenkins_user=args.jenkins_user,
        jenkins_password=args.jenkins_password,
        output_dir=args.output_dir,
        payloads_dir=args.payloads_dir,
        scan_results_dir=args.scan_results_dir,
        shelf_life_db=args.shelf_life_db,
        archive_dir=args.archive_dir,
    )
    collector.run()


if __name__ == "__main__":
    main()
