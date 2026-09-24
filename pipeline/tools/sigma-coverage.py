#!/usr/bin/env python3
"""
Map LitterBox results and Elastic alerts to public Sigma rules.

Loads Sigma rules from a local SigmaHQ clone (or uses a curated built-in list),
then matches payload detections against them by rule title, MITRE technique ID,
and keyword overlap.

Usage:
    # With a local Sigma repo clone
    sigma-coverage.py --litterbox-results scan.json \
                      --elastic-alerts alerts.json \
                      --sigma-dir /opt/sigma/rules/windows/ \
                      --output coverage-report.json

    # Using built-in curated rules only
    sigma-coverage.py --litterbox-results scan.json \
                      --elastic-alerts alerts.json \
                      --output coverage-report.json
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ---------------------------------------------------------------------------
# Curated Sigma rules most relevant to shellcode loader detection.
# Used as a fallback when the full SigmaHQ repository is not available.
# ---------------------------------------------------------------------------
CURATED_SIGMA_RULES = [
    # Process Injection
    {
        "id": "17eb8e57-9983-420d-ad8a-2c4976c22eb8",
        "title": "Process Injection - CreateRemoteThread",
        "category": "process_access",
        "techniques": ["T1055", "T1055.001"],
        "keywords": ["createremotethread", "process injection", "remote thread"],
        "level": "medium",
    },
    {
        "id": "c5f05e3a-5679-40c9-8a66-458e60584854",
        "title": "Suspicious NtMapViewOfSection",
        "category": "process_access",
        "techniques": ["T1055", "T1055.001"],
        "keywords": ["ntmapviewofsection", "section mapping", "process hollowing"],
        "level": "high",
    },
    {
        "id": "0e277796-5f23-4e49-a490-483131d4f6e1",
        "title": "Write to Process Memory",
        "category": "process_access",
        "techniques": ["T1055", "T1055.012"],
        "keywords": ["writeprocessmemory", "ntwritevirtualmemory", "memory write"],
        "level": "medium",
    },
    {
        "id": "bfce4f1b-e534-42f3-b44c-cd2e40ac9557",
        "title": "QueueUserAPC Process Injection",
        "category": "process_access",
        "techniques": ["T1055", "T1055.004"],
        "keywords": ["queueuserapc", "apc injection"],
        "level": "high",
    },
    # Suspicious Memory Allocation
    {
        "id": "c0b824af-1fdd-40f0-9af4-38be6d07f370",
        "title": "VirtualAlloc API Call From Suspicious Process",
        "category": "process_creation",
        "techniques": ["T1055", "T1620"],
        "keywords": ["virtualalloc", "memory allocation", "rwx"],
        "level": "medium",
    },
    {
        "id": "c3c0d620-a4a9-44ea-9e6e-66a4b5f32a76",
        "title": "Suspicious VirtualProtect Call",
        "category": "api_call",
        "techniques": ["T1055", "T1620"],
        "keywords": ["virtualprotect", "page_execute", "memory protection"],
        "level": "medium",
    },
    # Shellcode / Reflective Loading
    {
        "id": "552b6b65-df54-4e59-9264-95e5f9b0613b",
        "title": "Reflective DLL Loading",
        "category": "image_load",
        "techniques": ["T1620", "T1055.001"],
        "keywords": ["reflective", "dll loading", "reflectivedllinjection"],
        "level": "high",
    },
    {
        "id": "e5b33f7d-eb93-4499-a8e5-5b0e880ae3e4",
        "title": "Suspicious Shellcode Detection",
        "category": "process_creation",
        "techniques": ["T1059", "T1055"],
        "keywords": ["shellcode", "payload", "staged", "meterpreter"],
        "level": "high",
    },
    # Syscall / Direct Syscall evasion
    {
        "id": "83a09c08-d685-4e72-af0c-0a4f3a802a5a",
        "title": "Direct Syscall Usage",
        "category": "process_access",
        "techniques": ["T1106"],
        "keywords": ["syscall", "ntdll", "direct syscall", "hell's gate"],
        "level": "high",
    },
    {
        "id": "f4bbd493-b796-416e-bbf2-121235348529",
        "title": "Ntdll Unhooking via KnownDlls",
        "category": "file_access",
        "techniques": ["T1562.001"],
        "keywords": ["unhooking", "knowndlls", "ntdll", "edr bypass"],
        "level": "critical",
    },
    # Process Hollowing
    {
        "id": "c4b4b57a-548a-4e67-b75b-11c4f7254a2e",
        "title": "Process Hollowing",
        "category": "process_access",
        "techniques": ["T1055.012"],
        "keywords": ["process hollowing", "ntunmapviewofsection", "hollow"],
        "level": "high",
    },
    # Suspicious Process Creation
    {
        "id": "d6c505e5-8a5a-4c42-8783-c2a1f1f2ea9d",
        "title": "Suspicious Process Created by Unsigned Binary",
        "category": "process_creation",
        "techniques": ["T1036", "T1059"],
        "keywords": ["unsigned", "suspicious process", "binary"],
        "level": "medium",
    },
    # AMSI / ETW bypass
    {
        "id": "b1e41b33-1e82-4b4b-89e4-1b144e0b1c5a",
        "title": "AMSI Bypass Attempt",
        "category": "process_creation",
        "techniques": ["T1562.001"],
        "keywords": ["amsi", "amsiscanbuffer", "bypass", "amsiutils"],
        "level": "high",
    },
    {
        "id": "a]a4ce64-2016-4eb0-82cd-0fcde4e7c0ad",
        "title": "ETW Trace Provider Tampering",
        "category": "registry_set",
        "techniques": ["T1562.006"],
        "keywords": ["etw", "etwprovider", "trace", "tamper"],
        "level": "high",
    },
    # Credential / token
    {
        "id": "3acf2dc7-3c03-4b02-b195-31b3ce2a3671",
        "title": "Mimikatz Command Line",
        "category": "process_creation",
        "techniques": ["T1003", "T1003.001"],
        "keywords": ["mimikatz", "sekurlsa", "logonpasswords"],
        "level": "critical",
    },
    # Defense evasion - timestomping, masquerading
    {
        "id": "b4d80c4c-2e6e-49ae-bd45-c8a08e88cf16",
        "title": "Timestomping via SetFileTime",
        "category": "file_change",
        "techniques": ["T1070.006"],
        "keywords": ["timestomping", "setfiletime", "timestamp"],
        "level": "high",
    },
    # Cobalt Strike / C2 beacons
    {
        "id": "d7b6be9f-42d8-4e0c-9e0e-8b0a8b0f0b0d",
        "title": "Cobalt Strike Named Pipe",
        "category": "pipe_created",
        "techniques": ["T1071", "T1572"],
        "keywords": ["cobalt strike", "named pipe", "beacon", "MSSE-"],
        "level": "critical",
    },
    {
        "id": "ee35c295-a619-4fcc-8cdf-a24f3e8d2adf",
        "title": "Mythic Agent Connection",
        "category": "network_connection",
        "techniques": ["T1071.001", "T1573"],
        "keywords": ["mythic", "c2", "apollo", "poseidon", "http", "agent"],
        "level": "high",
    },
    # Sleep obfuscation / evasion
    {
        "id": "f0f0f0f0-0001-0002-0003-000000000001",
        "title": "Suspicious Sleep Obfuscation",
        "category": "api_call",
        "techniques": ["T1497.003"],
        "keywords": ["sleep", "obfuscation", "timer", "foliage", "ekko"],
        "level": "medium",
    },
    # Module stomping / phantom DLL hollowing
    {
        "id": "f0f0f0f0-0001-0002-0003-000000000002",
        "title": "Module Stomping Detection",
        "category": "image_load",
        "techniques": ["T1055.001", "T1574"],
        "keywords": ["module stomping", "phantom", "dll hollowing", "transacted"],
        "level": "high",
    },
]


class SigmaRule:
    """Minimal representation of a Sigma rule for matching purposes."""

    def __init__(self, rule_id, title, category, techniques, keywords, level,
                 description="", filename=""):
        self.id = rule_id
        self.title = title
        self.category = category
        self.techniques = set(techniques)
        self.keywords = [k.lower() for k in keywords]
        self.level = level
        self.description = description
        self.filename = filename

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "techniques": sorted(self.techniques),
            "level": self.level,
            "filename": self.filename,
        }


class SigmaCoverageMapper:
    """Map detections to Sigma rules and produce coverage reports."""

    def __init__(self, sigma_rules=None):
        self.rules = sigma_rules or []

    # ------------------------------------------------------------------
    # Rule Loading
    # ------------------------------------------------------------------

    @classmethod
    def from_directory(cls, sigma_dir):
        """Load Sigma rules from a local SigmaHQ clone directory."""
        if not HAS_YAML:
            print("Warning: PyYAML not installed. Using curated rules only.",
                  file=sys.stderr)
            return cls.from_curated()

        rules = []
        sigma_path = Path(sigma_dir)
        for yml_file in sigma_path.rglob("*.yml"):
            try:
                with open(yml_file, encoding="utf-8") as f:
                    docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if not isinstance(doc, dict) or "title" not in doc:
                        continue
                    rule = cls._parse_sigma_yaml(doc, str(yml_file))
                    if rule:
                        rules.append(rule)
            except Exception:
                continue

        print(f"Loaded {len(rules)} Sigma rules from {sigma_dir}")
        return cls(rules)

    @classmethod
    def from_curated(cls):
        """Load the built-in curated rule set."""
        rules = []
        for entry in CURATED_SIGMA_RULES:
            rules.append(SigmaRule(
                rule_id=entry["id"],
                title=entry["title"],
                category=entry["category"],
                techniques=entry["techniques"],
                keywords=entry["keywords"],
                level=entry["level"],
            ))
        print(f"Loaded {len(rules)} curated Sigma rules (built-in fallback)")
        return cls(rules)

    @staticmethod
    def _parse_sigma_yaml(doc, filename):
        """Parse a single Sigma YAML document into a SigmaRule."""
        title = doc.get("title", "")
        rule_id = doc.get("id", "")
        level = doc.get("level", "medium")
        description = doc.get("description", "")

        # Category from logsource
        logsource = doc.get("logsource", {})
        category = logsource.get("category", logsource.get("service", "unknown"))

        # Extract MITRE techniques from tags
        techniques = set()
        for tag in doc.get("tags", []):
            match = re.match(r"attack\.t(\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
            if match:
                techniques.add(f"T{match.group(1)}")

        # Keywords from title + description + detection field names
        keywords = []
        keywords.extend(title.lower().split())
        if description:
            # Extract meaningful words (skip common ones)
            for word in description.lower().split():
                if len(word) > 4 and word not in {"which", "where", "their", "there",
                                                   "about", "these", "those", "other",
                                                   "should", "could", "would", "being"}:
                    keywords.append(word)

        # Detection field values can contain useful keywords
        detection = doc.get("detection", {})
        for key, val in detection.items():
            if key in ("condition", "timeframe"):
                continue
            if isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str):
                        keywords.append(v.lower())
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, str):
                                keywords.append(item.lower())

        return SigmaRule(
            rule_id=rule_id,
            title=title,
            category=category,
            techniques=techniques,
            keywords=keywords,
            level=level,
            description=description,
            filename=filename,
        )

    # ------------------------------------------------------------------
    # Detection Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_litterbox_results(path):
        """Parse LitterBox scan results JSON.

        Expected format:
        {
            "file": "payload.exe",
            "detections": {
                "engine_name": {"detected": true, "result": "Trojan.Generic"},
                ...
            }
        }
        or a list of such objects.
        """
        with open(path) as f:
            data = json.load(f)

        if isinstance(data, list):
            results = data
        else:
            results = [data]

        detections = []
        for scan in results:
            scan_detections = scan.get("detections", scan.get("results", {}))
            for engine, info in scan_detections.items():
                if isinstance(info, dict):
                    if info.get("detected", False):
                        detections.append({
                            "source": "litterbox",
                            "engine": engine,
                            "name": info.get("result", info.get("name", "")),
                            "file": scan.get("file", scan.get("filename", "")),
                        })
                elif isinstance(info, bool) and info:
                    detections.append({
                        "source": "litterbox",
                        "engine": engine,
                        "name": engine,
                        "file": scan.get("file", ""),
                    })
                elif isinstance(info, str) and info:
                    detections.append({
                        "source": "litterbox",
                        "engine": engine,
                        "name": info,
                        "file": scan.get("file", ""),
                    })

        return detections

    @staticmethod
    def parse_elastic_alerts(path):
        """Parse Elastic alerts JSON (output from edr-diff.py or direct export)."""
        with open(path) as f:
            data = json.load(f)

        # Handle various formats
        if isinstance(data, dict):
            alerts = data.get("hits", {}).get("hits",
                     data.get("alerts", data.get("diff", {}).get("new", {}).values())))
            if alerts is None:
                alerts = []
        else:
            alerts = data

        if isinstance(alerts, dict):
            # e.g. diff output where keys are rule names
            alerts = list(alerts.values())

        detections = []
        for alert in alerts:
            src = alert.get("_source", alert)

            # Rule name
            rule_name = (
                src.get("kibana.alert.rule.name")
                or src.get("signal", {}).get("rule", {}).get("name")
                or src.get("rule_name", src.get("rule", {}).get("name", ""))
            )

            # MITRE techniques
            techniques = set()
            for threat in src.get("threat", []):
                tech_list = threat.get("technique", [])
                if not isinstance(tech_list, list):
                    tech_list = [tech_list]
                for t in tech_list:
                    tid = t.get("id")
                    if tid:
                        techniques.add(tid)
                    for sub in t.get("subtechnique", []):
                        sid = sub.get("id")
                        if sid:
                            techniques.add(sid)

            # Also check legacy signal schema
            signal_threat = src.get("signal", {}).get("rule", {}).get("threat", [])
            for threat in signal_threat:
                for t in threat.get("technique", []):
                    tid = t.get("id")
                    if tid:
                        techniques.add(tid)

            # Flat techniques list (from edr-diff summary format)
            if "techniques" in src:
                techniques.update(src["techniques"])

            detections.append({
                "source": "elastic",
                "rule_name": rule_name,
                "techniques": sorted(techniques),
                "severity": (
                    src.get("kibana.alert.severity")
                    or src.get("signal", {}).get("rule", {}).get("severity")
                    or src.get("severity", "unknown")
                ),
            })

        return detections

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match_detections(self, litterbox_detections, elastic_detections):
        """Match detections against Sigma rules.

        Matching criteria (ranked by confidence):
        1. MITRE technique ID overlap
        2. Rule title fuzzy match against detection name
        3. Keyword overlap between rule and detection name

        Returns:
            triggered: rules that matched at least one detection
            evaded:    rules that matched no detections
            coverage:  per-category coverage statistics
        """
        triggered = {}  # rule_id -> {rule, matches, confidence}
        all_detection_text = []

        # Build searchable text from all detections
        for det in litterbox_detections:
            all_detection_text.append(det.get("name", "").lower())
        for det in elastic_detections:
            all_detection_text.append(det.get("rule_name", "").lower())

        all_detection_techniques = set()
        for det in elastic_detections:
            all_detection_techniques.update(det.get("techniques", []))

        for rule in self.rules:
            matches = []
            confidence = 0.0

            # 1. Technique match (highest confidence)
            technique_overlap = rule.techniques & all_detection_techniques
            if technique_overlap:
                confidence = max(confidence, 0.7)
                matches.append({
                    "method": "technique_id",
                    "matched": sorted(technique_overlap),
                })

            # 2. Title match against detection names
            rule_title_lower = rule.title.lower()
            for det_text in all_detection_text:
                if not det_text:
                    continue
                # Exact substring
                if rule_title_lower in det_text or det_text in rule_title_lower:
                    confidence = max(confidence, 0.9)
                    matches.append({
                        "method": "title_match",
                        "rule_title": rule.title,
                        "detection": det_text,
                    })
                    break
                # Word overlap
                rule_words = set(rule_title_lower.split())
                det_words = set(det_text.split())
                overlap = rule_words & det_words
                # Require at least 2 meaningful word overlap
                meaningful = {w for w in overlap if len(w) > 3}
                if len(meaningful) >= 2:
                    score = len(meaningful) / max(len(rule_words), 1)
                    if score >= 0.3:
                        confidence = max(confidence, min(0.6, score))
                        matches.append({
                            "method": "title_fuzzy",
                            "overlapping_words": sorted(meaningful),
                            "score": round(score, 2),
                        })

            # 3. Keyword match
            keyword_hits = 0
            matched_keywords = []
            for kw in rule.keywords:
                if len(kw) < 4:
                    continue
                for det_text in all_detection_text:
                    if kw in det_text:
                        keyword_hits += 1
                        matched_keywords.append(kw)
                        break
            if keyword_hits >= 2:
                kw_score = keyword_hits / max(len(rule.keywords), 1)
                confidence = max(confidence, min(0.5, kw_score))
                matches.append({
                    "method": "keyword",
                    "matched_keywords": matched_keywords[:10],
                    "score": round(kw_score, 2),
                })

            if matches and confidence >= 0.3:
                triggered[rule.id] = {
                    "rule": rule.to_dict(),
                    "matches": matches,
                    "confidence": round(confidence, 2),
                }

        # Evaded rules
        triggered_ids = set(triggered.keys())
        evaded = []
        for rule in self.rules:
            if rule.id not in triggered_ids:
                evaded.append(rule.to_dict())

        # Coverage by category
        category_stats = defaultdict(lambda: {"total": 0, "triggered": 0, "evaded": 0})
        for rule in self.rules:
            cat = rule.category
            category_stats[cat]["total"] += 1
            if rule.id in triggered_ids:
                category_stats[cat]["triggered"] += 1
            else:
                category_stats[cat]["evaded"] += 1

        coverage = {}
        for cat, stats in sorted(category_stats.items()):
            coverage[cat] = {
                "total_rules": stats["total"],
                "triggered": stats["triggered"],
                "evaded": stats["evaded"],
                "coverage_pct": round(
                    100.0 * stats["triggered"] / max(stats["total"], 1), 1
                ),
            }

        return {
            "triggered": triggered,
            "evaded": evaded,
            "coverage_by_category": coverage,
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self, result, litterbox_detections, elastic_detections,
                        output_path):
        """Generate JSON and Markdown coverage reports."""
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "input_summary": {
                "litterbox_detections": len(litterbox_detections),
                "elastic_detections": len(elastic_detections),
                "sigma_rules_loaded": len(self.rules),
            },
            "overall": {
                "rules_triggered": len(result["triggered"]),
                "rules_evaded": len(result["evaded"]),
                "total_rules": len(self.rules),
                "overall_coverage_pct": round(
                    100.0 * len(result["triggered"]) / max(len(self.rules), 1), 1
                ),
            },
            "coverage_by_category": result["coverage_by_category"],
            "triggered_rules": result["triggered"],
            "evaded_rules": result["evaded"],
        }

        # JSON
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Markdown
        md_path = os.path.splitext(output_path)[0] + ".md"
        lines = self._render_markdown(report)
        with open(md_path, 'w') as f:
            f.write('\n'.join(lines))

        return output_path, md_path

    @staticmethod
    def _render_markdown(report):
        overall = report["overall"]
        lines = [
            "# Sigma Rule Coverage Report",
            "",
            f"Generated: {report['generated_at']}",
            "",
            "## Overall Coverage",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Sigma rules loaded | {overall['total_rules']} |",
            f"| Rules triggered | {overall['rules_triggered']} |",
            f"| Rules evaded | {overall['rules_evaded']} |",
            f"| Coverage | {overall['overall_coverage_pct']}% |",
            f"| LitterBox detections | {report['input_summary']['litterbox_detections']} |",
            f"| Elastic detections | {report['input_summary']['elastic_detections']} |",
            "",
            "## Coverage by Category",
            "",
            "| Category | Total | Triggered | Evaded | Coverage |",
            "|----------|-------|-----------|--------|----------|",
        ]

        for cat, stats in report["coverage_by_category"].items():
            lines.append(
                f"| {cat} | {stats['total_rules']} | {stats['triggered']} "
                f"| {stats['evaded']} | {stats['coverage_pct']}% |"
            )

        lines.extend(["", "## Triggered Rules", ""])
        if report["triggered_rules"]:
            lines.append("| Rule | Category | Level | Confidence | Techniques | Match Method |")
            lines.append("|------|----------|-------|------------|------------|--------------|")
            for _rid, info in sorted(report["triggered_rules"].items(),
                                      key=lambda x: x[1]["confidence"], reverse=True):
                rule = info["rule"]
                methods = ", ".join(m["method"] for m in info["matches"])
                techs = ", ".join(rule["techniques"]) or "-"
                lines.append(
                    f"| {rule['title']} | {rule['category']} | {rule['level']} "
                    f"| {info['confidence']} | {techs} | {methods} |"
                )
        else:
            lines.append("_No Sigma rules were triggered by the detections._")

        lines.extend(["", "## Evaded Rules", ""])
        if report["evaded_rules"]:
            lines.append("| Rule | Category | Level | Techniques |")
            lines.append("|------|----------|-------|------------|")
            for rule in report["evaded_rules"]:
                techs = ", ".join(rule["techniques"]) or "-"
                lines.append(
                    f"| {rule['title']} | {rule['category']} | {rule['level']} | {techs} |"
                )
        else:
            lines.append("_All loaded Sigma rules were triggered._")

        lines.append("")
        return lines


def parse_args():
    parser = argparse.ArgumentParser(
        description="Map detections to Sigma rules and generate coverage report."
    )

    parser.add_argument("--litterbox-results",
                        help="Path to LitterBox scan results JSON")
    parser.add_argument("--elastic-alerts",
                        help="Path to Elastic alerts JSON (from edr-diff.py or export)")
    parser.add_argument("--sigma-dir",
                        help="Path to SigmaHQ rules directory (e.g. /opt/sigma/rules/windows/)")
    parser.add_argument("--curated-only", action="store_true",
                        help="Use only the built-in curated rule set")
    parser.add_argument("--output", "-o", default="coverage-report.json",
                        help="Output file path (default: coverage-report.json)")

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.litterbox_results and not args.elastic_alerts:
        print("Error: provide at least one of --litterbox-results or --elastic-alerts.",
              file=sys.stderr)
        sys.exit(1)

    # Load Sigma rules
    if args.sigma_dir and not args.curated_only:
        if os.path.isdir(args.sigma_dir):
            mapper = SigmaCoverageMapper.from_directory(args.sigma_dir)
            # Supplement with curated rules not already present
            loaded_ids = {r.id for r in mapper.rules}
            for entry in CURATED_SIGMA_RULES:
                if entry["id"] not in loaded_ids:
                    mapper.rules.append(SigmaRule(
                        rule_id=entry["id"],
                        title=entry["title"],
                        category=entry["category"],
                        techniques=entry["techniques"],
                        keywords=entry["keywords"],
                        level=entry["level"],
                    ))
            print(f"Total rules after merging curated: {len(mapper.rules)}")
        else:
            print(f"Warning: {args.sigma_dir} not found. Using curated rules only.",
                  file=sys.stderr)
            mapper = SigmaCoverageMapper.from_curated()
    else:
        mapper = SigmaCoverageMapper.from_curated()

    # Load detections
    litterbox_detections = []
    elastic_detections = []

    if args.litterbox_results:
        print(f"Loading LitterBox results from {args.litterbox_results}")
        litterbox_detections = mapper.parse_litterbox_results(args.litterbox_results)
        print(f"  Parsed {len(litterbox_detections)} detections")

    if args.elastic_alerts:
        print(f"Loading Elastic alerts from {args.elastic_alerts}")
        elastic_detections = mapper.parse_elastic_alerts(args.elastic_alerts)
        print(f"  Parsed {len(elastic_detections)} detections")

    # Match
    print("Matching detections to Sigma rules...")
    result = mapper.match_detections(litterbox_detections, elastic_detections)

    # Report
    json_path, md_path = mapper.generate_report(
        result, litterbox_detections, elastic_detections, args.output
    )

    overall = result["coverage_by_category"]
    triggered = len(result["triggered"])
    evaded = len(result["evaded"])
    total = triggered + evaded
    pct = round(100.0 * triggered / max(total, 1), 1)

    print(f"\nReports written:")
    print(f"  JSON: {json_path}")
    print(f"  Markdown: {md_path}")
    print(f"\nCoverage: {triggered}/{total} rules triggered ({pct}%), {evaded} evaded")


if __name__ == "__main__":
    main()
