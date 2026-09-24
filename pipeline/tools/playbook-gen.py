#!/usr/bin/env python3
"""Generate operator playbook based on target environment.

Recommends the best loader + obfuscation combo for a given EDR target
and produces a markdown playbook with build commands and delivery guidance.
"""

import argparse
import yaml
import json
import os
import sys
from datetime import datetime, timezone

TARGET_EDRS = {
    "crowdstrike": {
        "name": "CrowdStrike Falcon",
        "strengths": ["memory scanning", "behavioral", "ml-based"],
        "weaknesses": ["dll sideloading from trusted paths", "indirect syscalls"],
        "recommended_profiles": ["evasive-c-heavy", "packed-ollvm"],
        "avoid": ["dotnet-loader"],
    },
    "defender": {
        "name": "Microsoft Defender",
        "strengths": ["amsi", "static signatures", "cloud lookup"],
        "weaknesses": ["ollvm obfuscation", "calypso packing"],
        "recommended_profiles": ["evasive-c", "packed-c"],
        "avoid": [],
    },
    "sentinelone": {
        "name": "SentinelOne",
        "strengths": ["behavioral ai", "static ai", "memory scanning"],
        "weaknesses": ["indirect syscalls", "dll sideloading"],
        "recommended_profiles": ["evasive-c-heavy", "packed-ollvm"],
        "avoid": ["quick-test"],
    },
    "elastic": {
        "name": "Elastic Security",
        "strengths": ["behavioral rules", "yara", "memory scanning"],
        "weaknesses": ["ollvm", "custom loaders"],
        "recommended_profiles": ["evasive-c", "evasive-c-heavy"],
        "avoid": [],
    },
    "carbon_black": {
        "name": "VMware Carbon Black",
        "strengths": ["behavioral", "reputation"],
        "weaknesses": ["signed binaries", "dll sideloading"],
        "recommended_profiles": ["evasive-c-signed", "packed-ollvm"],
        "avoid": [],
    },
}

# OS compatibility mapping: which languages/formats work on each OS
OS_COMPAT = {
    "windows10": {"languages": ["c-mingw", "c-ollvm", "go-garble", "rust", "csharp"], "formats": ["exe", "dll"]},
    "windows11": {"languages": ["c-mingw", "c-ollvm", "go-garble", "rust", "csharp"], "formats": ["exe", "dll"]},
    "windows2016": {"languages": ["c-mingw", "c-ollvm", "go-garble", "rust", "csharp"], "formats": ["exe", "dll"]},
    "windows2019": {"languages": ["c-mingw", "c-ollvm", "go-garble", "rust", "csharp"], "formats": ["exe", "dll"]},
    "windows2022": {"languages": ["c-mingw", "c-ollvm", "go-garble", "rust", "csharp"], "formats": ["exe", "dll"]},
}

# Delivery method recommendations by EDR
DELIVERY_OPTIONS = {
    "crowdstrike": [
        "DLL sideloading via trusted application path (e.g. OneDrive, Teams updater)",
        "Macro-free Office document with remote template injection",
        "ISO/IMG container to bypass MOTW (if target < Win11 22H2)",
    ],
    "defender": [
        "Direct execution from USB or network share",
        "LNK file with obfuscated command line",
        "HTA delivery via phishing link",
        "DLL sideloading from user-writable directory",
    ],
    "sentinelone": [
        "DLL sideloading from trusted vendor path",
        "Service binary replacement during maintenance window",
        "Scheduled task persistence with signed loader",
    ],
    "elastic": [
        "Direct execution with renamed binary",
        "DLL sideloading via trusted application",
        "WMI event subscription for persistence",
    ],
    "carbon_black": [
        "Signed binary execution (code-signed loader)",
        "DLL sideloading from trusted vendor path",
        "MSI package with embedded loader",
    ],
}

# Network constraint modifiers
NETWORK_CONSTRAINTS = {
    "standard": {
        "note": "Standard network - staged and stageless payloads supported",
        "avoid_formats": [],
    },
    "airgapped": {
        "note": "Air-gapped network - use stageless payloads only, embed all shellcode",
        "avoid_formats": ["staged"],
    },
    "monitored": {
        "note": "Heavily monitored network - prefer encrypted C2 channels, avoid common ports",
        "avoid_formats": [],
    },
    "restricted": {
        "note": "Restricted egress - use domain fronting or malleable C2 profiles",
        "avoid_formats": [],
    },
}


class PlaybookGenerator:
    def __init__(self, profiles_path="pipeline/build-profiles.yml",
                 shelf_life_path="/payloads/shelf-life/shelf-life.json"):
        with open(profiles_path) as f:
            self.profiles = yaml.safe_load(f).get("profiles", {})
        self.shelf_life = self._load_shelf_life(shelf_life_path)

    def _load_shelf_life(self, path):
        """Load historical shelf-life data for profile ranking."""
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _get_shelf_life_score(self, profile_name, edr):
        """Return average shelf-life hours for a profile against an EDR, or None."""
        key = f"{profile_name}:{edr}"
        if key in self.shelf_life:
            entries = self.shelf_life[key]
            if isinstance(entries, list) and entries:
                return sum(e.get("hours", 0) for e in entries) / len(entries)
            elif isinstance(entries, dict):
                return entries.get("hours", 0)
        return None

    def recommend(self, edr, os_version="windows10", network="standard"):
        """Return ranked list of recommended profiles with reasoning."""
        if edr not in TARGET_EDRS:
            raise ValueError(f"Unknown EDR: {edr}. Supported: {', '.join(TARGET_EDRS)}")

        edr_info = TARGET_EDRS[edr]
        os_info = OS_COMPAT.get(os_version, OS_COMPAT["windows10"])
        net_info = NETWORK_CONSTRAINTS.get(network, NETWORK_CONSTRAINTS["standard"])

        recommendations = []
        for name, profile in self.profiles.items():
            # Skip profiles the EDR specifically flags to avoid
            if name in edr_info.get("avoid", []):
                continue

            # Filter by OS language compatibility
            if profile.get("language") not in os_info["languages"]:
                continue

            # Filter by OS format compatibility
            if profile.get("output_format") not in os_info["formats"]:
                continue

            # Score the profile
            score = 0
            reasons = []

            # Boost if in EDR recommended list
            if name in edr_info["recommended_profiles"]:
                score += 50
                reasons.append("EDR-recommended profile")

            # Boost for obfuscation matching EDR weaknesses
            obf = profile.get("obfuscation", "none")
            for weakness in edr_info["weaknesses"]:
                if weakness.lower() in obf.lower():
                    score += 20
                    reasons.append(f"Exploits EDR weakness: {weakness}")

            # Boost for PE sanitisation
            if profile.get("pe_sanitise"):
                score += 10
                reasons.append("PE metadata sanitised")

            # Boost for signing (especially against reputation-based EDRs)
            if profile.get("signing_profile", "none") != "none":
                score += 15
                reasons.append(f"Code-signed ({profile['signing_profile']})")

            # Boost for calypso packing
            if obf == "calypso":
                score += 15
                reasons.append("Calypso packing layer")

            # Boost for OLLVM obfuscation
            if obf.startswith("ollvm"):
                score += 10
                reasons.append("OLLVM obfuscation")

            # Boost for DLL format (sideloading capability)
            if profile.get("output_format") == "dll":
                for weakness in edr_info["weaknesses"]:
                    if "sideload" in weakness.lower():
                        score += 25
                        reasons.append("DLL format enables sideloading")
                        break

            # Adjust by historical shelf-life data
            shelf_hours = self._get_shelf_life_score(name, edr)
            if shelf_hours is not None:
                score += min(int(shelf_hours / 2), 30)
                reasons.append(f"Historical shelf-life: ~{shelf_hours:.0f}h")

            # Penalise quick-test profile
            if name == "quick-test":
                score -= 30
                reasons.append("Testing-only profile (not for operations)")

            if not reasons:
                reasons.append("Generic profile match")

            recommendations.append({
                "profile": name,
                "score": score,
                "reasons": reasons,
                "config": profile,
                "shelf_life_hours": shelf_hours,
            })

        # Sort by score descending
        recommendations.sort(key=lambda r: r["score"], reverse=True)
        return recommendations

    def _jenkins_build_cmd(self, profile_name, profile, operator_id="", campaign_tag="",
                           mythic_uuid="", jenkins_url="http://10.5.99.3:8080"):
        """Generate a Jenkins build trigger command for a profile."""
        params = {
            "LANGUAGE": profile.get("language", "c-mingw"),
            "OUTPUT_FORMAT": profile.get("output_format", "exe"),
            "OBFUSCATION": profile.get("obfuscation", "none"),
            "PE_SANITISE": str(profile.get("pe_sanitise", True)).lower(),
            "LITTERBOX_SCAN": str(profile.get("litterbox_scan", True)).lower(),
            "SCAN_TYPE": profile.get("scan_type", "all"),
            "SIGNING_PROFILE": profile.get("signing_profile", "none"),
        }

        if operator_id:
            params["OPERATOR_ID"] = operator_id
        if campaign_tag:
            params["CAMPAIGN_TAG"] = campaign_tag
        if mythic_uuid:
            params["MYTHIC_PAYLOAD_UUID"] = mythic_uuid

        # Handle calypso preset flags
        if profile.get("obfuscation") == "calypso" and profile.get("packer_preset"):
            preset_flags = {
                "fast": "--unhook ntdll.dll",
                "stealth": "--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp",
                "stealth-obfuscated": "--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp --obfuscate",
                "evasive": "--unhook ntdll.dll --sleep 10 --amsi hwbp,context-corrupt --etw hwbp,complus --obfuscate --self-delete",
                "minimal": "--no-antidebug --amsi none --etw none",
            }
            flags = preset_flags.get(profile["packer_preset"], "")
            if flags:
                params["PACKER_FLAGS"] = flags

        param_str = " ".join(f'-p {k}="{v}"' for k, v in params.items())
        job_name = f"loader-{profile.get('language', 'c-mingw')}"

        lines = []
        lines.append("# Jenkins CLI")
        lines.append(f"java -jar jenkins-cli.jar -s {jenkins_url} build '{job_name}' {param_str}")
        lines.append("")
        lines.append("# curl (Remote API)")
        curl_params = "&".join(f"{k}={v}" for k, v in params.items())
        lines.append(f'curl -X POST "{jenkins_url}/job/{job_name}/buildWithParameters?{curl_params}" \\')
        lines.append(f'    --user "$JENKINS_USER:$JENKINS_TOKEN"')
        return "\n".join(lines)

    def generate_playbook(self, edr, os_version, operator_id, campaign_tag,
                          network="standard", mythic_uuid="",
                          jenkins_url="http://10.5.99.3:8080"):
        """Generate full markdown playbook."""
        recommendations = self.recommend(edr, os_version, network)
        edr_info = TARGET_EDRS[edr]
        net_info = NETWORK_CONSTRAINTS.get(network, NETWORK_CONSTRAINTS["standard"])

        playbook = []
        playbook.append("# Operator Playbook")
        playbook.append("")
        playbook.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        playbook.append(f"**Operator:** {operator_id}")
        playbook.append(f"**Campaign:** {campaign_tag}")
        playbook.append(f"**Target EDR:** {edr_info['name']}")
        playbook.append(f"**Target OS:** {os_version}")
        playbook.append(f"**Network:** {network} - {net_info['note']}")
        playbook.append("")

        # EDR intelligence summary
        playbook.append("## Target EDR Intelligence")
        playbook.append("")
        playbook.append(f"**{edr_info['name']}**")
        playbook.append("")
        playbook.append("**Known Strengths:**")
        for s in edr_info["strengths"]:
            playbook.append(f"- {s}")
        playbook.append("")
        playbook.append("**Known Weaknesses:**")
        for w in edr_info["weaknesses"]:
            playbook.append(f"- {w}")
        playbook.append("")
        if edr_info.get("avoid"):
            playbook.append("**Profiles to Avoid:**")
            for a in edr_info["avoid"]:
                playbook.append(f"- `{a}`")
            playbook.append("")

        # Recommended profiles
        playbook.append("## Recommended Profiles")
        playbook.append("")

        if not recommendations:
            playbook.append("*No compatible profiles found for this target configuration.*")
            playbook.append("")
        else:
            for i, rec in enumerate(recommendations[:5], 1):
                profile = rec["config"]
                playbook.append(f"### {i}. `{rec['profile']}` (Score: {rec['score']})")
                playbook.append("")
                playbook.append(f"**Description:** {profile.get('description', 'N/A')}")
                playbook.append(f"**Language:** {profile.get('language', 'N/A')}")
                playbook.append(f"**Format:** {profile.get('output_format', 'N/A')}")
                playbook.append(f"**Obfuscation:** {profile.get('obfuscation', 'none')}")
                if profile.get("signing_profile", "none") != "none":
                    playbook.append(f"**Signing:** {profile['signing_profile']}")
                if rec.get("shelf_life_hours") is not None:
                    playbook.append(f"**Historical Shelf-Life:** ~{rec['shelf_life_hours']:.0f} hours")
                playbook.append("")
                playbook.append("**Selection Rationale:**")
                for reason in rec["reasons"]:
                    playbook.append(f"- {reason}")
                playbook.append("")

        # Build commands
        playbook.append("## Build Commands")
        playbook.append("")

        for i, rec in enumerate(recommendations[:3], 1):
            playbook.append(f"### Option {i}: `{rec['profile']}`")
            playbook.append("")
            playbook.append("```bash")
            playbook.append(self._jenkins_build_cmd(
                rec["profile"], rec["config"],
                operator_id=operator_id, campaign_tag=campaign_tag,
                mythic_uuid=mythic_uuid, jenkins_url=jenkins_url,
            ))
            playbook.append("```")
            playbook.append("")

        # Build profile parameters (for manual Jenkins UI use)
        if recommendations:
            top = recommendations[0]
            playbook.append("### Manual Jenkins Parameters (Top Pick)")
            playbook.append("")
            playbook.append("| Parameter | Value |")
            playbook.append("|-----------|-------|")
            cfg = top["config"]
            playbook.append(f"| LANGUAGE | `{cfg.get('language', '')}` |")
            playbook.append(f"| OUTPUT_FORMAT | `{cfg.get('output_format', '')}` |")
            playbook.append(f"| OBFUSCATION | `{cfg.get('obfuscation', '')}` |")
            playbook.append(f"| PE_SANITISE | `{cfg.get('pe_sanitise', True)}` |")
            playbook.append(f"| SIGNING_PROFILE | `{cfg.get('signing_profile', 'none')}` |")
            playbook.append(f"| LITTERBOX_SCAN | `{cfg.get('litterbox_scan', True)}` |")
            playbook.append(f"| SCAN_TYPE | `{cfg.get('scan_type', 'all')}` |")
            playbook.append(f"| OPERATOR_ID | `{operator_id}` |")
            playbook.append(f"| CAMPAIGN_TAG | `{campaign_tag}` |")
            playbook.append("")

        # Delivery options
        playbook.append("## Delivery Options")
        playbook.append("")
        playbook.append(f"**Network constraint:** {net_info['note']}")
        playbook.append("")
        delivery = DELIVERY_OPTIONS.get(edr, [])
        if delivery:
            for d in delivery:
                playbook.append(f"- {d}")
        else:
            playbook.append("- Standard delivery methods apply")
        playbook.append("")

        # Deconfliction
        playbook.append("## Deconfliction")
        playbook.append("")
        playbook.append(f"- **Operator ID:** `{operator_id}`")
        playbook.append(f"- **Campaign Tag:** `{campaign_tag}`")
        playbook.append("- Tag all payloads after build:")
        playbook.append("```bash")
        playbook.append(f"python3 pipeline/tools/deconflict-tag.py tag \\")
        playbook.append(f"    --input loader.exe \\")
        playbook.append(f"    --operator {operator_id} \\")
        playbook.append(f"    --campaign {campaign_tag}")
        playbook.append("```")
        playbook.append("")

        # Cleanup checklist
        playbook.append("## Cleanup Checklist")
        playbook.append("")
        playbook.append("Post-operation cleanup steps:")
        playbook.append("")
        playbook.append("- [ ] Remove all payload files from staging hosts")
        playbook.append("- [ ] Delete shellcode source files from build server")
        playbook.append("- [ ] Rotate Mythic API tokens if used")
        playbook.append("- [ ] Archive build artifacts to `/payloads/archive/`")
        playbook.append("- [ ] Clear Jenkins workspace (`deleteDir()` runs automatically)")
        playbook.append("- [ ] Verify no loader binaries remain on operator workstation")
        playbook.append("- [ ] Document any IOCs generated during the operation")
        playbook.append("- [ ] Update shelf-life data with detection timeline")
        playbook.append("- [ ] Run cleanup automation:")
        playbook.append("  ```bash")
        playbook.append("  bash pipeline/tools/cleanup.sh --max-age 7")
        playbook.append("  ```")
        playbook.append("")

        # Operational notes
        playbook.append("## Operational Notes")
        playbook.append("")
        playbook.append("- Always verify payload with LitterBox scan before deployment")
        playbook.append("- Use `deconflict-tag.py read` to verify tags before delivery")
        playbook.append("- Coordinate with other operators via campaign tag to avoid deconfliction issues")
        playbook.append("- Report detection events to update shelf-life database")
        playbook.append("")

        return "\n".join(playbook)


def main():
    parser = argparse.ArgumentParser(
        description="Generate operator playbook based on target environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --edr crowdstrike --os windows10 --operator ALPHA --campaign EXERCISE-2024
  %(prog)s --edr defender --os windows11 --operator BRAVO --campaign RED-TEAM-Q1 --output playbook.md
  %(prog)s --list-edrs
  %(prog)s --edr elastic --os windows10 --operator CHARLIE --campaign TEST --network airgapped
        """,
    )

    parser.add_argument("--edr", type=str, help="Target EDR platform")
    parser.add_argument("--os", type=str, default="windows10",
                        help="Target OS version (default: windows10)")
    parser.add_argument("--operator", type=str, help="Operator callsign/ID")
    parser.add_argument("--campaign", type=str, help="Campaign tag")
    parser.add_argument("--network", type=str, default="standard",
                        choices=["standard", "airgapped", "monitored", "restricted"],
                        help="Network environment (default: standard)")
    parser.add_argument("--mythic-uuid", type=str, default="",
                        help="Mythic payload UUID to embed in build commands")
    parser.add_argument("--jenkins-url", type=str, default="http://10.5.99.3:8080",
                        help="Jenkins server URL (default: http://10.5.99.3:8080)")
    parser.add_argument("--profiles", type=str, default="pipeline/build-profiles.yml",
                        help="Path to build-profiles.yml")
    parser.add_argument("--shelf-life", type=str, default="/payloads/shelf-life/shelf-life.json",
                        help="Path to shelf-life data JSON")
    parser.add_argument("--output", "-o", type=str, help="Output file path (default: stdout)")
    parser.add_argument("--list-edrs", action="store_true", help="List supported EDR targets")
    parser.add_argument("--json", action="store_true",
                        help="Output recommendations as JSON instead of markdown")

    args = parser.parse_args()

    if args.list_edrs:
        print("Supported EDR Targets:")
        print("")
        for key, info in TARGET_EDRS.items():
            print(f"  {key:15s}  {info['name']}")
            print(f"  {'':15s}  Strengths: {', '.join(info['strengths'])}")
            print(f"  {'':15s}  Weaknesses: {', '.join(info['weaknesses'])}")
            print(f"  {'':15s}  Recommended: {', '.join(info['recommended_profiles'])}")
            if info.get("avoid"):
                print(f"  {'':15s}  Avoid: {', '.join(info['avoid'])}")
            print("")
        return

    if not args.edr:
        parser.error("--edr is required (use --list-edrs to see options)")
    if not args.operator:
        parser.error("--operator is required")
    if not args.campaign:
        parser.error("--campaign is required")

    if args.edr not in TARGET_EDRS:
        parser.error(f"Unknown EDR: {args.edr}. Use --list-edrs to see options.")

    gen = PlaybookGenerator(
        profiles_path=args.profiles,
        shelf_life_path=args.shelf_life,
    )

    if args.json:
        recommendations = gen.recommend(args.edr, args.os, args.network)
        output = json.dumps(recommendations, indent=2, default=str)
    else:
        output = gen.generate_playbook(
            edr=args.edr,
            os_version=args.os,
            operator_id=args.operator,
            campaign_tag=args.campaign,
            network=args.network,
            mythic_uuid=args.mythic_uuid,
            jenkins_url=args.jenkins_url,
        )

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[+] Playbook written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
