# Infrastructure, Deployment, and Operations

This document covers the Labyrinth range architecture, Docker builder images, build caching, runner management, backup/restore, monitoring, cleanup automation, and multi-architecture support.

---

## Range Architecture

The range is deployed on Ludus and organised into two VLANs:

- **VLAN 10** -- Target network. Contains the Elastic stack, EDR-monitored victims, and unmonitored victims.
- **VLAN 99** -- Infrastructure network. Contains Forgejo, Jenkins, Mythic, build runners, LitterBox, the operator workstation, and supporting services.

### IP Addressing

All IPs follow the pattern `10.<range_second_octet>.<vlan>.<host>`, where `range_second_octet` is the Ludus range-specific octet.

### Host Table

| VM Name | VLAN | Last Octet | Template | Role |
|---------|------|-----------|----------|------|
| `elastic` | 10 | 10 | Debian 12 | Elastic Stack (Elasticsearch + Kibana) v9.4.4. 16 GB RAM, 4 CPUs. |
| `victimEDR` | 10 | 11 | Win11 22H2 Enterprise | EDR-monitored target. Elastic Agent + LitterBox Whiskers agent + threat hunting agent. Reports to threat hunting sensor on VLAN 99. |
| `victim` | 10 | 12 | Win11 22H2 Enterprise | Unmonitored target (no EDR agent). Threat hunting agent only. |
| `forgejo` | 99 | 2 | Debian 12 | Forgejo Git server. HTTP on port 3000. Hosts the MAAS repository. |
| `jenkins` | 99 | 3 | Debian 12 | Jenkins CI server. HTTP on port 8080. Orchestrates the entire build pipeline. |
| `runner-lin01` | 99 | 4 | Debian 13 | Linux build runner. 8 GB RAM, 4 CPUs. Labels: `linux-c linux-go linux-rust linux-generic`. 2 executors. |
| `runner-lin02` | 99 | 5 | Debian 13 | Linux build runner (identical to lin01). |
| `mythic` | 99 | 6 | Ubuntu 24.04 | Mythic C2 teamserver. 16 GB RAM, 8 CPUs. Agents: Forge, Starburst, Erebus, Ariadne, Sphinx, Daedalus. C2 profiles: HTTP, SMB. |
| `runner-win01` | 99 | 7 | Win Server 2022 | Windows build runner. Labels: `windows-msvc windows-dotnet`. 2 executors. MSVC Build Tools installed. |
| `runner-lin03` | 99 | 8 | Debian 13 | Auto-scaled third Linux runner (not always active). See Runner Management below. |
| `commando` | 99 | 10 | Commando VM | Operator workstation. Pre-configured offensive tooling. |
| `litterbox` | 99 | 12 | Win Server 2022 | LitterBox sandbox for payload scanning. Listens on port 1337. Elastic integration enabled (reports to Elastic on VLAN 10). |
| `threathunting` | 99 | 13 | Ubuntu 24.04 | Threat hunting sensor. Runs RITA for beacon detection. Accepts mirrored PCAP streams. |

---

## Docker Builder Images

Each language toolchain runs inside a dedicated Docker container on the Linux runners. The `whispergate.ludus_maas_builders` Ansible role pulls these images onto each runner host.

| Image | Contents |
|-------|----------|
| `maas-builder-c` | MinGW cross-compiler (`x86_64-w64-mingw32-gcc`), Clang with OLLVM pass plugin (`/opt/ollvm/lib/libOLLVMPipeline.so`), Shellcrypt for shellcode encryption. Handles both `c-mingw` and `c-ollvm` builds. |
| `maas-builder-go` | Go toolchain with Garble installed. Cross-compiles to `GOOS=windows` for both `amd64` and `arm64`. |
| `maas-builder-rust` | Rust toolchain with `x86_64-pc-windows-gnu` and `aarch64-pc-windows-gnu` cross-compilation targets. |
| `maas-builder-calypso` | C++23 toolchain with Calypso packer installed. Includes MinGW for cross-compiling generated loaders. |

### Container UID

Jenkins runs all Docker containers as UID 989, GID 989. All cache volumes and output directories must be owned by `989:989` for the builds to write successfully.

---

## Build Caching

Builder containers mount host-side cache volumes to avoid re-downloading dependencies on every build.

### Volume Mounts (from Jenkinsfile)

| Builder | Host Path | Container Path |
|---------|----------|----------------|
| `maas-builder-go` | `/var/cache/maas/gomod` | `/go/pkg/mod` |
| `maas-builder-go` | `/var/cache/maas/gobuild` | `/root/.cache/go-build` |


Calypso (`maas-builder-calypso`) has no persistent cache requirements and does not need volume mounts.

### Initialising Caches

Run `cache-init.sh` on each Jenkins agent host to create the cache directories with correct ownership:

```bash
pipeline/tools/cache-init.sh
```

This creates the following directories under `/var/cache/maas/` and sets ownership to `989:989`:

- `gomod`, `gobuild` (Go)
- `cargo-registry`, `cargo-git` (Rust)
- `nuget` (.NET)

---

## Runner Management

### Current Runners

| Runner | Labels | Host | Executors |
|--------|--------|------|-----------|
| `runner-lin01` | `linux-c linux-go linux-rust linux-generic` | `10.<range_second_octet>.99.4` | 2 |
| `runner-lin02` | `linux-c linux-go linux-rust linux-generic` | `10.<range_second_octet>.99.5` | 2 |
| `runner-win01` | `windows-msvc windows-dotnet` | `10.<range_second_octet>.99.7` | 2 |

### Auto-Scaling (runner-lin03)

A third Linux runner (`runner-lin03`) can be brought up or down based on queue depth and agent load using `runner-scale.sh`:

```bash
pipeline/tools/runner-scale.sh up      # Register and bring online
pipeline/tools/runner-scale.sh down    # Take offline and remove
pipeline/tools/runner-scale.sh status  # Check current state
```

The scale runner lives at `10.<range_second_octet>.99.8` (last octet 8) and carries the same labels as the other Linux runners: `linux-c linux-go linux-rust linux-generic` with 2 executors.

Configuration is in `pipeline/tools/runner-scale-config.yml`. The runner connects to Jenkins via SSH using the `jenkins-ssh` credential ID.

The `Jenkinsfile.scale` pipeline wraps this script for automated triggering based on queue depth.

### Adding runner-lin03 to the Range

To make the runner permanent, add its VM definition to `range-config.yml` (the commented-out block in `runner-scale-config.yml` provides the template) with the `whispergate.ludus_jenkins_agent` and `whispergate.ludus_maas_builders` roles.

---

## Backup and Restore

The `backup-restore.sh` script manages backups for four targets:

### Targets

| Target | What Gets Backed Up |
|--------|-------------------|
| `forgejo` | Forgejo data directory (`/var/lib/gitea`) via Forgejo's built-in dump command. Backed up from `10.<range_second_octet>.99.2`. |
| `jenkins` | Jenkins home directory (`/var/lib/jenkins`) -- jobs, configurations, credentials. Backed up from `10.<range_second_octet>.99.3`. |
| `mythic` | Mythic PostgreSQL database (`mythic_db`). Backed up from `10.<range_second_octet>.99.6` via `pg_dump`. |
| `payloads` | Built payload artifacts from `/payloads`. |

All backups are stored under `/var/backups/maas/` with timestamps in `YYYYMMDD_HHMMSS` format.

### Usage

```bash
# Back up everything
backup-restore.sh backup all

# Back up a single target
backup-restore.sh backup forgejo

# Restore a specific backup by timestamp
backup-restore.sh restore forgejo 20260917_143000

# List available backups
backup-restore.sh list

# Prune backups older than N days
backup-restore.sh prune 30
```

### Cron Scheduling

Set up a cron job on the machine that has SSH access to all infrastructure hosts. Example for daily full backups:

```
0 3 * * * /path/to/backup-restore.sh backup all 2>&1 | logger -t maas-backup
```

---

## Monitoring (Grafana)

### Setup

Run `pipeline/tools/grafana/setup.sh` on the designated monitoring host (any Debian/Ubuntu machine with network access to Jenkins). The script:

1. Installs Grafana OSS from the official APT repository (if not already installed).
2. Installs required Grafana plugins: `marcusolsson-json-datasource` and `yesoreyeram-infinity-datasource`.
3. Deploys provisioning configurations for datasources and dashboards to `/etc/grafana/provisioning/`.
4. Deploys the MAAS dashboard JSON to `/var/lib/grafana/dashboards/maas/`.
5. Deploys the metrics collector script to `/opt/maas/metrics-collector.py`.
6. Runs an initial metrics collection against Jenkins.
7. Installs a cron job that runs the metrics collector every 5 minutes.
8. Fixes file permissions and restarts Grafana.

### Dashboard

The MAAS Grafana dashboard provides:

- Build history and success/failure rates by profile and obfuscation type.
- LitterBox scan results, detection rates over time, and per-engine detection matrices.
- Shelf-life tracking (how long payloads survive before detection).
- Infrastructure metrics: runner status, cache usage, disk usage, and queue depth.
- Filtering by obfuscation profile (`ollvm-cff`, `ollvm-bcf-cff`, `ollvm-full`, `ollvm-heavy`, `garble-literals`, `string-encrypt`, `calypso`).

### Metrics Collector

The Python script (`metrics-collector.py`) polls Jenkins's API for build data, LitterBox for scan results, and infrastructure hosts for resource usage. Output is written as JSON to `/var/lib/grafana/data/maas/metrics.json`, which Grafana reads via the JSON datasource plugin.

---

## Cleanup

The `cleanup.sh` script removes old artifacts to prevent disk exhaustion. It cleans:

- **Payloads**: Files in `/payloads` older than `MAX_AGE` days (default: 30) or exceeding `MAX_COUNT` per loader (default: 50).
- **Jenkins builds**: Old build records via the Jenkins API.
- **Mythic callbacks**: Stale callback data via the Mythic API.
- **Docker images**: Unused images on runner hosts.
- **Build caches**: Warns when any cache directory exceeds `CACHE_WARN_GB` (default: 5 GB).

### Usage

```bash
# Preview what would be deleted
cleanup.sh --dry-run

# Run with defaults (30-day retention, 50 max per loader)
cleanup.sh

# Custom retention
cleanup.sh --max-age 14 --max-count 25
```

All actions are logged to `/var/log/maas/cleanup-<timestamp>.log`.

### Scheduled Pipeline

The `Jenkinsfile.cleanup` pipeline wraps `cleanup.sh` and is typically configured as a weekly cron trigger in Jenkins (e.g., `H H(2-4) * * 0` for Sunday night).

---

## Multi-Architecture Support

The pipeline supports ARM64 cross-compilation for Go, Rust, C (MinGW), and C# loaders via the `TARGET_ARCH` parameter.

### ARM64 Build Profiles

| Profile | Language | Notes |
|---------|----------|-------|
| `garble-go-arm64` | Go (Garble) | Sets `GOARCH=arm64`. Full Garble obfuscation (literals, tiny). |
| `rust-loader-arm64` | Rust | Cross-compiles to `aarch64-pc-windows-gnu`. |
| `mingw-c-arm64` | C (MinGW) | Uses `aarch64-w64-mingw32` toolchain prefix. No OLLVM (OLLVM does not support ARM64 targets). |
| `dotnet-loader-arm64` | C# | Self-contained trimmed publish for `win-arm64` RID. |

### Toolchain Differences

- **Go**: Only `GOARCH` changes. Garble and all build flags work identically.
- **Rust**: Requires the `aarch64-pc-windows-gnu` target installed in the `maas-builder-rust` image.
- **C (MinGW)**: The toolchain prefix switches from `x86_64-w64-mingw32` to `aarch64-w64-mingw32` for both GCC and Clang `--target`. OLLVM obfuscation is not available for ARM64 builds.
- **C# (.NET)**: Uses the `win-arm64` runtime identifier with self-contained trimmed publish.

### Limitations

- **No OLLVM on ARM64**: The OLLVM pass plugin targets x86_64 only. ARM64 C builds use MinGW without obfuscation.
- **No LitterBox scanning**: ARM64 payloads have `litterbox_scan: false` because no ARM64 sandbox is available. Only `static` scan type is used (signature-based, no dynamic execution).
- **No Calypso on ARM64**: Calypso packing is x86_64 only.
