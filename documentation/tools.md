# Pipeline Tools Reference

All tools live under `pipeline/tools/`. Python tools require Python 3; shell scripts target Bash.

---

## PE Tools

### pe-sanitise.py

Strips identifying metadata from Windows PE files to reduce static signatures. Accepts one or more PE file paths or glob patterns as positional arguments.

**Flags:**

| Flag | Description |
|------|-------------|
| `--strip-rich` | Zero out the Rich header |
| `--fake-rich` | Replace the Rich header with a plausible fake (VS 2015-2024 tool IDs) |
| `--randomise-timestamp` | Randomise the PE timestamp to a random value |
| `--timestamp-pool` | Pick the timestamp from a curated pool of real VS release dates instead of pure random |
| `--strip-debug` | Null the debug directory entry in the optional header |
| `--strip-pdb-path` | Zero out PDB path strings in CODEVIEW debug entries |
| `--strip-version-info` | Strip the version resource |
| `--randomise-version` | Generate random plausible version info (use with `--version-rc`) |
| `--version-rc` | Output a companion `.rc` resource file with fake version info |
| `--recalc-checksum` | Recalculate and update the PE checksum after modifications |
| `--all` | Apply all sanitisation steps (fake Rich header, pool timestamp, strip debug, strip PDB path, strip version info, recalc checksum) |

`--fake-rich` and `--strip-rich` are mutually exclusive. Under `--all`, the Rich header is faked rather than stripped.

**Examples:**

```bash
# Full sanitisation of a single file
pe-sanitise.py --all loader.exe

# Strip only the Rich header and PDB path
pe-sanitise.py --strip-rich --strip-pdb-path loader.exe

# Fake the Rich header and use a realistic timestamp across a batch
pe-sanitise.py --fake-rich --timestamp-pool payloads/*.exe

# Sanitise and recalculate checksum
pe-sanitise.py --strip-debug --strip-pdb-path --recalc-checksum loader.exe
```

---

### deconflict-tag.py

Embeds deconfliction tags in PE files for operator attribution. Tags are appended as a PE overlay (after the last section) and do not affect execution. Each tag contains the operator ID, campaign name, a Unix timestamp, and a truncated SHA-256 hash for integrity verification.

The overlay format is: `MAAS_TAG_START` + JSON payload + `MAAS_TAG_END`.

**Subcommands:**

**`tag`** -- Embed a new tag in a PE file. Strips any existing tag first.

```bash
deconflict-tag.py tag --input loader.exe --operator red1 --campaign APEX-24
deconflict-tag.py tag -i loader.exe --operator red1 --campaign APEX-24 --output tagged.exe
```

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Path to PE file (required) |
| `--operator` | Operator callsign or ID (required) |
| `--campaign` | Campaign tag (required) |
| `--output`, `-o` | Output path; default is to tag in-place |

**`read`** -- Read and display the tag from a PE file.

```bash
deconflict-tag.py read --input loader.exe
deconflict-tag.py read --input loader.exe --json
```

**`verify`** -- Verify the tag's integrity hash and optionally check expected operator/campaign values.

```bash
deconflict-tag.py verify --input loader.exe
deconflict-tag.py verify --input loader.exe --operator red1 --campaign APEX-24
```

**`strip`** -- Remove the deconfliction tag from a PE file.

```bash
deconflict-tag.py strip --input loader.exe
```

---

### payload-version.py / payload-version.sh

Generates a deterministic version hash from build inputs: source commit, shellcode content, obfuscation profile, and build flags. Identical inputs always produce the same version string for deduplication and rollback.

The version hash is a SHA-256 computed over the concatenation of the git HEAD commit, shellcode file hash, obfuscation profile name, and build flags string.

`payload-version.sh` is a thin shell wrapper that locates Python 3 and passes all arguments through to `payload-version.py`. Use it in pipeline stages where the Python binary path may vary.

**Flags:**

| Flag | Description |
|------|-------------|
| `--source-dir` | Path to source directory for git commit lookup (default: `.`) |
| `--shellcode` | Path to shellcode binary (default: `shellcode/payload.bin`) |
| `--obfuscation` | Obfuscation profile name (default: `none`) |
| `--flags` | Build flags string (default: empty) |
| `--profile` | Build profile name from `build-profiles.yml` |
| `--pe-file` | Path to final PE file for output hash |
| `--output` | Output manifest file path (default: `manifest.json`) |
| `--version-only` | Print only the version hash to stdout, no manifest file |

**Manifest JSON format:**

The output manifest contains the version hash, the individual input hashes (git commit, shellcode SHA-256), the obfuscation profile, build flags, profile name, PE file hash (if provided), and a build timestamp.

**Examples:**

```bash
# Generate a full manifest
payload-version.py --source-dir . --shellcode payload.bin \
    --obfuscation ollvm-full --flags "-O2" --profile evasive-c \
    --output manifest.json

# Get just the version hash for scripting
VERSION=$(payload-version.sh --source-dir . --shellcode payload.bin --version-only)
```

---

## Evasion Tools

### sideload_gen.py

Generates C source, module-definition (.def), and Makefile for a DLL sideloading proxy. The proxy forwards every export to the real DLL (renamed with an `_orig` suffix) while executing embedded shellcode via `DllMain`.

**Supported DLL targets:**

- `version.dll` -- 15 exports (GetFileVersionInfo*, VerFindFile*, VerQueryValue*, etc.)
- `winmm.dll` -- 16 exports (PlaySound*, mciSendCommand*, timeGetTime, waveOut*, etc.)
- `dbghelp.dll` -- 13 exports (MiniDumpWriteDump, SymInitialize, StackWalk64, etc.)
- `amsi.dll` -- 11 exports (AmsiInitialize, AmsiScanBuffer, DllGetClassObject, etc.)
- `userenv.dll` -- 13 exports (CreateEnvironmentBlock, GetUserProfileDirectory*, LoadUserProfile*, etc.)
- `crypt32.dll` -- CertAddCertificateContextToStore, CertCloseStore, and related crypto exports

Use `--list` to see the full export database at runtime.

**Generated file structure:**

```
output/
  proxy.c          -- DllMain with shellcode execution + export forwarders
  proxy.def        -- Module definition file listing all forwarded exports
  Makefile         -- Cross-compilation Makefile for the maas-builder-c Docker image
  shellcode.h      -- Embedded shellcode header (placeholder or from --shellcode-header)
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--target` | Target DLL to proxy, e.g. `version.dll` (required unless `--list`) |
| `--output` | Output directory for generated files (default: `./output`) |
| `--shellcode-header` | Path to a `shellcode.h` file to embed; without this, a placeholder `0xCC` breakpoint is used |
| `--list` | List all supported sideload targets and exit |

**Pipeline integration:**

The pipeline's "Encrypt Shellcode" stage produces `shellcode.h` in the format this generator expects. Compile the output with the `maas-builder-c` Docker image:

```bash
# Generate proxy source for version.dll
sideload_gen.py --target version.dll --output ./loader-sideload-version/

# Generate with real shellcode
sideload_gen.py --target version.dll --shellcode-header shellcode.h --output ./out/

# Compile in the builder container
docker run --rm -v $PWD:/build maas-builder-c make -C /build
```

Copy the generated directory into `loaders/loader-sideload-<target>/` for the `OUTPUT_FORMAT=dll` pipeline path.

---

## Detection and Testing Tools

### yara-gen.py

Extracts unique byte patterns from PE files and produces YARA rules. Useful for checking what AV/EDR signatures target and verifying obfuscation effectiveness across builds.

**Pattern extraction methods:**

The tool parses PE section headers, computes import hashes (imphash), and extracts byte sequences from executable sections. It identifies patterns that are unique to the payload and unlikely to appear in benign software.

**Flags:**

| Flag | Description |
|------|-------------|
| `--input` | Single PE file to analyse (mutually exclusive with `--input-dir`) |
| `--input-dir` | Directory of PE files for batch processing |
| `--output` | Output `.yar` file path (single file mode) |
| `--output-dir` | Output directory for `.yar` files (batch mode) |
| `--name` | YARA rule name (default: `MAAS_Payload`) |
| `--negative` | Generate negative rules -- patterns that should NOT be present after obfuscation |
| `--min-condition` | Minimum number of string matches required in the condition clause (default: 3) |
| `--extensions` | File extensions to process in batch mode, comma-separated (default: `.exe,.dll,.sys,.bin`) |

**Negative rule mode:** When `--negative` is set, the generated rule inverts the condition. If any of the extracted patterns still match the obfuscated binary, the rule fires, indicating the obfuscation did not remove that signature. Run this against pre-obfuscation builds to create a baseline, then scan post-obfuscation output.

**Examples:**

```bash
# Single file rule generation
yara-gen.py --input loader.exe --output loader.yar --name MAAS_Loader_C_OLLVM

# Batch processing an entire build output
yara-gen.py --input-dir /payloads/latest/ --output-dir /payloads/yara/

# Negative rule for obfuscation verification
yara-gen.py --input loader.exe --output negative.yar --name PRE_OBFUSC --negative
```

---

### edr-diff.py

Compares Elastic Security alerts between two payload executions and produces a diff showing new, removed, and common detections. Supports live Elastic queries and pre-saved JSON alert files.

**Elastic connection flags:**

| Flag | Description |
|------|-------------|
| `--elastic-url` | Elasticsearch URL (e.g. `https://10.5.10.100:9200`) |
| `--api-key` | Elastic API key |
| `--username` | Elastic username (default: `elastic`) |
| `--password` | Elastic password |
| `--verify-ssl` | Verify SSL certificates (default: off) |
| `--index` | Override alert index pattern (defaults to `.siem-signals-*` and `.alerts-security.alerts-*`) |

**Time-window query mode:**

| Flag | Description |
|------|-------------|
| `--before-start` | Start of the "before" time window (ISO-8601) |
| `--before-end` | End of the "before" time window |
| `--after-start` | Start of the "after" time window |
| `--after-end` | End of the "after" time window |

**File-based comparison:**

| Flag | Description |
|------|-------------|
| `--before-file` | JSON file with "before" alerts |
| `--after-file` | JSON file with "after" alerts |

**Filters:**

| Flag | Description |
|------|-------------|
| `--host` | Filter alerts by hostname |
| `--process` | Filter alerts by process name |

**Output:**

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output path for the diff report JSON (default: `diff-report.json`) |
| `--save-alerts` | Save the raw alert sets alongside the diff |

The diff report JSON groups alerts into `new` (appeared only after the change), `removed` (no longer triggered), and `common` (present in both windows).

**Examples:**

```bash
# Live query comparing two time windows
edr-diff.py --elastic-url https://10.5.10.100:9200 \
    --before-start "2024-01-01T00:00:00" --before-end "2024-01-01T00:05:00" \
    --after-start "2024-01-01T01:00:00" --after-end "2024-01-01T01:05:00" \
    --output diff-report.json

# File-based comparison
edr-diff.py --before-file alerts-v1.json --after-file alerts-v2.json \
    --output diff-report.json
```

---

### sigma-coverage.py

Maps LitterBox scan results and Elastic alerts to public Sigma rules. Loads Sigma rules from a local SigmaHQ clone or falls back to a curated built-in list of rules relevant to shellcode loader detection.

**Matching strategies:**

1. **MITRE technique ID** -- Matches detections to Sigma rules that share the same ATT&CK technique ID (e.g. T1055, T1055.001).
2. **Fuzzy title matching** -- Compares alert/detection names against Sigma rule titles using substring and token overlap.
3. **Keyword overlap** -- Each curated rule carries a keyword list; detections are matched when their description or alert name shares keywords.

**Flags:**

| Flag | Description |
|------|-------------|
| `--litterbox-results` | Path to LitterBox scan results JSON |
| `--elastic-alerts` | Path to Elastic alerts JSON |
| `--sigma-dir` | Path to a local SigmaHQ rules directory (e.g. `/opt/sigma/rules/windows/`) |
| `--curated-only` | Use only the built-in curated rule set, skip loading from `--sigma-dir` |
| `--output`, `-o` | Output path for the coverage report JSON (default: `coverage-report.json`) |

**Built-in rule fallback:** When no `--sigma-dir` is provided (or `--curated-only` is set), the tool uses a hardcoded list of Sigma rules covering process injection, suspicious syscalls, memory allocation, and related techniques. Requires `pyyaml` only when loading rules from a SigmaHQ directory.

**Examples:**

```bash
# With a local Sigma repo
sigma-coverage.py --litterbox-results scan.json \
    --elastic-alerts alerts.json \
    --sigma-dir /opt/sigma/rules/windows/ \
    --output coverage-report.json

# Using built-in curated rules only
sigma-coverage.py --litterbox-results scan.json \
    --elastic-alerts alerts.json \
    --output coverage-report.json
```

---

### shelf-life.py

Tracks payload shelf life: the time from build to first detection. Maintains a JSON database of payload builds and their scan history, recording when each AV engine first detects each payload variant.

**Database location:** Default path is `payloads/shelf-life/shelf-life.json`. Override with `--db`.

**Subcommands:**

**`register`** -- Register a new payload build in the database.

| Flag | Description |
|------|-------------|
| `--version` | Unique build identifier / hash (required) |
| `--profile` | Build profile name (required) |
| `--build-time` | Build timestamp in ISO-8601 (required) |
| `--notes` | Optional notes |

**`scan`** -- Record a LitterBox scan result against a registered payload.

| Flag | Description |
|------|-------------|
| `--version` | Payload version hash (required) |
| `--results` | Path to LitterBox scan results JSON |
| `--scan-time` | Scan timestamp (default: now) |

**`report`** -- Generate shelf-life reports.

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output file path (default: `shelf-life-report.json`) |
| `--format` | Output format: `json` or `markdown` (default: `json`) |

**`status`** -- Show status of a specific payload.

| Flag | Description |
|------|-------------|
| `--version` | Payload version hash (required) |

**`list`** -- List all tracked payloads.

**Examples:**

```bash
shelf-life.py register --version abc123 --profile evasive-c \
    --build-time "2024-01-01T00:00:00"

shelf-life.py scan --version abc123 --results scan.json

shelf-life.py report --format markdown --output shelf-life-report.md

shelf-life.py status --version abc123

shelf-life.py list
```

---

### regression-report.py

Compares current LitterBox scan results against a stored baseline and produces a markdown report showing per-profile detection deltas. Used in the regression pipeline stage to gate builds.

**Exit codes:**
- `0` -- All profiles within threshold (or no baseline to compare)
- `1` -- One or more profiles regressed beyond the allowed threshold

**Flags:**

| Flag | Description |
|------|-------------|
| `--baseline` | Path to baseline JSON file (required) |
| `--current` | Path to current results JSON file (required) |
| `--threshold` | Max allowed detection increase before flagging regression (default: 2) |
| `--output` | Output path for the markdown report (default: `regression-report.md`) |
| `--json-output` | Output path for the structured JSON comparison (default: `regression-comparison.json`) |

**Report format:**

The markdown report includes build numbers, the detection threshold, a summary table (passed / improved / regressed / new), and a per-profile detail table with baseline detections, current detections, delta, and status (PASS, IMPROVED, REGRESSED, NEW, REMOVED, SKIPPED).

**Example:**

```bash
regression-report.py --baseline /payloads/baseline.json \
    --current /payloads/scan-results/latest.json \
    --threshold 2 \
    --output regression-report.md
```

If no baseline file exists, the tool prints a message suggesting `UPDATE_BASELINE=true` and exits 0 (no regression to compare against).

---

## Operational Tools

### playbook-gen.py

Recommends the best loader and obfuscation combination for a given EDR target, then produces a markdown playbook with build commands and delivery guidance.

**Supported EDR targets:**

| Target | EDR Product | Key Strengths | Recommended Profiles |
|--------|-------------|---------------|----------------------|
| `crowdstrike` | CrowdStrike Falcon | Memory scanning, behavioral, ML | evasive-c-heavy, packed-ollvm |
| `defender` | Microsoft Defender | AMSI, static signatures, cloud lookup | evasive-c, garble-go, packed-c |
| `sentinelone` | SentinelOne | Behavioral AI, static AI, memory scanning | evasive-c-heavy, packed-ollvm |
| `elastic` | Elastic Security | Behavioral rules, YARA, memory scanning | evasive-c, evasive-c-heavy |
| `carbon_black` | VMware Carbon Black | Behavioral, reputation | evasive-c-signed, packed-ollvm |

Use `--list-edrs` to print the current list.

**Flags:**

| Flag | Description |
|------|-------------|
| `--edr` | Target EDR platform (see table above) |
| `--os` | Target OS (default: `windows10`; also: `windows11`, `windows2016/2019/2022`) |
| `--operator` | Operator callsign/ID |
| `--campaign` | Campaign tag |
| `--network` | Network type: `standard` or `airgapped` (default: `standard`) |
| `--mythic-uuid` | Mythic payload UUID |
| `--jenkins-url` | Jenkins URL (default: `http://10.5.99.3:8080`) |
| `--profiles` | Path to build-profiles.yml (default: `pipeline/build-profiles.yml`) |
| `--shelf-life` | Path to shelf-life database (default: `/payloads/shelf-life/shelf-life.json`) |
| `--output`, `-o` | Output file path (default: stdout) |
| `--list-edrs` | List supported EDR targets and exit |
| `--json` | Output as JSON instead of markdown |

**Scoring algorithm:** Profiles are scored against the target EDR based on the EDR's known strengths and weaknesses, the profile's obfuscation level, shelf-life history (if available), and OS compatibility. The playbook recommends the top-scoring profiles and includes delivery method suggestions tailored to each EDR.

**Example:**

```bash
playbook-gen.py --edr crowdstrike --os windows11 \
    --operator red1 --campaign APEX-24 \
    --output playbook.md
```

---

### cleanup.sh

Automated cleanup of old payloads, Jenkins builds, stale Mythic callbacks, unused Docker images, and oversized build caches.

**Usage:** `cleanup.sh [--dry-run] [--max-age DAYS] [--max-count N]`

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | off | Show what would be deleted without deleting |
| `--max-age` | 30 days | Delete artifacts older than N days |
| `--max-count` | 50 | Keep at most N artifacts per loader |
| `--payloads` | `/payloads` | Payloads directory |
| `--jenkins` | `http://10.5.99.3:8080` | Jenkins URL |
| `--mythic` | `https://10.5.99.6:7443` | Mythic URL |

**What it cleans:**

- Old payload files beyond `--max-age` or `--max-count`
- Jenkins build artifacts
- Stale Mythic callbacks
- Unused Docker images
- Build caches exceeding the size warning threshold (default: 5 GB, controlled by `CACHE_WARN_GB`)

Logs to `/var/log/maas/cleanup-<timestamp>.log`.

---

### backup-restore.sh

Backup and restore for the range's core services.

**Usage:** `backup-restore.sh backup|restore|list|prune [target] [timestamp]`

**Targets:** `all`, `forgejo`, `jenkins`, `mythic`, `payloads`

**Commands:**

| Command | Description |
|---------|-------------|
| `backup <target>` | Back up the specified target (or `all`) to `/var/backups/maas/` |
| `restore <target> <timestamp>` | Restore a target from a timestamped backup |
| `list` | List available backups |
| `prune <days>` | Remove backups older than N days |

**What each target backs up:**

- **forgejo** -- Gitea data directory (`/var/lib/gitea`) via SSH to `10.5.99.2`
- **jenkins** -- Jenkins home (`/var/lib/jenkins`) and job configs
- **mythic** -- PostgreSQL database dump (`mythic_db`) via SSH to `10.5.99.6`
- **payloads** -- The `/payloads` directory

**Examples:**

```bash
backup-restore.sh backup all
backup-restore.sh backup forgejo
backup-restore.sh restore forgejo 20260917_143000
backup-restore.sh list
backup-restore.sh prune 30
```

---

### backup-cron.sh

Cron wrapper that runs a full backup (`backup all`) followed by a prune of backups older than 30 days. Install via crontab on a runner or the Jenkins host:

```
0 2 * * * /path/to/pipeline/tools/backup-cron.sh >> /var/log/maas-backup.log 2>&1
```

---

## Infrastructure Tools

### runner-scale.sh

Manages scaling of a third Linux Jenkins agent (`runner-lin03`) based on current queue depth and agent load. Reads its configuration from `runner-scale-config.yml`.

**Usage:** `runner-scale.sh up|down|status`

**Commands:**

| Command | Description |
|---------|-------------|
| `status` | Show current queue depth, agent load, and whether the scale node is online |
| `up` | Register and bring online `runner-lin03` as an additional Jenkins agent |
| `down` | Take `runner-lin03` offline and remove it from Jenkins |

**Third runner configuration** (from `runner-scale-config.yml`):

| Parameter | Value |
|-----------|-------|
| Node name | `runner-lin03` |
| Host | `10.5.99.8` |
| Labels | `linux-c linux-go linux-rust linux-nim linux-generic` |
| Executors | 2 |
| Remote root | `/opt/jenkins-agent` |
| Credentials ID | `jenkins-ssh` |

The config file also includes a commented Ludus range entry for provisioning the runner VM (Debian 13, 8 GB RAM, 4 CPUs, VLAN 99, IP `.8`) with the `ludus_jenkins_agent` and `ludus_maas_builders` roles.

---

### cache-init.sh

Creates build cache directories under `/var/cache/maas/` and sets ownership to UID/GID `989:989` (the Jenkins agent user). Run on each Jenkins agent host.

**Cache directories created:**

- `nimble` -- Nim package cache
- `nim-cache` -- Nim compilation cache
- `gomod` -- Go module cache
- `gobuild` -- Go build cache
- `cargo-registry` -- Rust crate registry
- `cargo-git` -- Rust git dependency cache
- `nuget` -- .NET NuGet package cache

---

## Monitoring

### Grafana Dashboard

A pre-built Grafana dashboard (`grafana/dashboard.json`) for monitoring pipeline health, detection metrics, and infrastructure status. It uses the `marcusolsson-json-datasource` plugin to read metrics from a JSON file written by the metrics collector.

**Dashboard layout -- 4 rows, 14 panels:**

**Row 1: Build Pipeline Metrics**
- Build Success/Failure Rate (donut chart)
- Build Duration Over Time
- Builds Per Day
- Build Queue Depth

**Row 2: LitterBox Scan Results**
- Detection Rate Over Time
- Detection Heatmap
- Best Performing Profiles
- Detection Rate by Obfuscation Type

**Row 3: Payload Shelf Life**
- Average Shelf Life by Profile
- Shelf Life Trend
- First Detection Engines

**Row 4: Infrastructure**
- Runner Status
- Docker Cache Usage
- Disk Usage

---

### metrics-collector.py

Collects pipeline metrics for the Grafana dashboard. Reads from the Jenkins API, on-disk LitterBox scan results, shelf-life database, and version manifests. Writes a unified `metrics.json` consumed by the Grafana JSON API datasource.

**Data sources:**

- Jenkins API (`http://10.5.99.3:8080`) -- build results, durations, queue depth
- LitterBox scan results (`/payloads/scan-results/`) -- detection rates, engine/payload matrix
- Shelf-life database (`/payloads/shelf-life/shelf-life.json`) -- shelf-life trends, first-detection engines
- Build caches (`/var/cache/maas/*`) -- cache size metrics
- Archive directory (`/payloads/archive/`) -- disk usage

**Usage:**

```bash
metrics-collector.py --jenkins-url http://10.5.99.3:8080 \
    --output-dir /var/lib/grafana/data/maas/
```

Typically run via cron every 5 minutes:

```
*/5 * * * * /opt/maas/metrics-collector.py \
    --jenkins-url http://10.5.99.3:8080 \
    --output-dir /var/lib/grafana/data/maas/ 2>&1 | logger -t maas-metrics
```

---

### setup.sh (Grafana)

Installs and provisions Grafana on a Debian/Ubuntu monitoring host. Steps:

1. Install Grafana OSS (from the official APT repo, if not already installed)
2. Install required plugins: `marcusolsson-json-datasource`, `yesoreyeram-infinity-datasource`
3. Deploy provisioning configs for datasources and dashboards from `grafana/provisioning/`
4. Copy `dashboard.json` to `/var/lib/grafana/dashboards/maas/`
5. Deploy `metrics-collector.py` to `/opt/maas/`
6. Run an initial metrics collection (writes empty metrics if Jenkins is not reachable yet)
7. Install a cron job to run the collector every 5 minutes
8. Fix permissions and restart Grafana

**Provisioning config files** (under `grafana/provisioning/`):

- `datasources/maas.yml` -- Configures the JSON API datasource pointing at `/var/lib/grafana/data/maas/`
- `dashboards/maas.yml` -- Tells Grafana where to find the dashboard JSON

---

## Code Signing

### signing-setup.md

Documents how to set up Limelighter for PE code signing. Limelighter generates fake code-signing certificates and signs PE files to evade static analysis that checks for valid signatures.

**Installation options:**

1. Add to the `maas-builder-go` Docker image via `go install github.com/Tylous/Limelighter@latest`
2. Manual build from the GitHub repository

**Dependencies:** Go 1.17+ and OpenSSL libraries (`libssl-dev` / `openssl`).

**Usage:**

```bash
# Clone a real certificate from a domain
Limelighter -I input.exe -O output.exe -Domain www.microsoft.com -Real

# Self-signed certificate with a custom domain
Limelighter -I input.exe -O output.exe -Domain internal-tools.contoso.com -Password changeme
```

Predefined signing profiles are in `signing-profiles.yml`. The Jenkins pipeline reads the selected profile and passes the appropriate flags to Limelighter.
