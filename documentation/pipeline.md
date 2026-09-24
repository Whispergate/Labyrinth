# CI/CD Pipeline

The Labyrinth build system is a set of Jenkins pipelines that compile loader source into signed, obfuscated, and scanned payloads. Everything runs on Linux Docker agents (with the exception of C# builds, which use a Windows .NET agent) and produces Windows PE artifacts.

## Pipeline Overview

There are three ways to trigger a build:

1. **Push-to-build (Jenkins webhook)** -- A push to a loader repo fires the main `Jenkinsfile`. The pipeline resolves the loader directory from the `LANGUAGE` parameter or the job name (stripping any `loader-` prefix if needed). It validates that the loader directory contains a `build.sh` and `loader.yml` before proceeding.

2. **Daedalus / tool build (`Jenkinsfile.tooling`)** -- Both Daedalus `buildWithParameters` dispatches and mirrored tool repos use the same `Jenkinsfile.tooling` pipeline. It clones a repo, compiles it with the specified language toolchain, optionally obfuscates (ConfuserEx, Garble, Calypso) and signs the output, then archives the artifact. This path does not fetch shellcode from Mythic.

---

## Main Pipeline (Jenkinsfile)

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `LANGUAGE` | string | (empty) | Loader directory name (e.g. `loader-c-mingw`, `loader-rust`). Also accepts the short form (`c-mingw`, `rust`) for backwards compatibility. When empty, the pipeline resolves the loader from the job name. |
| `OUTPUT_FORMAT` | choice | `exe` | Output format. Choices: `exe`, `dll`, `shellcode` |
| `OBFUSCATION` | choice | `none` | Obfuscation profile. Choices: `none`, `ollvm-cff`, `ollvm-bcf-cff`, `ollvm-full`, `ollvm-heavy`, `garble-literals`, `string-encrypt`, `calypso` |
| `CALYPSO_MODE` | choice | `pack` | Calypso mode. `pack` wraps the compiled custom loader in Calypso (loader-in-loader). `standalone` feeds raw shellcode to Calypso and uses Calypso's own loader (single loader, lower detection). Only applies when `OBFUSCATION` is `calypso`. |
| `PACKER_PRESET` | string | (empty) | Named packer preset from `build-profiles.yml`. Resolved to flags at build time. Choices: `none`, `fast`, `stealth`, `stealth-obfuscated`, `evasive`, `evasive-drip`, `minimal`. Ignored if `PACKER_FLAGS` is set. |
| `PACKER_FLAGS` | string | (empty) | Raw Calypso flags (e.g. `--unhook ntdll.dll --amsi hwbp --etw hwbp --sleep 10`). Overrides `PACKER_PRESET` if both are set. |
| `SHELLCODE_PATH` | string | (empty) | Path to shellcode binary (relative to repo) |
| `MYTHIC_PAYLOAD_UUID` | string | (empty) | Mythic payload UUID to fetch shellcode from |
| `LITTERBOX_SCAN` | boolean | `true` | Submit to LitterBox after build |
| `SCAN_TYPE` | choice | `all` | LitterBox scan profile. Choices: `all`, `static`, `dynamic`, `edr` |
| `PE_SANITISE` | boolean | `true` | Strip PE metadata post-build |
| `SIGNING_PROFILE` | string | `none` | Code signing profile: `microsoft`, `google`, `intel`, `custom`, `none` |
| `TARGET_ARCH` | choice | `amd64` | Target architecture. Choices: `amd64`, `arm64` |
| `OPERATOR_ID` | string | (empty) | Operator callsign for deconfliction tagging |
| `CAMPAIGN_TAG` | string | (empty) | Campaign identifier for deconfliction tagging |

### Environment / Credentials

The pipeline pulls three secrets from the Jenkins credential store:

- `litterbox-url` -- Base URL of the LitterBox scanning service
- `mythic-url` -- Base URL of the Mythic C2 server
- `mythic-api-token` -- API token for Mythic payload download

Artifacts are written to `/payloads/${BUILD_TAG}`.

### Stages

**1. Checkout** -- Checks out the SCM source on a `linux-generic` node, stashes everything as `source`. Resolves the loader directory from the `LANGUAGE` parameter or the job name pattern `loader-<name>`. Validates that the resolved directory contains `build.sh` and `loader.yml`. In Calypso standalone mode, loader directory validation is skipped since no custom loader is used.

**2. Fetch Mythic Payload** -- Conditional: runs only when `MYTHIC_PAYLOAD_UUID` is provided. Downloads the raw shellcode binary from the Mythic API to `shellcode/payload.bin` and stashes it.

**3. Encrypt Shellcode** -- Conditional: skipped when `CALYPSO_MODE` is `standalone` (Calypso handles shellcode encryption directly). Otherwise, runs on the `maas-builder-c` Docker image. Generates a random 32-byte XOR key and uses Shellcrypt to produce encrypted shellcode in four formats: C header (`.h`), Go source (`.go`), Rust source (`.rs`), and C# source (`.cs`). If no shellcode file exists, it writes a single `0xCC` byte as a placeholder. Stashes the result as `encrypted-shellcode`.

**4. Build** -- Conditional: skipped when `CALYPSO_MODE` is `standalone` (Calypso uses its own loader). Otherwise, a single generic build stage that delegates to the loader's own `build.sh` script. The stage reads `loader.yml` from the loader directory to determine the Docker image, agent label, shellcode destination, shellcode format, and volume mounts. It copies the encrypted shellcode to the path specified by `shellcode_dest`, then executes `build.sh <output_format> <target_arch> <obfuscation>`.

Each loader's `loader.yml` declares:

| Field | Description |
|---|---|
| `docker_image` | Docker image to run the build in (e.g. `maas-builder-c`, `maas-builder-go`) |
| `agent_label` | Jenkins agent label (e.g. `linux-c`, `linux-go`) |
| `shellcode_dest` | Where to copy the encrypted shellcode (e.g. `src/shellcode.h`) |
| `shellcode_format` | Shellcode format to use (`c`, `go`, `rust`, `csharp`) |
| `volumes` | Additional Docker volume mounts for caching |

Each loader's `build.sh` receives three positional arguments: output format (`exe`, `dll`, `shellcode`), target architecture (`amd64`, `arm64`), and obfuscation profile. The script handles all compilation logic internally.

The build output is stashed as `artifact`.

**5. Pack - Calypso** -- Conditional: runs only when `OBFUSCATION == 'calypso'`. Runs on `maas-builder-calypso`. Operates in two modes controlled by `CALYPSO_MODE`:

- **`pack`** (default): Wraps the compiled custom loader PE inside Calypso's own loader (loader-in-loader). Uses `--peinject` for native PEs or `--type csharp` for .NET assemblies. This double-layer increases binary complexity but may also increase detection signatures from stacking two loaders.
- **`standalone`**: Feeds raw shellcode directly to Calypso with `--type shellcode`. Calypso generates a single executable using its own C++23 loader with built-in evasion (indirect syscalls, AMSI/ETW bypass, sleep delay, etc.). No custom loader is compiled. This produces a single-layer loader with a smaller detection footprint.

Flag resolution order: explicit `PACKER_FLAGS` parameter, then `PACKER_PRESET` (resolved from `packer_presets` in `build-profiles.yml`), then Calypso's built-in defaults. If an unknown preset name is given, the build fails with the list of available presets.

**6. PE Sanitisation** -- Conditional: runs when `PE_SANITISE` is true. Runs `pe-sanitise.py` with `--strip-rich --randomise-timestamp --strip-debug --strip-version-info` to remove forensic indicators from the PE headers.

**7. Sign - Limelighter** -- Conditional: runs when `SIGNING_PROFILE` is not `none`. Runs on `maas-builder-go`. Loads the signing profile from `pipeline/tools/signing-profiles.yml`. For `real` mode profiles, Limelighter clones the TLS certificate from the target domain. For `self-signed` mode, it generates a self-signed certificate with the configured domain and password.

**8. Checksum** -- Computes SHA-256 checksums for all `loader.*` files. Stashes the final artifacts as `final`. The checksum stage cascades through stash names: it tries `signed`, then `sanitised`, then `artifact`.

**9. Deconfliction Tag** -- Conditional: runs when both `OPERATOR_ID` and `CAMPAIGN_TAG` are provided. Embeds operator and campaign metadata into the artifact using `deconflict-tag.py`, then recomputes checksums.

**10. Version Manifest** -- Generates `manifest.json` via `payload-version.py` containing the source directory hash, shellcode reference, obfuscation settings, profile name, and PE file hash. Archived as a Jenkins artifact.

**11. LitterBox Scan** -- Conditional: runs when `LITTERBOX_SCAN` is true. Uploads the final artifact to LitterBox and triggers scans based on `SCAN_TYPE`:
- `static` -- AV signature scan only
- `dynamic` -- Sandbox detonation with polling (5-minute timeout, exponential backoff)
- `edr` -- Iterates all configured EDR profiles, waits 60 seconds per profile for agent telemetry
- `all` -- Runs static, dynamic, and all EDR scans sequentially

If the risk level comes back `critical` or `high`, the build is marked unstable (not failed).

**12. Archive** -- Copies `loader.*`, `checksums.sha256`, and `manifest.json` to `${ARTIFACT_DIR}` on the shared `/payloads` volume and archives them in Jenkins.

### Post-build

On success, artifacts are archived to `/payloads/archive/${LANGUAGE}/${VERSION}/` with automatic pruning to keep only the last 10 versions per loader.

### Stash Flow

```
source --> encrypted-shellcode --> artifact --> sanitised --> signed --> final
```

Each post-processing stage stashes under a new name. Downstream stages try to unstash the most-processed version first, falling back through the chain.

---

## Tooling Pipeline (Jenkinsfile.tooling)

Compiles third-party tools from any Git repository. Intended for standalone tool builds -- it does not fetch shellcode from Mythic or interact with LitterBox. Called by the Daedalus `daedalus_obfuscate_build` command via `buildWithParameters`.

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `REPO_URL` | string | (empty) | Git clone URL of the tool repo |
| `REPO_TOKEN` | password | (empty) | Access token for private repos (HTTP basic auth) |
| `REF` | string | `main` | Branch or tag to checkout |
| `SOURCE_PATH` | string | (empty) | Subdirectory or file to compile (empty = repo root) |
| `LANGUAGE` | string | `csharp` | Build language: `csharp`, `go`, `rust`, `c-mingw`, `cpp-mingw`, `nim` |
| `OUTPUT_FORMAT` | string | `exe` | Output format: `exe`, `dll`, `bin`, `shellcode`, `svc` |
| `OBFUSCATION` | string | `none` | Obfuscation level: `none`, `basic`, `full`, `garble`, `calypso` |
| `PACKER_FLAGS` | string | (empty) | Extra Calypso flags |
| `SIGNING_PROFILE` | string | `none` | Code signing profile |

### Stages

**1. Clone** -- Shallow-clones the repo at the specified ref. If `REPO_TOKEN` is provided, it is injected into the HTTPS URL as basic auth.

**2. Build** -- Dispatches to the appropriate compiler based on `LANGUAGE`:
- `csharp` -- Finds `.sln` or `.csproj` and runs `dotnet build -c Release`
- `go` -- `GOOS=windows GOARCH=amd64 go build -ldflags="-s -w"`
- `rust` -- `cargo build --release --target x86_64-pc-windows-gnu`
- `c-mingw` -- Uses Makefile if present, otherwise compiles all `.c` files with MinGW
- `cpp-mingw` -- Same pattern for C++ sources
- `nim` -- `nim c -d:mingw -d:release -d:strip --opt:size --app:gui`

**3. Obfuscate** -- Conditional on `OBFUSCATION != 'none'`:
- `basic` (C# only) -- ConfuserEx with rename + control flow
- `full` (C# only) -- ConfuserEx with control flow, ref proxy, rename, anti-debug, constants, resources
- `garble` (Go only) -- Rebuilds with `garble -literals -tiny`
- `calypso` (any) -- Packs with Calypso using `--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp` plus any extra flags

**4. Sign - Limelighter** -- Same signing logic as the main pipeline, using the hardcoded domain map.

### Output

Artifacts are archived under `build/` with Jenkins fingerprinting enabled. The workspace (`repo/`, `build-obf/`) is cleaned up in the post block.

---

## Tool Build

Mirrored tool repos and Daedalus `daedalus_obfuscate_build` both use `Jenkinsfile.tooling` (`daedalus-tooling-build` Jenkins job). See the Tooling Pipeline section above for parameters and stages.

---

## Matrix Pipeline (Jenkinsfile.matrix)

Builds the same loader source code across multiple profiles from `build-profiles.yml` in parallel, scans each variant with LitterBox, and selects the variant with the lowest detection count.

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `LOADER` | string | `loader-c-ollvm` | Loader job name to trigger as downstream build |
| `SHELLCODE_SOURCE` | string | (empty) | Mythic payload UUID (leave empty to use `SHELLCODE_FILE`) |
| `SHELLCODE_FILE` | string | `shellcode/payload.bin` | Shellcode file path |
| `PROFILES` | string | `evasive-c,garble-go,rust-loader` | Comma-separated profile names from `build-profiles.yml` |

### How It Works

1. **Parse Profiles** -- Reads `build-profiles.yml`, validates all requested profile names exist, and stores their configuration in environment variables.

2. **Matrix Build** -- Triggers the main `Jenkinsfile` as a downstream job once per profile, in parallel. Each profile's settings (language, output format, obfuscation, PE sanitisation, scan type) are mapped to the main pipeline's parameters. LitterBox scanning is disabled at this stage -- the matrix pipeline handles scanning itself.

3. **Scan All** -- Uploads each successful variant to LitterBox, triggers static and dynamic scans, polls for results, and extracts the detection count from the static scan results.

4. **Select Best** -- Compares detection counts across all variants, picks the one with the lowest score, and copies it to `/payloads/latest/${LOADER}/`. A `selected-profile.txt` file records which profile won. All variants and the scan summary are archived.

---

## Regression Pipeline (Jenkinsfile.regression)

Builds every profile defined in `build-profiles.yml`, scans each one, and compares the detection counts against a stored baseline. The pipeline fails if any profile's detection count increased by more than the threshold.

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `SHELLCODE_SOURCE` | string | (empty) | Mythic payload UUID |
| `SHELLCODE_FILE` | string | `shellcode/payload.bin` | Shellcode file path |
| `THRESHOLD` | string | `2` | Max allowed detection increase before failing |
| `UPDATE_BASELINE` | boolean | `false` | Update baseline with current results |
| `BASELINE_PATH` | string | `/payloads/baselines/regression-baseline.json` | Path to baseline JSON file |
| `SIGNING_PROFILE` | string | `none` | Code signing profile to apply |

### Stages

1. **Checkout** and **Fetch Mythic Payload** -- Same as main pipeline.
2. **Encrypt Shellcode** -- Generates all four language formats.
3. **Build All Profiles** -- Iterates every profile in `build-profiles.yml`, builds in parallel using helper functions (`buildForLanguage`, `packWithCalypso`), applies PE sanitisation and signing as configured. Each profile's artifact is stashed separately.
4. **Scan All Profiles** -- Submits each scannable profile to LitterBox (skips profiles with `litterbox_scan: false`). Collects detection counts into `regression-results.json`.
5. **Compare Baseline** -- Runs `regression-report.py` to diff current results against the baseline. If any profile's detection count increased by more than `THRESHOLD`, the build fails with `REGRESSION DETECTED`.
6. **Update Baseline** -- Conditional: copies the current results to `BASELINE_PATH` when `UPDATE_BASELINE` is true. Run this after updating loader source or obfuscation to establish a new reference point.
7. **Archive Artifacts** -- Copies all per-profile binaries and reports to `/payloads/regression/${BUILD_TAG}`.

### First Run

On the first run there is no baseline file. The comparison stage logs a warning and skips the diff. Run the pipeline once with `UPDATE_BASELINE=true` to create the initial baseline.

---

## Utility Pipelines

### Jenkinsfile.rollback

Restores a previous build version from the archive.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `LOADER` | string | `loader-c-ollvm` | Loader name |
| `VERSION` | string | (empty) | Version hash to restore (empty = latest) |
| `LIST_VERSIONS` | boolean | `false` | List available versions instead of restoring |

Archives live at `/payloads/archive/{loader}/{version}/`. Each version directory contains the loader binaries, checksums, and a `manifest.json` with timestamp, profile, and PE hash.

When restoring, the pipeline:
1. Backs up the current `/payloads/latest/{loader}/` to an archive entry prefixed `_pre-rollback-`
2. Copies the selected version into `/payloads/latest/{loader}/`

Use `LIST_VERSIONS=true` to print a table of available versions with timestamps, profiles, and PE hashes without restoring anything.

### Jenkinsfile.scale

Runner auto-scaling utility.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ACTION` | choice | `status` | Runner scale action. Choices: `status`, `up`, `down` |

Delegates to `pipeline/tools/runner-scale.sh` with the selected action. Configuration is in `pipeline/tools/runner-scale-config.yml`.

### Jenkinsfile.cleanup

Weekly artifact cleanup, triggered by cron at 3 AM every Sunday.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `MAX_AGE` | string | `30` | Max artifact age in days |
| `MAX_COUNT` | string | `50` | Max artifacts per loader |
| `DRY_RUN` | boolean | `true` | Show what would be deleted without deleting |

Runs `pipeline/tools/cleanup.sh` with the age and count limits. Defaults to dry-run mode -- set `DRY_RUN=false` to actually delete. Logs are archived from `/var/log/maas/cleanup-*.log`.

---

## Build Profiles

Profiles are defined in `pipeline/build-profiles.yml`. Each profile is a named set of build parameters that can be referenced by the matrix and regression pipelines.

### Profile Table

| Profile | Language | Output | Obfuscation | Calypso Mode | PE Sanitise | Signing | Scan Type | Arch |
|---|---|---|---|---|---|---|---|---|
| `quick-test` | c-mingw | exe | none | -- | no | none | static | amd64 |
| `evasive-c` | c-ollvm | exe | ollvm-full | -- | yes | none | all | amd64 |
| `evasive-c-heavy` | c-ollvm | exe | ollvm-heavy | -- | yes | none | all | amd64 |
| `evasive-c-signed` | c-ollvm | exe | ollvm-full | -- | yes | microsoft | all | amd64 |
| `evasive-c-dll` | c-ollvm | dll | ollvm-bcf-cff | -- | yes | none | all | amd64 |
| `garble-go` | go-garble | exe | garble-literals | -- | yes | none | all | amd64 |
| `rust-loader` | rust | exe | none | -- | yes | none | all | amd64 |
| `dotnet-loader` | csharp | exe | none | -- | yes | none | edr | amd64 |
| `packed-c` | c-mingw | exe | calypso | pack | yes | -- | all | amd64 |
| `packed-ollvm` | c-ollvm | exe | calypso | pack | yes | -- | all | amd64 |
| `packed-rust` | rust | exe | calypso | pack | yes | -- | all | amd64 |
| `packed-csharp` | csharp | exe | calypso | pack | yes | -- | edr | amd64 |
| `calypso-stealth` | -- | exe | calypso | standalone | yes | -- | all | amd64 |
| `calypso-evasive` | -- | exe | calypso | standalone | yes | -- | all | amd64 |
| `calypso-evasive-drip` | -- | exe | calypso | standalone | yes | -- | all | amd64 |
| `calypso-minimal` | -- | exe | calypso | standalone | yes | -- | all | amd64 |
| `garble-go-arm64` | go-garble | exe | garble-literals | -- | yes | none | static | arm64 |
| `rust-loader-arm64` | rust | exe | none | -- | yes | none | static | arm64 |
| `mingw-c-arm64` | c-mingw | exe | none | -- | yes | none | static | arm64 |
| `dotnet-loader-arm64` | csharp | exe | none | -- | yes | none | static | arm64 |

ARM64 profiles have `litterbox_scan: false` because there is no ARM64 sandbox available; they use static-only scanning.

The `packed-c` and `packed-ollvm` profiles use the `stealth` Calypso preset. The `packed-rust` profile uses `fast`. The `packed-csharp` profile uses `stealth` with `--type csharp`.

### Calypso Presets

| Preset | Flags | Description |
|---|---|---|
| `fast` | `--unhook ntdll.dll` | Quick pack with basic evasion |
| `stealth` | `--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp` | Full evasion suite with AMSI and ETW bypass |
| `stealth-obfuscated` | `--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp --obfuscate` | Full evasion with source-level obfuscation |
| `evasive` | `--unhook ntdll.dll --sleep 10 --amsi hwbp,context-corrupt --etw hwbp,complus --obfuscate --self-delete` | Maximum evasion with multi-method AMSI/ETW bypass, obfuscation, and self-delete |
| `minimal` | `--no-antidebug --amsi none --etw none` | Encryption only, no evasion tricks |

### Signing Profiles

Defined in `pipeline/tools/signing-profiles.yml`. Limelighter is used for all code signing.

| Profile | Domain | Mode | Description |
|---|---|---|---|
| `microsoft` | `www.microsoft.com` | real | Clone Microsoft's code signing certificate |
| `google` | `www.google.com` | real | Clone Google's code signing certificate |
| `intel` | `www.intel.com` | real | Clone Intel's code signing certificate |
| `custom` | `internal-tools.contoso.com` | self-signed | Self-signed with custom domain (password: `changeme`) |
| `none` | -- | -- | Skip signing |

In `real` mode, Limelighter fetches the TLS certificate from the target domain and clones it. In `self-signed` mode, it generates a self-signed certificate for the specified domain.

---

## Build Caching

Docker build agents mount persistent cache volumes from `/var/cache/maas/` on the host to avoid re-downloading dependencies on every build.

### Cache Volumes by Builder

| Builder | Container Mount | Host Path |
|---|---|---|
| `maas-builder-go` | `/go/pkg/mod` | `/var/cache/maas/gomod` |
| `maas-builder-go` | `/root/.cache/go-build` | `/var/cache/maas/gobuild` |
| `maas-builder-rust` | `/usr/local/cargo/registry` | `/var/cache/maas/cargo-registry` |
| `maas-builder-rust` | `/usr/local/cargo/git` | `/var/cache/maas/cargo-git` |

All builders also mount `/payloads:/payloads` for artifact storage.

### Initializing Caches on New Runners

Run `pipeline/tools/cache-init.sh` on each Jenkins agent host. The script creates all cache directories under `/var/cache/maas/` and sets ownership to UID/GID `989:989` (the Jenkins agent user inside the Docker containers).

```
sudo bash pipeline/tools/cache-init.sh
```

The cache directories created are: `gomod`, `gobuild`, `cargo-registry`, `cargo-git`, `nuget`.
