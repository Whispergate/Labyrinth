# Labyrinth

![Labyrinth Banner](https://github.com/Whispergate/Labyrinth/blob/main/assets/Labyrinth.png?raw=true)

Malware-as-a-Service (MAAS) cyber range for [Ludus](https://docs.ludus.cloud). Automated offensive development pipeline with CI/CD-driven payload compilation, obfuscation, and EDR evasion testing.

Based on [Joff Thyer's MAAS concept](https://github.com/yoda66/MAAS) (WWHF 2023), extended with Forgejo, Jenkins, Mythic C2 eventing via [Daedalus](https://github.com/Whispergate/Daedalus), and Elastic EDR detonation testing.

## Architecture

```
Source Control (Forgejo)  →  Build (Jenkins + Docker runners)  →  Obfuscate (OLLVM/Garble)
    →  Package (Erebus)  →  Test (Sphinx → LitterBox → EDR)  →  Verdict in Mythic
```

![Labyrinth Architecture](https://github.com/Whispergate/Labyrinth/blob/main/assets/LabyrinthArchitecture.png?raw=true)

### Range Hosts

| VLAN | IP | Hostname | Role |
|------|-----|----------|------|
| 10 | .10 | elastic | Elasticsearch + Kibana + Fleet Server |
| 10 | .11 | victimEDR | EDR detonation target (Elastic Agent + Whiskers) |
| 10 | .12 | victim | Baseline target (no EDR) |
| 99 | .2 | forgejo | Forgejo Git server (HTTPS via Nginx) |
| 99 | .3 | jenkins | Jenkins CI/CD controller (port 8080) |
| 99 | .4 | runner-lin01 | Linux Docker build runner |
| 99 | .5 | runner-lin02 | Linux Docker build runner |
| 99 | .6 | mythic | Mythic C2 + Starburst + Erebus + Sphinx + Daedalus |
| 99 | .7 | runner-win01 | Windows build runner (MSVC + .NET) |
| 99 | .10 | commando | Operator workstation (CommandoVM) |
| 99 | .12 | litterbox | LitterBox sandbox server (port 1337) |
| 99 | .13 | threathunting | RITA + Zeek sensor |

IPs follow the pattern `10.<range_second_octet>.<vlan>.<last_octet>`. For example, with a range second octet of `5`, the Forgejo server is at `10.5.99.2`.

### Build Targets

Five loader toolchains are preconfigured, each in its own Forgejo repo under the `offensive-tooling` organisation:

| Repo | Toolchain | Docker Image | Runner Label |
|------|-----------|-------------|--------------|
| loader-c-mingw | MinGW GCC cross-compiler | maas-builder-c | linux-c |
| loader-c-ollvm | Clang + OLLVM passes | maas-builder-c | linux-c |
| loader-go-garble | Go + Garble obfuscator | maas-builder-go | linux-go |
| loader-nim | Nim cross-compiler | maas-builder-nim | linux-nim |
| loader-csharp | .NET SDK (win-x64) | native | windows-dotnet |

### Example Loaders

The `loaders/` directory contains ready-to-use shellcode loaders for the C-based toolchains. Each loader embeds shellcode as a PE resource (`.rsrc` section) at compile time rather than reading from disk at runtime.

```
loaders/
├── loader-c-mingw/src/
│   ├── loader.c        # Win32 API injection techniques
│   ├── resource.h      # Resource ID definitions
│   └── resource.rc     # Binds shellcode/payload.bin as RCDATA
└── loader-c-ollvm/src/
    ├── loader.c        # NT API injection techniques (runtime-resolved)
    ├── resource.h
    └── resource.rc
```

Both loaders use a dispatch table of injection techniques selectable at runtime via `-t <N>` or at compile time by changing `DEFAULT_TECHNIQUE`:

| # | loader-c-mingw | loader-c-ollvm |
|---|----------------|----------------|
| 0 | VirtualAlloc + CreateThread | NtAllocateVirtualMemory + NtCreateThreadEx |
| 1 | VirtualAlloc + EnumWindows callback | NtQueueApcThread + NtTestAlert |
| 2 | VirtualAlloc + CreateTimerQueueTimer | NtCreateSection + dual NtMapViewOfSection |
| 3 | QueueUserAPC + NtTestAlert | NtAllocateVirtualMemory + EnumWindows callback |
| 4 | ConvertThreadToFiber + CreateFiber | NtCreateThreadEx suspended + ResumeThread |

The OLLVM loader resolves all ntdll functions at runtime via `GetProcAddress` to avoid static imports that EDR hooks at the Win32 layer. OLLVM obfuscation passes make the resolver and dispatch logic harder to reverse.

To add a new technique, write a function matching the `inject_fn` signature and append one entry to the `techniques[]` array.

**Build commands** (resource compilation + linking):

```bash
# MinGW
x86_64-w64-mingw32-windres src/resource.rc -o resource.o
x86_64-w64-mingw32-gcc -o loader.exe src/loader.c resource.o \
    -lntdll -lkernel32 -mwindows -s -O2

# OLLVM (with obfuscation flags)
x86_64-w64-mingw32-windres src/resource.rc -o resource.o
clang --target=x86_64-w64-mingw32 <ollvm-flags> \
    -o loader.exe src/loader.c resource.o -lntdll -lkernel32 -s -O1
```

Place your shellcode at `shellcode/payload.bin` before building. The resource compiler embeds it into the PE; at runtime the loader extracts it via `FindResource` / `LoadResource`.

### Two Build Paths

Builds can be triggered two ways, both fully automated by the setup script:

1. **Jenkins pipeline** (push-to-build) - a `git push` to any loader repo fires a Forgejo webhook that triggers the Jenkins `Jenkinsfile`. Jenkins uses Docker-based agents for Linux builds and a native Windows agent for C#. The pipeline includes PE sanitisation, checksumming, and LitterBox scanning.

2. **Daedalus workflow_dispatch** (Mythic-triggered) - Daedalus dispatches a Forgejo Actions workflow (`.forgejo/workflows/build.yml`) with build parameters. The workflow runs on self-hosted runners labeled `maas` and contains the same build commands, PE sanitisation, and LitterBox scanning steps.

Both paths produce the same output: a compiled, optionally obfuscated and sanitised payload with checksums and scan results.

### OLLVM Obfuscation Profiles

The C/OLLVM toolchain supports four obfuscation levels:

| Profile | Passes | Description |
|---------|--------|-------------|
| `ollvm-cff` | `-fla` | Control flow flattening only |
| `ollvm-bcf-cff` | `-fla -bcf` | Flattening + bogus control flow |
| `ollvm-full` | `-fla -bcf -sub` | Flattening + bogus CF + instruction substitution |
| `ollvm-heavy` | `-fla -split -bcf -bcf_prob=100 -bcf_loop=3 -sub -sub_loop=5` | All passes at maximum iterations |

`ollvm-heavy` applies every available pass with high iteration counts: 100% bogus block probability across 3 loops and 5 substitution loops. This produces significantly larger and slower binaries but makes static analysis and pattern matching substantially harder. Use it when evasion matters more than payload size.

## Installation

### Prerequisites

- A running [Ludus](https://docs.ludus.cloud) server (Proxmox-based)
- SSH access to the Ludus server
- `ludus` CLI configured and authenticated
- On the machine running the setup script: `curl`, `jq`, `git`, and network access to the range's VLAN 99

### Step 1: Install Ansible Galaxy Roles

These roles provision each VM in the range. Run all of them before deploying.

```bash
ludus ansible role add whispergate.ludus_forgejo
ludus ansible role add whispergate.ludus_jenkins
ludus ansible role add whispergate.ludus_jenkins_agent
ludus ansible role add whispergate.ludus_jenkins_agent_windows
ludus ansible role add whispergate.ludus_maas_builders
ludus ansible role add whispergate.ludus_vs_build_tools
ludus ansible role add whispergate.ludus_mythic_teamserver
ludus ansible role add whispergate.ludus_litterbox
ludus ansible role add whispergate.ludus_litterbox_whiskers_agent
ludus ansible role add whispergate.ludus_threat_hunting
ludus ansible role add badsectorlabs.ludus_elastic_container
ludus ansible role add badsectorlabs.ludus_elastic_agent
```

### Step 2: Set the Range Configuration

```bash
ludus range config set -f range-config.yml
```

Review `range-config.yml` before deploying. The default credentials are:

| Service | User | Password |
|---------|------|----------|
| Forgejo | forgejo-admin | ForgejoPW1! |
| Jenkins | admin | JenkinsPW1! |

Change the `role_vars` passwords in `range-config.yml` if you want different credentials. The setup script reads these from environment variables, so you can override them at runtime without editing the file.

### Step 3: Deploy

```bash
ludus range deploy
```

This takes 30-60 minutes depending on your server. It provisions all 13 VMs, installs services, builds Docker toolchain images on the Linux runners, installs VS Build Tools and .NET SDK on the Windows runner, and deploys Mythic with all agents and eventing containers (including Daedalus).

Monitor progress:

```bash
ludus range status
ludus range logs -f
```

Wait for the deploy to complete before continuing. All VMs should show `SUCCESS` in `ludus range status`.

### Step 4: Get the Mythic API Token

After deployment, SSH into the Mythic VM and retrieve the admin API token. You will need this for Daedalus and for the setup script.

```bash
ssh root@<ludus-server>
# Then from the server, or directly if you have range access:
ssh user@10.<RANGE>.99.6
cd /opt/Mythic
sudo ./mythic-cli config get MYTHIC_ADMIN_PASSWORD
```

Log into Mythic at `https://10.<RANGE>.99.6:7443` with `mythic_admin` and the password above. Go to the settings page and copy your API token (or generate one).

### Step 5: Run the Setup Script

The setup script creates Forgejo organisations and repos, pushes the Jenkinsfile and Daedalus workflow into each repo, configures webhooks, sets Forgejo Actions secrets, creates Jenkins pipeline jobs, and provisions Jenkins credentials.

Run it and follow the interactive prompts:

```bash
bash pipeline/setup.sh
```

The script walks through five sections:

1. **Range second octet** - the number from your Ludus range (e.g. `5` for `10.5.x.x`)
2. **Service URLs** - auto-generated from the octet, edit if your layout differs
3. **Credentials** - Forgejo and Jenkins admin users/passwords
4. **API token** - Mythic token from step 4 (can be skipped and added later)
5. **Webhook token** - the shared secret for Jenkins generic-webhook-trigger

It shows a summary and asks for confirmation before making any changes.

For scripted or CI use, pre-set environment variables and skip the prompts:

```bash
export RANGE_OCTET=5
export MYTHIC_API_TOKEN="<your-mythic-api-token>"
bash pipeline/setup.sh --non-interactive
```

All variables (`FORGEJO_URL`, `FORGEJO_USER`, `FORGEJO_PASS`, `JENKINS_URL`, `JENKINS_USER`, `JENKINS_PASS`, `MYTHIC_URL`, `LITTERBOX_URL`, `JENKINS_WEBHOOK_TOKEN`) can be overridden via environment. The script prints a summary at the end with the Daedalus provider config values you need for the next step.

### Step 6: Upload Eventing Workflows

Daedalus and Sphinx ship their event workflows as JSON files, but they are not registered automatically. You need to upload them manually.

1. Open Mythic at `https://10.<RANGE>.99.6:7443` and go to the **Eventing** page.
2. Click **Import** and upload the Daedalus workflow files from the Mythic VM:
   ```
   /opt/Mythic/InstalledServices/daedalus/eventing/*.json
   ```
3. Do the same for Sphinx:
   ```
   /opt/Mythic/InstalledServices/sphinx/eventing/*.json
   ```

After importing, you should see the Daedalus workflows (manual_build, auto_build, check_status, download_artifact, build_and_scan, scan_payload, get_verdict) and the Sphinx workflows on the Eventing page.

### Step 7: Configure Daedalus Providers

Configure the provider credentials for whichever build path you want to use:

**Forgejo provider** (for Daedalus-triggered builds via workflow_dispatch):

| Field | Value |
|-------|-------|
| url | `https://10.<RANGE>.99.2` |
| token | The Forgejo API token printed by the setup script (or set via `DAEDALUS_FORGEJO_TOKEN`) |
| owner | `offensive-tooling` |
| repo | The specific loader repo (e.g. `loader-c-mingw`) |

**Jenkins provider** (for Daedalus-triggered builds via buildWithParameters):

| Field | Value |
|-------|-------|
| url | `http://10.<RANGE>.99.3:8080` |
| user | `admin` (or your Jenkins admin user) |
| token | A Jenkins API token (generate one from Jenkins > user > Configure > API Token) |

You can configure both providers. Daedalus lets you select which one to use per workflow execution.

### Step 8: Verify

1. **Forgejo** - browse to `https://10.<RANGE>.99.2/offensive-tooling`. You should see five loader repos, each containing a `Jenkinsfile`, `.forgejo/workflows/build.yml`, `tools/pe-sanitise.py`, and `build-profiles.yml`.

2. **Jenkins** - browse to `http://10.<RANGE>.99.3:8080`. You should see five pipeline jobs (one per loader). Check that all three build agents (runner-lin01, runner-lin02, runner-win01) are connected under Manage Jenkins > Nodes.

3. **Daedalus** - in Mythic's Eventing page, run the `manual_build` workflow with the Forgejo or Jenkins provider and a test repo to confirm end-to-end connectivity.

## Pipeline

The `pipeline/` directory contains:

| File | Purpose |
|------|---------|
| `Jenkinsfile` | Parameterised multi-stage pipeline: checkout, fetch Mythic payload, resource compilation, build (5 language targets with Docker agents), PE sanitisation, checksumming, LitterBox scan, archive |
| `build-profiles.yml` | Preset build configurations (quick-test, evasive-c, evasive-c-heavy, evasive-c-dll, garble-go, nim-loader, dotnet-loader) |
| `tools/pe-sanitise.py` | Strips Rich headers, randomises timestamps, nulls debug directories, strips version info from PE files |
| `setup.sh` | Interactive bootstrap: orgs, repos, webhooks, Forgejo Actions workflows, Jenkins jobs, secrets, and credentials |

The `loaders/` directory contains example source for the C-based toolchains:

| Directory | Description |
|-----------|-------------|
| `loaders/loader-c-mingw/src/` | MinGW loader with 5 Win32 API injection techniques, shellcode embedded via PE resource |
| `loaders/loader-c-ollvm/src/` | OLLVM loader with 5 NT API injection techniques (runtime-resolved), shellcode embedded via PE resource |

Each loader includes `resource.rc` and `resource.h` which bind `shellcode/payload.bin` into the PE's `.rsrc` section at compile time. The setup script copies these into the Forgejo repos during bootstrap.

### Build Profiles

Profiles in `build-profiles.yml` are preconfigured parameter sets:

| Profile | Language | Obfuscation | PE Sanitise | LitterBox |
|---------|----------|-------------|-------------|-----------|
| quick-test | c-mingw | none | no | static only |
| evasive-c | c-ollvm | ollvm-full | yes | all |
| evasive-c-heavy | c-ollvm | ollvm-heavy | yes | all |
| evasive-c-dll | c-ollvm | ollvm-bcf-cff | yes | all |
| garble-go | go-garble | garble-literals | yes | all |
| nim-loader | nim | string-encrypt | yes | all |
| dotnet-loader | csharp | none | yes | edr |

## Usage

### Push-to-Build (Jenkins)

Clone a loader repo, add your source code, and push:

```bash
GIT_SSL_NO_VERIFY=true git clone https://forgejo-admin:<password>@10.<RANGE>.99.2/offensive-tooling/loader-c-mingw.git
cd loader-c-mingw
# Add your loader source to src/
# Add shellcode to shellcode/payload.bin
git add -A && git commit -m "Initial loader"
GIT_SSL_NO_VERIFY=true git push origin main
```

The Forgejo webhook fires, Jenkins picks up the job, builds with the Docker toolchain, runs PE sanitisation and LitterBox scanning, and archives the artifact.

### Daedalus-Triggered Build (Mythic)

From the Mythic Eventing page or via a Mythic callback, run the `manual_build` workflow:

- **provider**: `forgejo` or `jenkins`
- **job**: `offensive-tooling/loader-c-mingw` (Forgejo) or `loader-c-mingw` (Jenkins)
- **LANGUAGE**: `c-mingw`, `c-ollvm`, `go-garble`, `nim`, or `csharp`
- **OUTPUT_FORMAT**: `exe`, `dll`, or `shellcode`
- **OBFUSCATION**: `none`, `ollvm-cff`, `ollvm-bcf-cff`, `ollvm-full`, `ollvm-heavy`, `garble-literals`, or `string-encrypt`
- **SHELLCODE_SOURCE**: `mythic:<payload-uuid>` to fetch shellcode from Mythic automatically

Daedalus triggers the build, polls for completion, and can download the artifact back into Mythic.

### Automated Build on Payload Creation

The `auto_build` Daedalus workflow triggers a build automatically when a new Mythic payload is generated. Configure it in the Eventing page with your preferred provider, job, and build parameters. When a payload completes, Daedalus dispatches a build with `SHELLCODE_SOURCE=mythic:<uuid>`, compiles the loader, and optionally scans and tags the result.

## References

- [MAAS (original)](https://github.com/yoda66/MAAS) - Joff Thyer, WWHF 2023
- [Daedalus](https://github.com/Whispergate/Daedalus) - CI/CD eventing bridge for Mythic
- [Erebus](https://github.com/Whispergate/Erebus) - Initial access packaging
- [Sphinx](https://github.com/Whispergate/Sphinx) - LitterBox scanning bridge for Mythic
- [Mythic C2](https://github.com/its-a-feature/Mythic)
- [Ludus](https://docs.ludus.cloud)
