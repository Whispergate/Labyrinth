# Daedalus

Daedalus is a Mythic Command Augmentation (CA) container that adds CI/CD build management, artifact fetching, scanning, and obfuscation pipeline commands to any supported Mythic agent callback. It bridges Mythic C2 and the Labyrinth build infrastructure so operators can trigger builds, fetch artifacts, and scan payloads without leaving the Mythic UI.

## Supported Agents

Daedalus injects its commands into callbacks from these Mythic agents:

- Apollo
- Athena
- Merlin
- Starburst

## Supported CI/CD Providers

- Jenkins
- GitHub Actions
- GitLab CI
- Forgejo Actions
- Gitea Actions (shares the Forgejo API)

---

## Commands

Daedalus adds eight commands to supported agent callbacks, grouped by function.

### Build and Fetch

#### daedalus_fetch_execute

Download an artifact from a CI/CD build and execute it in-memory on the target callback. Supports BOFs and .NET assemblies. The command auto-selects the binary artifact, uploads it to Mythic, then delegates to the agent's native execution command (`execute_coff`, `execute_assembly`, etc.).

```
daedalus_fetch_execute -job loader-c-mingw -tool_type bof
daedalus_fetch_execute -provider github -job build.yml -build_id latest -tool_type assembly
```

#### daedalus_register_tool

Download an artifact and register it as a persistent file in Mythic for later use. Unlike `fetch_execute`, it does not delegate to the agent -- it stores the file and completes.

```
daedalus_register_tool -job loader-c-mingw -tool_name whoami.o
```

#### daedalus_obfuscate_build

Clone a Git repository, trigger a CI/CD obfuscation pipeline (ConfuserEx, Garble, Calypso, Limelighter signing), poll for completion, and download the result. Designed for compiling third-party tools from source.

```
daedalus_obfuscate_build -repo_url https://github.com/nicocha30/ligolo-ng -language go -obfuscation garble
```

#### daedalus_quick_build

Trigger any CI/CD job with arbitrary JSON parameters, poll for completion, download the artifact, and register or execute it. A generic build command that works with any job without repo-cloning logic.

```
daedalus_quick_build -job loader-c-mingw
daedalus_quick_build -job loader-c-mingw -build_params '{"OBFUSCATION":"ollvm-full"}' -tool_type bof
```

### Monitoring and Discovery

#### daedalus_list_builds

List CI/CD jobs, builds for a job, or artifacts for a specific build. Three modes: no args lists all jobs, `-job` shows recent build info, `-job -build_id` lists artifacts.

```
daedalus_list_builds
daedalus_list_builds -job loader-c-mingw
daedalus_list_builds -job loader-c-mingw -build_id 42
```

#### daedalus_check_build

Check build status with optional log tail. Shows status, duration, URL, artifacts, and errors.

```
daedalus_check_build -job loader-c-mingw -build_id 42
daedalus_check_build -job loader-c-mingw -include_log true -log_lines 100
```

#### daedalus_get_log

Retrieve build console output. Configurable line count from the end of the log.

```
daedalus_get_log -job loader-c-mingw -build_id 42 -lines 200
```

### Scanning

#### daedalus_scan_artifact

Fetch a CI/CD artifact and submit it to LitterBox for static, dynamic, or EDR scanning. Returns the risk level, per-engine detection results, and scan verdicts.

```
daedalus_scan_artifact -job loader-c-mingw -scan_type both
daedalus_scan_artifact -job loader-c-ollvm -scan_type all -edr_profile defender
```

---

## Credential Resolution

All commands resolve provider credentials through a three-tier fallback:

1. **Task arguments** -- Per-invocation overrides (e.g. `-jenkins_url`, `-jenkins_token`)
2. **Mythic Secrets** -- Stored in Mythic user settings under Settings > Secrets
3. **Environment variables** -- Container-level defaults

### Required Secrets

| Secret Key | Provider | Description |
|------------|----------|-------------|
| `JENKINS_API_KEY` | Jenkins | Jenkins API token |
| `GITHUB_API_KEY` | GitHub | GitHub personal access token |
| `GITLAB_API_KEY` | GitLab | GitLab personal access token |
| `FORGEJO_API_KEY` | Forgejo | Forgejo API token |
| `GITEA_API_KEY` | Gitea | Gitea API token |
| `REPO_TOKEN` | Any | Access token for private source repos |

---

## Agent Support

Daedalus maps each supported agent to its native execution commands via `agent_support.json`. When a command delegates execution (e.g. `fetch_execute` with `tool_type=bof`), it looks up the agent's BOF or assembly command name and parameter names from this mapping.

| Agent | BOF Command | Assembly Command |
|-------|-------------|-----------------|
| Apollo | `execute_coff` | `execute_assembly` (also `inline_assembly`) |
| Athena | `coff` | `execute-assembly` |
| Merlin | `coff` | `execute-assembly` |
| Starburst | `execute_coff` | `execute_assembly` |

---

## Loader Resolution

When a workflow or command specifies a `language` parameter instead of a `job` name, Daedalus resolves the Jenkins job name automatically. The `language` value can be either the full loader directory name (`loader-c-mingw`) or the short form (`c-mingw`). If the value does not start with `loader-`, the prefix is added. The resolved name is also passed as the `LANGUAGE` build parameter to Jenkins.

Examples:
- `language: loader-c-mingw` -- job resolves to `loader-c-mingw`, LANGUAGE=`loader-c-mingw`
- `language: c-mingw` -- job resolves to `loader-c-mingw`, LANGUAGE=`loader-c-mingw`
- `language: rust` -- job resolves to `loader-rust`, LANGUAGE=`loader-rust`

---

## Eventing Workflows

Daedalus registers seven eventing workflows with Mythic. These are triggered from the Mythic Eventing page or automatically on payload creation.

| Workflow | Trigger | Description |
|----------|---------|-------------|
| Auto Build | `payload_build_finish` | Fires on new payload creation. Triggers a CI build, polls for completion, downloads the artifact, scans it via LitterBox, and tags the payload in Mythic. |
| Build and Scan | Manual | Full pipeline: trigger build, poll, download, upload to Mythic, scan via LitterBox, tag results. |
| Manual Build | Manual | Trigger a CI build and poll for completion. No scanning. |

All three build workflows (Auto Build, Build and Scan, Manual Build) expose `CALYPSO_MODE` and `PACKER_PRESET` in their environment blocks alongside the existing `PACKER_FLAGS`. Set `CALYPSO_MODE` to `pack` or `standalone`, and `PACKER_PRESET` to a named preset (`none`, `fast`, `stealth`, `stealth-obfuscated`, `evasive`, `evasive-drip`, `minimal`). The preset is resolved to flags by the Jenkinsfile. If `PACKER_FLAGS` is set, it overrides the preset.

Example environment block for a standalone Calypso build with the evasive-drip preset:

```yaml
environment:
    OBFUSCATION: calypso
    CALYPSO_MODE: standalone
    PACKER_PRESET: evasive-drip
```
| Scan Payload | Manual | Submit an existing Mythic payload to LitterBox for scanning. |
| Check Build Status | Manual | Check the current status of a CI/CD build. |
| Download Artifact | Manual | Download a build artifact and upload it to Mythic. |
| Get Verdict | Manual | Retrieve LitterBox scan results and Daedalus build tags for a payload. |

---

## Environment Variables

Daedalus reads several environment variables from the container or the workflow YAML environment blocks. All are optional when Mythic Secrets or task arguments provide the values.

| Variable | Default | Description |
|----------|---------|-------------|
| `DAEDALUS_PROVIDER` | `jenkins` | Default CI/CD provider |
| `DAEDALUS_VERIFY_SSL` | `false` | Set to `1`, `true`, or `yes` to enable SSL certificate verification on outbound HTTP requests |
| `JENKINS_URL` | (empty) | Jenkins server URL |
| `JENKINS_USER` | (empty) | Jenkins username |
| `LITTERBOX_URL` | (empty) | LitterBox API URL |
| `EDR_PROFILE` | (empty) | Default EDR profile for scanning |

Provider-specific connection variables (`FORGEJO_URL`, `FORGEJO_TOKEN`, `GITHUB_TOKEN`, etc.) follow the same pattern and are documented in the provider source files.

### Build Parameters

The workflow environment block can also set build parameters that get forwarded to the Jenkinsfile. These map 1:1 to Jenkins pipeline parameters. If a value is empty or missing, the Jenkinsfile default applies.

| Variable | Default | Description |
|----------|---------|-------------|
| `JOB` | (empty) | Jenkins job name. Auto-resolved from `LANGUAGE` if empty. |
| `LANGUAGE` | (empty) | Loader directory name (e.g. `loader-c-mingw` or `c-mingw`). Auto-prefixed with `loader-` if needed. |
| `OUTPUT_FORMAT` | `exe` | Output format: `exe`, `dll`, `shellcode` |
| `OBFUSCATION` | `none` | Obfuscation profile: `none`, `ollvm-cff`, `ollvm-bcf-cff`, `ollvm-full`, `ollvm-heavy`, `garble-literals`, `string-encrypt`, `calypso` |
| `CALYPSO_MODE` | `pack` | Calypso mode: `pack` (loader-in-loader) or `standalone` (single loader from raw shellcode). Only applies when `OBFUSCATION` is `calypso`. |
| `PACKER_PRESET` | (empty) | Named packer preset from `build-profiles.yml`: `none`, `fast`, `stealth`, `stealth-obfuscated`, `evasive`, `evasive-drip`, `minimal`. Resolved to flags by the Jenkinsfile. Ignored if `PACKER_FLAGS` is set. |
| `PACKER_FLAGS` | (empty) | Raw Calypso flags. Overrides `PACKER_PRESET` if both are set. |
| `PE_SANITISE` | `true` | Strip PE metadata post-build |
| `SIGNING_PROFILE` | `none` | Code signing profile: `microsoft`, `google`, `intel`, `custom`, `none` |
| `TARGET_ARCH` | `amd64` | Target architecture: `amd64`, `arm64` |
| `LITTERBOX_SCAN` | `true` | Submit to LitterBox after build |
| `SCAN_TYPE` | `all` | LitterBox scan profile: `all`, `static`, `dynamic`, `edr` |
| `OPERATOR_ID` | (empty) | Operator callsign for deconfliction tagging |
| `CAMPAIGN_TAG` | (empty) | Campaign identifier for deconfliction tagging |
