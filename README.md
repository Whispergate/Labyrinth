# Labyrinth

![Labyrinth Banner](https://github.com/Whispergate/Labyrinth/blob/main/assets/Labyrinth.png?raw=true)

Malware-as-a-Service (MAAS) cyber range for [Ludus](https://docs.ludus.cloud). Automated offensive development pipeline with CI/CD-driven payload compilation, obfuscation, and EDR evasion testing.

## Architecture

```
Source Control (Forgejo)  ->  Build (Jenkins + Docker runners)  ->  Obfuscate (OLLVM/Garble)
    ->  Package (Erebus)  ->  Test (Sphinx -> LitterBox -> EDR)  ->  Verdict in Mythic
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

## Quick Start

**Prerequisites:** A running [Ludus](https://docs.ludus.cloud) server with SSH access and `ludus` CLI configured. On the setup machine: `curl`, `jq`, `git`, and network access to VLAN 99.

**1. Install Ansible roles**

```bash
ludus ansible role add whispergate.ludus_forgejo whispergate.ludus_jenkins whispergate.ludus_jenkins_agent whispergate.ludus_jenkins_agent_windows whispergate.ludus_maas_builders whispergate.ludus_vs_build_tools whispergate.ludus_mythic_teamserver whispergate.ludus_litterbox whispergate.ludus_litterbox_whiskers_agent whispergate.ludus_threat_hunting badsectorlabs.ludus_elastic_container badsectorlabs.ludus_elastic_agent
```

**2. Set the range configuration**

```bash
ludus range config set -f range-config.yml
```

**3. Deploy the range**

```bash
ludus range deploy
```

Takes 30-60 minutes. Monitor with `ludus range status` and `ludus range logs -f`.

**4. Get the Mythic API token**

SSH into the Mythic VM, run `sudo ./mythic-cli config get MYTHIC_ADMIN_PASSWORD` from `/opt/Mythic`, then log into `https://10.<RANGE>.99.6:7443` and copy your API token from settings.

**5. Run the setup script**

```bash
bash pipeline/setup.sh
```

Creates Forgejo orgs/repos, pushes pipeline files, configures webhooks, sets secrets, and creates Jenkins jobs. For non-interactive use: `export RANGE_OCTET=5 MYTHIC_API_TOKEN="<token>" && bash pipeline/setup.sh --non-interactive`.

**6. Upload eventing workflows**

Import the JSON files from `/opt/Mythic/InstalledServices/daedalus/eventing/*.json` and `/opt/Mythic/InstalledServices/sphinx/eventing/*.json` via the Mythic Eventing page.

**7. Configure Daedalus providers**

Set Forgejo and/or Jenkins provider credentials in Daedalus. The setup script prints the values you need.

**8. Verify**

Check Forgejo at `https://10.<RANGE>.99.2/offensive-tooling` for five loader repos. Check Jenkins at `http://10.<RANGE>.99.3:8080` for five pipeline jobs and three connected agents. Run the `manual_build` workflow in Mythic to confirm end-to-end connectivity.

## Usage

### Push-to-Build

Push to any loader repo in Forgejo. The webhook triggers Jenkins, which builds with the Docker toolchain, sanitises the PE, runs LitterBox scanning, and archives the artifact.

```bash
GIT_SSL_NO_VERIFY=true git clone https://forgejo-admin:<password>@10.<RANGE>.99.2/offensive-tooling/loader-c-mingw.git
# Add source to src/, shellcode to shellcode/payload.bin, then push
```

### Daedalus Build

Run the `manual_build` workflow from Mythic's Eventing page. Select provider (Forgejo or Jenkins), target repo, language, output format, and obfuscation level. Daedalus triggers the build, polls for completion, and downloads the artifact into Mythic. The `auto_build` workflow fires automatically on new Mythic payload creation.

### Daedalus CA Commands

From any supported agent callback (Apollo, Athena, Merlin, Starburst), Daedalus adds eight commands:

| Command | Description |
|---------|-------------|
| `daedalus_fetch_execute` | Fetch artifact and execute in-memory (BOF/assembly) |
| `daedalus_register_tool` | Fetch artifact and register in Mythic |
| `daedalus_obfuscate_build` | Clone repo, obfuscate, build, and fetch |
| `daedalus_quick_build` | Trigger any CI job with arbitrary params, poll, download |
| `daedalus_list_builds` | List CI jobs, builds, or artifacts |
| `daedalus_check_build` | Check build status with optional log tail |
| `daedalus_get_log` | Retrieve build console output |
| `daedalus_scan_artifact` | Fetch artifact and scan via LitterBox |

### Tooling Build

The `daedalus_obfuscate_build` command compiles third-party offensive tools from mirrored repos. Point it at a `REPO_URL`, pick a language and obfuscation level, and the pipeline clones, compiles, optionally obfuscates (ConfuserEx, Garble, Calypso), and archives the artifact.

## Documentation

Detailed documentation lives in the `documentation/` folder:

- [`documentation/loaders.md`](documentation/loaders.md) - Loader architecture, injection techniques, adding new loaders
- [`documentation/pipeline.md`](documentation/pipeline.md) - Pipeline stages, parameters, build profiles, Calypso presets
- [`documentation/tools.md`](documentation/tools.md) - All pipeline tools reference (PE sanitisation, YARA, EDR diffing, etc.)
- [`documentation/evasion.md`](documentation/evasion.md) - Obfuscation, indirect syscalls, code signing, DLL sideloading
- [`documentation/infrastructure.md`](documentation/infrastructure.md) - Range layout, Docker images, caching, backup, Grafana
- [`documentation/daedalus.md`](documentation/daedalus.md) - Daedalus CA commands, eventing workflows, credential resolution, agent support

## References

- [MAAS (original)](https://github.com/yoda66/MAAS) - Joff Thyer, WWHF 2023
- [Daedalus](https://github.com/Whispergate/Daedalus) - CI/CD eventing bridge for Mythic
- [Erebus](https://github.com/Whispergate/Erebus) - Initial access packaging
- [Sphinx](https://github.com/Whispergate/Sphinx) - LitterBox scanning bridge for Mythic
- [Mythic C2](https://github.com/its-a-feature/Mythic)
- [Ludus](https://docs.ludus.cloud)
