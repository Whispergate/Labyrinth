# Labyrinth

Malware-as-a-Service (MAAS) Ludus cyber range. A fully automated offensive development pipeline deployed on [Ludus](https://docs.ludus.cloud), featuring CI/CD-driven payload compilation, obfuscation, and automated EDR evasion testing.

Based on [Joff Thyer's MAAS concept](https://github.com/yoda66/MAAS) (WWHF 2023), extended with Forgejo, Jenkins, Mythic C2 eventing, and Elastic EDR detonation testing.

## Architecture

```
Source Control (Forgejo)  →  Build (Jenkins + Docker runners)  →  Obfuscate (OLLVM/Garble)
    →  Package (Erebus)  →  Test (Sphinx → LitterBox → EDR)  →  Verdict in Mythic
```

### Range Hosts

| VLAN | IP | Hostname | Role |
|------|-----|----------|------|
| 10 | .10 | elastic | Elasticsearch + Kibana + Fleet Server |
| 10 | .11 | victimEDR | EDR detonation target (Elastic Agent + Whiskers) |
| 10 | .12 | victim | Baseline target (no EDR) |
| 99 | .1 | kali | Operator workstation |
| 99 | .2 | forgejo | Forgejo Git server |
| 99 | .3 | jenkins | Jenkins CI/CD controller |
| 99 | .4 | runner-lin01 | Linux Docker build runner |
| 99 | .5 | runner-lin02 | Linux Docker build runner |
| 99 | .6 | mythic | Mythic C2 + Apollo + Erebus + Sphinx + Daedalus |
| 99 | .7 | runner-win01 | Windows build runner (MSVC + .NET) |
| 99 | .10 | commando | Operator workstation (CommandoVM) |
| 99 | .12 | litterbox | LitterBox sandbox server |
| 99 | .13 | threathunting | RITA + Zeek sensor |

## Existing Roles (Ansible Galaxy)

These roles are already published under the `whispergate` namespace:

- `whispergate.ludus_forgejo` — Forgejo server
- `whispergate.ludus_jenkins` — Jenkins CI via Docker
- `whispergate.ludus_mythic_teamserver` — Mythic C2 + agents + eventing containers
- `whispergate.ludus_litterbox` — LitterBox sandbox
- `whispergate.ludus_litterbox_whiskers_agent` — Whiskers agent on EDR target
- `whispergate.ludus_threat_hunting` — Zeek + RITA sensor/agent
- `badsectorlabs.ludus_elastic_container` — Elastic Stack
- `badsectorlabs.ludus_elastic_agent` — Elastic Agent enrollment

## New Roles (This Repo)

These roles are defined in `roles/` and need to be installed on the Ludus host:

| Role | Description |
|------|-------------|
| `ludus_jenkins_agent` | Linux Jenkins agent with Docker, connects to controller via WebSocket |
| `ludus_jenkins_agent_windows` | Windows Jenkins agent service (NSSM-managed), Java 17 |
| `ludus_maas_builders` | Builds Docker toolchain images: `maas-builder-c` (MinGW + Clang + OLLVM), `maas-builder-go` (Go + Garble), `maas-builder-nim` (Nim + winim) |
| `ludus_vs_build_tools` | Silent install of VS 2022 Build Tools + Windows SDK + .NET SDK |

## Pipeline

The `pipeline/` directory contains:

- `Jenkinsfile` — Parameterised multi-stage pipeline (compile → obfuscate → sanitise → scan → archive)
- `build-profiles.yml` — Preset build configurations (quick-test, evasive-c, garble-go, etc.)
- `tools/pe-sanitise.py` — Strips Rich headers, timestamps, debug directories from PE files
- `setup-forgejo-repos.sh` — Creates orgs, repos, and Jenkins webhooks on Forgejo

## Deployment

```bash
# 1. Install Galaxy roles
ludus ansible role add whispergate.ludus_forgejo
ludus ansible role add whispergate.ludus_jenkins
ludus ansible role add whispergate.ludus_mythic_teamserver
ludus ansible role add whispergate.ludus_litterbox
ludus ansible role add whispergate.ludus_litterbox_whiskers_agent
ludus ansible role add whispergate.ludus_threat_hunting
ludus ansible role add badsectorlabs.ludus_elastic_container
ludus ansible role add badsectorlabs.ludus_elastic_agent

# 2. Install local roles from this repo
ludus ansible role add-local roles/ludus_jenkins_agent
ludus ansible role add-local roles/ludus_jenkins_agent_windows
ludus ansible role add-local roles/ludus_maas_builders
ludus ansible role add-local roles/ludus_vs_build_tools

# 3. Deploy the range
ludus range config set -f range-config.yml
ludus range deploy

# 4. After deployment — set up Forgejo repos and webhooks
# Edit setup-forgejo-repos.sh with your range number, then:
bash pipeline/setup-forgejo-repos.sh
```

## Post-Deployment

1. **Jenkins**: Access at `http://10.RANGE.99.3:8080`, configure credentials for Mythic API token, LitterBox API token, and signing keys
2. **Forgejo**: Access at `http://10.RANGE.99.2:3000`, push loader source code to the repos
3. **Mythic**: Access at `https://10.RANGE.99.6:7443`, Daedalus commands are available to trigger builds from the C2 UI
4. **LitterBox**: Access at `http://10.RANGE.99.12:1337`
5. **Kibana**: Access at `https://10.RANGE.10.10:5601` for EDR alert review

## References

- [MAAS (original)](https://github.com/yoda66/MAAS) — Joff Thyer, WWHF 2023
- [Erebus](https://github.com/Whispergate/Erebus) — Initial access packaging
- [Sphinx](https://github.com/Whispergate/Sphinx) — LitterBox ↔ Mythic eventing bridge
- [Daedalus](https://github.com/Whispergate/Daedalus) — CI/CD ↔ Mythic eventing bridge
- [Mythic C2](https://github.com/its-a-feature/Mythic)
- [Ludus](https://docs.ludus.cloud)
