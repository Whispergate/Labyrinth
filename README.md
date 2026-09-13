# Labyrinth

Malware-as-a-Service (MAAS) Ludus cyber range. Automated offensive development pipeline on [Ludus](https://docs.ludus.cloud) with CI/CD-driven payload compilation, obfuscation, and EDR evasion testing.

Based on [Joff Thyer's MAAS concept](https://github.com/yoda66/MAAS) (WWHF 2023), extended with Forgejo, Jenkins, Mythic C2 eventing, and Elastic EDR detonation testing.

## Architecture

```
Source Control (Forgejo)  →  Build (Jenkins + Docker runners)  →  Obfuscate (OLLVM/Garble)
    →  Package (Erebus)  →  Test (Sphinx → LitterBox → EDR)  →  Verdict in Mythic
```

![Labyrinth Architecture](https://github.com/Whispergate/Labyrinth/assets/LabyrinthArchitecture.png)

### Range Hosts

| VLAN | IP | Hostname | Role |
|------|-----|----------|------|
| 10 | .10 | elastic | Elasticsearch + Kibana + Fleet Server |
| 10 | .11 | victimEDR | EDR detonation target (Elastic Agent + Whiskers) |
| 10 | .12 | victim | Baseline target (no EDR) |
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

Published under the `whispergate` and `badsectorlabs` namespaces:

- `whispergate.ludus_forgejo` - Forgejo server
- `whispergate.ludus_jenkins` - Jenkins CI via Docker
- `whispergate.ludus_mythic_teamserver` - Mythic C2 + agents + eventing containers
- `whispergate.ludus_litterbox` - LitterBox sandbox
- `whispergate.ludus_litterbox_whiskers_agent` - Whiskers agent on EDR target
- `whispergate.ludus_threat_hunting` - Zeek + RITA sensor/agent
- `badsectorlabs.ludus_elastic_container` - Elastic Stack
- `badsectorlabs.ludus_elastic_agent` - Elastic Agent enrollment

## Pipeline

The `pipeline/` directory contains:

- `Jenkinsfile` - Parameterised multi-stage pipeline (compile → obfuscate → sanitise → scan → archive)
- `build-profiles.yml` - Preset build configurations (quick-test, evasive-c, garble-go, etc.)
- `tools/pe-sanitise.py` - Strips Rich headers, timestamps, debug directories from PE files
- `setup-forgejo-repos.sh` - Creates orgs, repos, and Jenkins webhooks on Forgejo

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
ludus ansible role add whispergate.ludus_vs_build_tools
ludus ansible role add whispergate.ludus_maas_builders
ludus ansible role add whispergate.ludus_jenkins_agent_windows
ludus ansible role add whispergate.ludus_jenkins_agent

# 2. Deploy the range
ludus range config set -f range-config.yml
ludus range deploy

# 3. After deployment - set up Forgejo repos and webhooks
# Edit setup-forgejo-repos.sh with your range second octet, then:
bash pipeline/setup-forgejo-repos.sh
```

## Post-Deployment

1. **Jenkins**: Access at `http://10.RANGE.99.3:8080`, configure credentials for Mythic API token, LitterBox API token, and signing keys
2. **Forgejo**: Access at `http://10.RANGE.99.2:3000`, push loader source code to the repos
3. **Mythic**: Access at `https://10.RANGE.99.6:7443`, Daedalus commands are available to trigger builds from the C2 UI
4. **LitterBox**: Access at `http://10.RANGE.99.12:1337`
5. **Kibana**: Access at `https://10.RANGE.10.10:5601` for EDR alert review

## References

- [MAAS (original)](https://github.com/yoda66/MAAS) - Joff Thyer, WWHF 2023
- [Erebus](https://github.com/Whispergate/Erebus) - Initial access packaging
- [Sphinx](https://github.com/Whispergate/Sphinx) - LitterBox ↔ Mythic eventing bridge
- [Daedalus](https://github.com/Whispergate/Daedalus) - CI/CD ↔ Mythic eventing bridge
- [Mythic C2](https://github.com/its-a-feature/Mythic)
- [Ludus](https://docs.ludus.cloud)
