#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------------------------------------
# Labyrinth range - Forgejo + Jenkins + Daedalus bootstrap
#
# Creates organisations, repos, webhooks, Forgejo Actions workflows,
# Jenkins pipeline jobs, and the secrets Daedalus needs to trigger builds.
#
# Run from an operator workstation that can reach Forgejo and Jenkins.
# Requires: curl, jq, git
#
# Usage:
#   bash pipeline/setup.sh                  # interactive prompts
#   bash pipeline/setup.sh --non-interactive  # use env vars / defaults only
# --------------------------------------------------------------------------

NON_INTERACTIVE=false
for arg in "$@"; do
    case "$arg" in
        --non-interactive|-n) NON_INTERACTIVE=true ;;
    esac
done

# --------------------------------------------------------------------------
# Prompt helper - uses existing env var or default, asks user to confirm/edit.
# In non-interactive mode, silently accepts the env var / default.
# For secrets, pass "secret" as $4 to hide input.
# --------------------------------------------------------------------------
prompt_var() {
    local var_name="$1"
    local label="$2"
    local default_val="$3"
    local is_secret="${4:-}"

    local current="${!var_name:-$default_val}"

    if [[ "$NON_INTERACTIVE" == true ]]; then
        printf -v "$var_name" '%s' "$current"
        return
    fi

    if [[ "$is_secret" == "secret" && -n "$current" ]]; then
        local display="****${current: -4}"
    else
        local display="$current"
    fi

    if [[ -n "$display" ]]; then
        printf "  %s [%s]: " "$label" "$display"
    else
        printf "  %s: " "$label"
    fi

    if [[ "$is_secret" == "secret" ]]; then
        read -rs input
        echo ""
    else
        read -r input
    fi

    if [[ -n "$input" ]]; then
        printf -v "$var_name" '%s' "$input"
    else
        printf -v "$var_name" '%s' "$current"
    fi
}

# --------------------------------------------------------------------------
# Interactive configuration
# --------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  Labyrinth Pipeline Setup"
echo "=========================================="
echo ""

if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "Configure your range. Press Enter to accept the default shown in brackets."
    echo "Set environment variables beforehand to pre-fill values."
    echo ""
fi

# --- Range second octet ---
RANGE_OCTET="${RANGE_OCTET:-}"

if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "[1/5] Range network"
    echo ""
    prompt_var RANGE_OCTET "Range second octet (e.g. 5 for 10.5.x.x)" ""

    if [[ -z "$RANGE_OCTET" ]]; then
        echo ""
        echo "  ERROR: Range second octet is required."
        echo "  This is the number from your Ludus range (e.g. 5 for 10.5.x.x)."
        echo "  Find it with: ludus range list"
        exit 1
    fi
    echo ""
fi

if [[ -z "$RANGE_OCTET" ]]; then
    echo "ERROR: RANGE_OCTET must be set in non-interactive mode."
    echo "  export RANGE_OCTET=5  # your range second octet"
    exit 1
fi

# Build default URLs from the octet
_FORGEJO_DEFAULT="https://10.${RANGE_OCTET}.99.2"
_JENKINS_DEFAULT="http://10.${RANGE_OCTET}.99.3:8080"
_MYTHIC_DEFAULT="https://10.${RANGE_OCTET}.99.6:7443"
_LITTERBOX_DEFAULT="http://10.${RANGE_OCTET}.99.12:1337"

# --- Service URLs ---
FORGEJO_URL="${FORGEJO_URL:-$_FORGEJO_DEFAULT}"
JENKINS_URL="${JENKINS_URL:-$_JENKINS_DEFAULT}"
MYTHIC_URL="${MYTHIC_URL:-$_MYTHIC_DEFAULT}"
LITTERBOX_URL="${LITTERBOX_URL:-$_LITTERBOX_DEFAULT}"

if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "[2/5] Service URLs"
    echo ""
    prompt_var FORGEJO_URL    "Forgejo URL"    "$_FORGEJO_DEFAULT"
    prompt_var JENKINS_URL    "Jenkins URL"    "$_JENKINS_DEFAULT"
    prompt_var MYTHIC_URL     "Mythic URL"     "$_MYTHIC_DEFAULT"
    prompt_var LITTERBOX_URL  "LitterBox URL"  "$_LITTERBOX_DEFAULT"
    echo ""
fi

# --- Credentials ---
FORGEJO_USER="${FORGEJO_USER:-forgejo-admin}"
FORGEJO_PASS="${FORGEJO_PASS:-ForgejoPW1!}"
JENKINS_USER="${JENKINS_USER:-admin}"
JENKINS_PASS="${JENKINS_PASS:-JenkinsPW1!}"

if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "[3/5] Service credentials"
    echo ""
    prompt_var FORGEJO_USER  "Forgejo admin user"      "forgejo-admin"
    prompt_var FORGEJO_PASS  "Forgejo admin password"   "ForgejoPW1!"  secret
    prompt_var JENKINS_USER  "Jenkins admin user"       "admin"
    prompt_var JENKINS_PASS  "Jenkins admin password"   "JenkinsPW1!"  secret
    echo ""
fi

# --- API token ---
MYTHIC_API_TOKEN="${MYTHIC_API_TOKEN:-}"

if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "[4/5] Mythic API token"
    echo "  (leave blank to skip - you can add this later via Jenkins/Forgejo UI)"
    echo ""
    prompt_var MYTHIC_API_TOKEN  "Mythic API token"     ""  secret
    echo ""
fi

# --- Webhook token ---
JENKINS_WEBHOOK_TOKEN="${JENKINS_WEBHOOK_TOKEN:-maas-build-trigger}"

if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "[5/5] Jenkins webhook"
    echo ""
    prompt_var JENKINS_WEBHOOK_TOKEN  "Webhook trigger token"  "maas-build-trigger"
    echo ""
fi

# --------------------------------------------------------------------------
# Confirm before proceeding
# --------------------------------------------------------------------------
if [[ "$NON_INTERACTIVE" == false ]]; then
    echo "=========================================="
    echo "  Configuration summary"
    echo "=========================================="
    echo ""
    echo "  Range octet:  ${RANGE_OCTET}"
    echo "  Forgejo:      ${FORGEJO_URL} (${FORGEJO_USER})"
    echo "  Jenkins:      ${JENKINS_URL} (${JENKINS_USER})"
    echo "  Mythic:       ${MYTHIC_URL}"
    echo "  LitterBox:    ${LITTERBOX_URL}"
    if [[ -n "${MYTHIC_API_TOKEN}" ]]; then
        echo "  Mythic token: set"
    else
        echo "  Mythic token: not set"
    fi
    echo ""
    printf "  Proceed? [Y/n]: "
    read -r confirm
    if [[ "${confirm,,}" == "n" ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# --------------------------------------------------------------------------
# Build curl commands
# --------------------------------------------------------------------------
CURL="curl -sk -u ${FORGEJO_USER}:${FORGEJO_PASS}"
CURL_JENKINS="curl -sk -u ${JENKINS_USER}:${JENKINS_PASS}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------
# 1. Organisations
# --------------------------------------------------------------------------
echo "[*] Creating organisations..."
for org in offensive-tooling configs; do
    $CURL -X POST "${FORGEJO_URL}/api/v1/orgs" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"${org}\", \"visibility\": \"private\"}" \
        2>/dev/null || echo "  org '${org}' may already exist"
done

# --------------------------------------------------------------------------
# 2. Repos
# --------------------------------------------------------------------------
echo "[*] Creating repos..."
declare -A REPOS=(
    ["offensive-tooling/loader-c-mingw"]="C loader compiled with MinGW"
    ["offensive-tooling/loader-c-ollvm"]="C loader with Clang + OLLVM passes"
    ["offensive-tooling/loader-go-garble"]="Go loader obfuscated with Garble"
    ["offensive-tooling/loader-nim"]="Nim loader cross-compiled with MinGW"
    ["offensive-tooling/loader-csharp"]="C# loader built with .NET SDK"
    ["configs/pipeline-configs"]="YAML pipeline configurations and build profiles"
)

for repo_path in "${!REPOS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    desc="${REPOS[$repo_path]}"

    $CURL -X POST "${FORGEJO_URL}/api/v1/orgs/${org}/repos" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${repo}\", \"description\": \"${desc}\", \"private\": true, \"auto_init\": true}" \
        2>/dev/null || echo "  repo '${repo_path}' may already exist"
done

# --------------------------------------------------------------------------
# 3. Jenkins webhooks (generic-webhook-trigger on push)
# --------------------------------------------------------------------------
echo "[*] Configuring webhooks for Jenkins..."
for repo_path in "${!REPOS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    [[ "$org" == "configs" ]] && continue

    $CURL -X POST "${FORGEJO_URL}/api/v1/repos/${org}/${repo}/hooks" \
        -H "Content-Type: application/json" \
        -d "{
            \"type\": \"forgejo\",
            \"active\": true,
            \"config\": {
                \"url\": \"${JENKINS_URL}/generic-webhook-trigger/invoke?token=${JENKINS_WEBHOOK_TOKEN}\",
                \"content_type\": \"json\",
                \"secret\": \"\"
            },
            \"events\": [\"push\"]
        }" 2>/dev/null || echo "  webhook for '${repo_path}' may already exist"
done

# --------------------------------------------------------------------------
# 4. Forgejo API token for Daedalus
# --------------------------------------------------------------------------
echo "[*] Creating Forgejo API token for Daedalus..."
DAEDALUS_TOKEN=$($CURL -s -X POST "${FORGEJO_URL}/api/v1/users/${FORGEJO_USER}/tokens" \
    -H "Content-Type: application/json" \
    -d '{"name": "daedalus", "scopes": ["all"]}' \
    | jq -r '.sha1 // empty') || true

if [[ -z "${DAEDALUS_TOKEN:-}" ]]; then
    echo "  token 'daedalus' may already exist - reusing existing token"
    echo "  (set DAEDALUS_FORGEJO_TOKEN env var if you already have one)"
    DAEDALUS_TOKEN="${DAEDALUS_FORGEJO_TOKEN:-}"
fi

# --------------------------------------------------------------------------
# 5. Enable Forgejo Actions on build repos
# --------------------------------------------------------------------------
echo "[*] Enabling Forgejo Actions on build repos..."
for repo_path in "${!REPOS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    [[ "$org" == "configs" ]] && continue

    $CURL -s -X PATCH "${FORGEJO_URL}/api/v1/repos/${org}/${repo}" \
        -H "Content-Type: application/json" \
        -d '{"has_actions": true}' \
        >/dev/null 2>&1 || echo "  could not enable actions on '${repo_path}'"
done

# --------------------------------------------------------------------------
# 6. Forgejo Actions secrets (for Daedalus workflow_dispatch builds)
# --------------------------------------------------------------------------
echo "[*] Setting Forgejo Actions secrets..."
set_forgejo_secret() {
    local org="$1" repo="$2" name="$3" value="$4"
    $CURL -s -X PUT "${FORGEJO_URL}/api/v1/repos/${org}/${repo}/actions/secrets/${name}" \
        -H "Content-Type: application/json" \
        -d "{\"data\": \"${value}\"}" \
        >/dev/null 2>&1 || echo "  could not set secret '${name}' on '${org}/${repo}'"
}

for repo_path in "${!REPOS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    [[ "$org" == "configs" ]] && continue

    if [[ -n "${MYTHIC_URL}" ]]; then
        set_forgejo_secret "$org" "$repo" "MYTHIC_URL"   "$MYTHIC_URL"
    fi
    if [[ -n "${MYTHIC_API_TOKEN}" ]]; then
        set_forgejo_secret "$org" "$repo" "MYTHIC_TOKEN"  "$MYTHIC_API_TOKEN"
    fi
    if [[ -n "${LITTERBOX_URL}" ]]; then
        set_forgejo_secret "$org" "$repo" "LITTERBOX_URL"   "$LITTERBOX_URL"
    fi
done

# --------------------------------------------------------------------------
# 7. Push Forgejo Actions workflow + Jenkinsfile into each build repo
# --------------------------------------------------------------------------
echo "[*] Pushing pipeline files into repos..."

FORGEJO_GIT_URL="${FORGEJO_URL/https:\/\//https://${FORGEJO_USER}:${FORGEJO_PASS}@}"

# Daedalus Forgejo workflow - per-language build commands from Labyrinth
generate_forgejo_workflow() {
    local language="$1"
    cat <<'WORKFLOW_HEADER'
name: Daedalus Build

on:
  workflow_dispatch:
    inputs:
      LANGUAGE:
        description: "Build language/toolchain"
        required: false
      OUTPUT_FORMAT:
        description: "Output format (exe, dll, shellcode)"
        required: false
        default: "exe"
      OBFUSCATION:
        description: "Obfuscation profile"
        required: false
        default: "none"
      SHELLCODE_SOURCE:
        description: "Mythic payload ref (mythic:<uuid>)"
        required: false
        default: ""
      SHELLCODE_FILE:
        description: "Path to shellcode file in repo"
        required: false
        default: "shellcode/payload.bin"
      PE_SANITISE:
        description: "Strip PE metadata post-build"
        required: false
        default: "true"
      LITTERBOX_SCAN:
        description: "Submit to LitterBox after build"
        required: false
        default: "true"
      SCAN_TYPE:
        description: "LitterBox scan profile"
        required: false
        default: "all"

jobs:
  build:
    runs-on: [self-hosted, maas]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Fetch payload from Mythic
        if: startsWith(inputs.SHELLCODE_SOURCE, 'mythic:')
        run: |
          mkdir -p shellcode
          UUID="${{ inputs.SHELLCODE_SOURCE }}"
          UUID="${UUID#mythic:}"
          curl -sk -H "apitoken: ${{ secrets.MYTHIC_TOKEN }}" \
            "${{ secrets.MYTHIC_URL }}/api/v1.4/payloads/download/${UUID}" \
            -o "${{ inputs.SHELLCODE_FILE }}"
          ls -la "${{ inputs.SHELLCODE_FILE }}"

      - name: Validate shellcode
        run: |
          if [ -n "${{ inputs.SHELLCODE_SOURCE }}" ] || [ -f "${{ inputs.SHELLCODE_FILE }}" ]; then
            test -f "${{ inputs.SHELLCODE_FILE }}" || { echo "[-] No shellcode"; exit 1; }
          fi

WORKFLOW_HEADER

    case "$language" in
        c-mingw)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build shellcode
          [ -f shellcode/payload.bin ] || printf '\xcc' > shellcode/payload.bin
          x86_64-w64-mingw32-windres src/resource.rc -o resource.o
          FMT="${{ inputs.OUTPUT_FORMAT }}"
          if [ "$FMT" = "dll" ]; then
            x86_64-w64-mingw32-gcc -o build/loader.dll \
              src/main.c src/payload.c src/techniques/*.c resource.o \
              -Isrc -shared -lntdll -lkernel32 -mwindows -s -O2
          else
            x86_64-w64-mingw32-gcc -o build/loader.exe \
              src/main.c src/payload.c src/techniques/*.c resource.o \
              -Isrc -lntdll -lkernel32 -mwindows -s -O2
          fi

BUILD_BLOCK
            ;;
        c-ollvm)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build shellcode
          [ -f shellcode/payload.bin ] || printf '\xcc' > shellcode/payload.bin
          x86_64-w64-mingw32-windres src/resource.rc -o resource.o
          OLLVM_FLAGS=""
          case "${{ inputs.OBFUSCATION }}" in
            ollvm-cff)       OLLVM_FLAGS="-mllvm -fla" ;;
            ollvm-bcf-cff)   OLLVM_FLAGS="-mllvm -fla -mllvm -bcf" ;;
            ollvm-full)      OLLVM_FLAGS="-mllvm -fla -mllvm -bcf -mllvm -sub" ;;
            ollvm-heavy)     OLLVM_FLAGS="-mllvm -fla -mllvm -split -mllvm -bcf -mllvm -bcf_prob=100 -mllvm -bcf_loop=3 -mllvm -sub -mllvm -sub_loop=5" ;;
          esac
          clang --target=x86_64-w64-mingw32 $OLLVM_FLAGS \
            -c src/main.c src/payload.c src/ntapi.c src/techniques/*.c -Isrc -O1
          FMT="${{ inputs.OUTPUT_FORMAT }}"
          if [ "$FMT" = "dll" ]; then
            x86_64-w64-mingw32-gcc -o build/loader.dll \
              *.o resource.o -shared -lntdll -lkernel32 -s
          else
            x86_64-w64-mingw32-gcc -o build/loader.exe \
              *.o resource.o -lntdll -lkernel32 -s
          fi

BUILD_BLOCK
            ;;
        go-garble)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          GOOS=windows GOARCH=amd64 \
          garble -literals -tiny build \
            -o build/loader.exe -ldflags="-s -w" \
            ./cmd/loader

BUILD_BLOCK
            ;;
        nim)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          nim c -d:mingw -d:release -d:strip \
            --opt:size --app:gui \
            -o:build/loader.exe src/loader.nim

BUILD_BLOCK
            ;;
        csharp)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          dotnet publish src/Loader.csproj \
            -c Release -r win-x64 \
            --self-contained true \
            -p:PublishSingleFile=true \
            -p:PublishTrimmed=true \
            -o build/

BUILD_BLOCK
            ;;
    esac

    cat <<'WORKFLOW_FOOTER'
      - name: PE Sanitisation
        if: inputs.PE_SANITISE == 'true'
        run: |
          if command -v python3 &>/dev/null && [ -f tools/pe-sanitise.py ]; then
            python3 tools/pe-sanitise.py build/loader.* \
              --strip-rich --randomise-timestamp --strip-debug --strip-version-info
          fi

      - name: Checksum
        run: |
          cd build && sha256sum loader.* > checksums.sha256

      - name: LitterBox Scan
        if: inputs.LITTERBOX_SCAN == 'true'
        run: |
          LB="${{ secrets.LITTERBOX_URL }}"
          FILE=$(ls build/loader.* | head -1)
          MD5=$(curl -sf -X POST "${LB}/upload" \
            -F "file=@${FILE};type=application/octet-stream" | jq -r '.file_info.md5')
          [ -n "$MD5" ] && [ "$MD5" != "null" ] || { echo "[-] Upload failed"; exit 0; }
          echo "[+] Uploaded - MD5: ${MD5}"
          SCAN="${{ inputs.SCAN_TYPE }}"
          case "$SCAN" in
            static)  curl -sf -X POST "${LB}/analyze/static/${MD5}" > /dev/null; sleep 3 ;;
            dynamic) curl -sf -X POST "${LB}/analyze/dynamic/${MD5}" > /dev/null
                     for i in $(seq 1 30); do
                       S=$(curl -sf "${LB}/api/results/dynamic/${MD5}" | jq -r '.status // empty')
                       case "$S" in completed|blocked_by_av|partial|error|"") break ;; esac
                       sleep 5
                     done ;;
            all)     curl -sf -X POST "${LB}/analyze/static/${MD5}" > /dev/null
                     curl -sf -X POST "${LB}/analyze/dynamic/${MD5}" > /dev/null
                     sleep 3
                     for i in $(seq 1 30); do
                       S=$(curl -sf "${LB}/api/results/dynamic/${MD5}" | jq -r '.status // empty')
                       case "$S" in completed|blocked_by_av|partial|error|"") break ;; esac
                       sleep 5
                     done ;;
          esac
          curl -sf "${LB}/api/results/risk/${MD5}" | jq . > build/scan-results.json || true
          echo "[+] Results: ${LB}/results/info/${MD5}"

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: build-${{ github.run_id }}
          path: build/
WORKFLOW_FOOTER
}

# Map repo name to the language used in its workflow
repo_language() {
    case "$1" in
        loader-c-mingw)  echo "c-mingw" ;;
        loader-c-ollvm)  echo "c-ollvm" ;;
        loader-go-garble) echo "go-garble" ;;
        loader-nim)       echo "nim" ;;
        loader-csharp)    echo "csharp" ;;
        *)                echo "" ;;
    esac
}

TMPDIR="$(mktemp -d)"
JENKINS_COOKIE_JAR="$(mktemp)"
trap 'rm -rf "$TMPDIR" "$JENKINS_COOKIE_JAR"' EXIT

for repo_path in "${!REPOS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    [[ "$org" == "configs" ]] && continue

    lang=$(repo_language "$repo")
    [[ -z "$lang" ]] && continue

    echo "  -> ${org}/${repo} (${lang})"

    REPO_DIR="${TMPDIR}/${repo}"
    GIT_SSL_NO_VERIFY=true git clone -q "${FORGEJO_GIT_URL}/${org}/${repo}.git" "$REPO_DIR" 2>/dev/null || {
        echo "    clone failed - skipping"
        continue
    }

    pushd "$REPO_DIR" >/dev/null

    # Forgejo Actions workflow
    mkdir -p .forgejo/workflows
    generate_forgejo_workflow "$lang" > .forgejo/workflows/build.yml

    # Jenkinsfile (copy from pipeline/)
    if [[ -f "${SCRIPT_DIR}/Jenkinsfile" ]]; then
        cp "${SCRIPT_DIR}/Jenkinsfile" Jenkinsfile
    fi

    # PE sanitisation tool
    if [[ -f "${SCRIPT_DIR}/tools/pe-sanitise.py" ]]; then
        mkdir -p tools
        cp "${SCRIPT_DIR}/tools/pe-sanitise.py" tools/pe-sanitise.py
    fi

    # Build profiles
    if [[ -f "${SCRIPT_DIR}/build-profiles.yml" ]]; then
        cp "${SCRIPT_DIR}/build-profiles.yml" build-profiles.yml
    fi

    # Source layout + example loaders
    mkdir -p src shellcode
    LOADER_DIR="${SCRIPT_DIR}/../loaders/${repo}"
    if [[ -d "$LOADER_DIR/src" ]]; then
        cp -r "$LOADER_DIR"/src/* src/ 2>/dev/null || true
    else
        [[ -f src/.gitkeep ]] || touch src/.gitkeep
    fi
    [[ -f shellcode/.gitkeep ]] || touch shellcode/.gitkeep
    if [[ "$lang" == "go-garble" ]]; then
        mkdir -p cmd/loader
        [[ -f cmd/loader/.gitkeep ]] || touch cmd/loader/.gitkeep
    fi

    git add -A
    if ! git diff --cached --quiet; then
        GIT_SSL_NO_VERIFY=true git \
            -c user.name="Labyrinth Setup" \
            -c user.email="setup@labyrinth.range" \
            commit -q -m "Add Daedalus workflows, Jenkinsfile, and pipeline tooling"
        GIT_SSL_NO_VERIFY=true git push -q origin main 2>/dev/null || echo "    push failed"
    else
        echo "    already up to date"
    fi

    popd >/dev/null
done

# Push build profiles into configs/pipeline-configs
echo "  -> configs/pipeline-configs"
CONFIGS_DIR="${TMPDIR}/pipeline-configs"
GIT_SSL_NO_VERIFY=true git clone -q "${FORGEJO_GIT_URL}/configs/pipeline-configs.git" "$CONFIGS_DIR" 2>/dev/null || true
if [[ -d "$CONFIGS_DIR" ]]; then
    pushd "$CONFIGS_DIR" >/dev/null
    [[ -f "${SCRIPT_DIR}/build-profiles.yml" ]] && cp "${SCRIPT_DIR}/build-profiles.yml" build-profiles.yml
    git add -A
    if ! git diff --cached --quiet; then
        GIT_SSL_NO_VERIFY=true git \
            -c user.name="Labyrinth Setup" \
            -c user.email="setup@labyrinth.range" \
            commit -q -m "Add build profiles"
        GIT_SSL_NO_VERIFY=true git push -q origin main 2>/dev/null || echo "    push failed"
    fi
    popd >/dev/null
fi

# --------------------------------------------------------------------------
# 8. Jenkins pipeline jobs (one per build repo)
#    Jenkins crumbs are session-bound - the JSESSIONID cookie from the crumb
#    request must be sent with every subsequent POST.
# --------------------------------------------------------------------------
echo "[*] Creating Jenkins pipeline jobs..."

jenkins_crumb() {
    curl -sk -u "${JENKINS_USER}:${JENKINS_PASS}" \
        -c "$JENKINS_COOKIE_JAR" \
        "${JENKINS_URL}/crumbIssuer/api/json" \
        | jq -r '.crumb // empty' 2>/dev/null || echo ""
}

CRUMB=$(jenkins_crumb)
if [[ -z "$CRUMB" ]]; then
    echo "  WARNING: could not fetch Jenkins crumb - job/credential creation may fail"
fi

jenkins_post() {
    curl -sk -u "${JENKINS_USER}:${JENKINS_PASS}" \
        -b "$JENKINS_COOKIE_JAR" \
        -H "Jenkins-Crumb: ${CRUMB}" \
        "$@"
}

create_jenkins_job() {
    local job_name="$1" org="$2" repo="$3"

    local config_xml
    config_xml=$(cat <<JOBXML
<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <actions/>
  <description>Daedalus/Labyrinth build pipeline for ${org}/${repo}</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
      <triggers>
        <org.jenkinsci.plugins.gwt.GenericTrigger plugin="generic-webhook-trigger">
          <spec/>
          <token>${JENKINS_WEBHOOK_TOKEN}</token>
          <printContributedVariables>false</printContributedVariables>
          <printPostContent>false</printPostContent>
          <causeString>Forgejo push to ${org}/${repo}</causeString>
        </org.jenkinsci.plugins.gwt.GenericTrigger>
      </triggers>
    </org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition" plugin="workflow-cps">
    <scm class="hudson.plugins.git.GitSCM" plugin="git">
      <configVersion>2</configVersion>
      <userRemoteConfigs>
        <hudson.plugins.git.UserRemoteConfig>
          <url>${FORGEJO_URL}/${org}/${repo}.git</url>
          <credentialsId>forgejo-git</credentialsId>
        </hudson.plugins.git.UserRemoteConfig>
      </userRemoteConfigs>
      <branches>
        <hudson.plugins.git.BranchSpec>
          <name>*/main</name>
        </hudson.plugins.git.BranchSpec>
      </branches>
      <extensions>
        <hudson.plugins.git.extensions.impl.GitClientDisableSSLVerification/>
      </extensions>
    </scm>
    <scriptPath>Jenkinsfile</scriptPath>
    <lightweight>true</lightweight>
  </definition>
  <disabled>false</disabled>
</flow-definition>
JOBXML
    )

    local http_code
    http_code=$(jenkins_post -s -o /dev/null -w "%{http_code}" \
        -X POST "${JENKINS_URL}/createItem?name=${job_name}" \
        -H "Content-Type: application/xml" \
        -d "${config_xml}")

    case "$http_code" in
        200) echo "  created '${job_name}'" ;;
        400) echo "  job '${job_name}' already exists" ;;
        *)   echo "  WARNING: job '${job_name}' returned HTTP ${http_code}" ;;
    esac
}

for repo_path in "${!REPOS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    [[ "$org" == "configs" ]] && continue

    create_jenkins_job "$repo" "$org" "$repo"
done

# --------------------------------------------------------------------------
# 9. Jenkins credentials
# --------------------------------------------------------------------------
echo "[*] Configuring Jenkins credentials..."

add_jenkins_credential() {
    local cred_xml="$1" cred_id="$2"

    local http_code
    http_code=$(jenkins_post -s -o /dev/null -w "%{http_code}" \
        -X POST "${JENKINS_URL}/credentials/store/system/domain/_/createCredentials" \
        -H "Content-Type: application/xml" \
        -d "${cred_xml}")

    case "$http_code" in
        200) echo "  created credential '${cred_id}'" ;;
        409) echo "  credential '${cred_id}' already exists" ;;
        *)   echo "  WARNING: credential '${cred_id}' returned HTTP ${http_code}" ;;
    esac
}

# Forgejo Git credential (used by pipeline SCM checkout)
FORGEJO_GIT_CRED=$(cat <<CREDXML
<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
  <scope>GLOBAL</scope>
  <id>forgejo-git</id>
  <description>Forgejo Git access for pipeline checkout</description>
  <username>${FORGEJO_USER}</username>
  <password>${FORGEJO_PASS}</password>
</com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
CREDXML
)
add_jenkins_credential "$FORGEJO_GIT_CRED" "forgejo-git"

# Secret text credentials
add_jenkins_secret_text() {
    local cred_id="$1" cred_secret="$2" cred_desc="$3"
    [[ -z "$cred_secret" ]] && return

    local cred_xml
    cred_xml=$(cat <<CREDXML
<org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
  <scope>GLOBAL</scope>
  <id>${cred_id}</id>
  <description>${cred_desc}</description>
  <secret>${cred_secret}</secret>
</org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
CREDXML
    )
    add_jenkins_credential "$cred_xml" "$cred_id"
}

add_jenkins_secret_text "mythic-url"       "$MYTHIC_URL"       "Mythic server URL"
add_jenkins_secret_text "mythic-api-token"  "$MYTHIC_API_TOKEN" "Mythic API token"
add_jenkins_secret_text "litterbox-url"     "$LITTERBOX_URL"    "LitterBox scanner URL"

# --------------------------------------------------------------------------
# 10. Disable Git SSL verification in Jenkins (Forgejo uses self-signed cert)
# --------------------------------------------------------------------------
echo "[*] Disabling Git SSL verification in Jenkins..."

# Set GIT_SSL_NO_VERIFY globally AND run git config --global to cover the
# lightweight SCM checkout (which uses the system git, not the Jenkins env).
http_code=$(jenkins_post -s -o /dev/null -w "%{http_code}" \
    -X POST "${JENKINS_URL}/scriptText" \
    --data-urlencode "script=import jenkins.model.Jenkins
def instance = Jenkins.getInstance()
def desc = instance.getDescriptor('hudson.plugins.git.GitSCM')
desc.setGlobalConfigName('Labyrinth Setup')
desc.setGlobalConfigEmail('setup@labyrinth.range')
desc.save()
instance.getGlobalNodeProperties().replaceBy(
  [new hudson.slaves.EnvironmentVariablesNodeProperty(
    [new hudson.slaves.EnvironmentVariablesNodeProperty.Entry('GIT_SSL_NO_VERIFY', 'true')]
  )]
)
instance.save()
['git', 'config', '--global', 'http.sslVerify', 'false'].execute().waitFor()
println('OK')")

case "$http_code" in
    200) echo "  Git SSL verification disabled globally" ;;
    *)   echo "  WARNING: could not disable Git SSL verification (HTTP ${http_code})"
         echo "  Set it manually: Manage Jenkins > System > Global properties > Environment variables"
         echo "    Name: GIT_SSL_NO_VERIFY  Value: true"
         echo "  And on the Jenkins server: git config --global http.sslVerify false" ;;
esac

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  Setup complete"
echo "=========================================="
echo ""
echo "  Range:        10.${RANGE_OCTET}.x.x"
echo "  Forgejo:      ${FORGEJO_URL} (${FORGEJO_USER})"
echo "  Jenkins:      ${JENKINS_URL} (${JENKINS_USER})"
echo "  Mythic:       ${MYTHIC_URL}"
echo "  LitterBox:    ${LITTERBOX_URL}"
if [[ -n "${DAEDALUS_TOKEN:-}" ]]; then
echo "  Daedalus tok: ${DAEDALUS_TOKEN}"
fi
echo ""
echo "  Daedalus provider config for Mythic Eventing UI:"
echo ""
echo "    Forgejo provider:"
echo "      url:   ${FORGEJO_URL}"
echo "      token: ${DAEDALUS_TOKEN:-<create manually or set DAEDALUS_FORGEJO_TOKEN>}"
echo "      owner: offensive-tooling"
echo ""
echo "    Jenkins provider:"
echo "      url:   ${JENKINS_URL}"
echo "      user:  ${JENKINS_USER}"
echo "      token: <generate at ${JENKINS_URL}/user/${JENKINS_USER}/security/>"
echo ""
echo "  Each build repo now contains:"
echo "    .forgejo/workflows/build.yml  - Daedalus workflow_dispatch target"
echo "    Jenkinsfile                   - Full Jenkins pipeline"
echo "    tools/pe-sanitise.py          - PE metadata sanitisation tool"
echo "    build-profiles.yml            - Predefined build profiles"
