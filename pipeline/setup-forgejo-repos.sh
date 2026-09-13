#!/usr/bin/env bash
set -euo pipefail

# Creates the initial Forgejo organisations and repos, and configures
# webhooks to trigger Jenkins builds on push.
#
# Run from an operator workstation that can reach both Forgejo and Jenkins.

FORGEJO_URL="${FORGEJO_URL:-https://10.RANGE.99.2:3000}"
FORGEJO_USER="${FORGEJO_USER:-forgejo-admin}"
FORGEJO_PASS="${FORGEJO_PASS:-ForgejoPW1!}"
JENKINS_URL="${JENKINS_URL:-http://10.RANGE.99.3:8080}"
JENKINS_WEBHOOK_TOKEN="${JENKINS_WEBHOOK_TOKEN:-maas-build-trigger}"

CURL="curl -sk -u ${FORGEJO_USER}:${FORGEJO_PASS}"

echo "[*] Creating organisations..."
for org in offensive-tooling configs; do
    $CURL -X POST "${FORGEJO_URL}/api/v1/orgs" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"${org}\", \"visibility\": \"private\"}" \
        2>/dev/null || echo "  org '${org}' may already exist"
done

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

echo "[+] Done. Repos and webhooks configured."
echo "    Forgejo: ${FORGEJO_URL}"
echo "    Jenkins: ${JENKINS_URL}"
