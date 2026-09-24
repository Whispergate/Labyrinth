#!/bin/bash
# Runner auto-scaling for MAAS Jenkins
# Usage: runner-scale.sh up|down|status
#
# Manages scaling of a third Linux Jenkins agent (runner-lin03)
# based on current queue depth and agent load.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/runner-scale-config.yml"

JENKINS_URL="http://10.5.99.3:8080"
JENKINS_USER="admin"
JENKINS_PASS="JenkinsPW1!"
JENKINS_CLI="/opt/jenkins-agent/jenkins-cli.jar"

# Scale node details (from runner-scale-config.yml or defaults)
SCALE_NODE_NAME="runner-lin03"
SCALE_NODE_HOST="10.5.99.8"
SCALE_NODE_LABELS="linux-c linux-go linux-rust linux-nim linux-generic"
SCALE_NODE_EXECUTORS=2
SCALE_NODE_REMOTE_ROOT="/opt/jenkins-agent"
SCALE_NODE_CREDENTIALS_ID="jenkins-ssh"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*"; }

# ---------------------------------------------------------------------------
# Jenkins API helpers
# ---------------------------------------------------------------------------

jenkins_api() {
    local endpoint="$1"
    curl -sf -u "${JENKINS_USER}:${JENKINS_PASS}" \
        "${JENKINS_URL}${endpoint}" 2>/dev/null
}

jenkins_api_post() {
    local endpoint="$1"
    shift
    curl -sf -u "${JENKINS_USER}:${JENKINS_PASS}" \
        -X POST "${JENKINS_URL}${endpoint}" "$@" 2>/dev/null
}

get_crumb() {
    local crumb_json
    crumb_json=$(jenkins_api "/crumbIssuer/api/json" 2>/dev/null || true)
    if [ -n "${crumb_json}" ]; then
        local field value
        field=$(echo "${crumb_json}" | jq -r '.crumbRequestField')
        value=$(echo "${crumb_json}" | jq -r '.crumb')
        echo "-H ${field}:${value}"
    fi
}

# ---------------------------------------------------------------------------
# status - Show agent overview
# ---------------------------------------------------------------------------

cmd_status() {
    log_info "Querying Jenkins agent status..."

    local computers
    computers=$(jenkins_api "/computer/api/json?depth=1")
    if [ -z "${computers}" ]; then
        log_error "Failed to reach Jenkins API at ${JENKINS_URL}"
        exit 1
    fi

    local total online busy idle offline
    total=$(echo "${computers}" | jq '.computer | length')
    online=$(echo "${computers}" | jq '[.computer[] | select(.offline == false)] | length')
    busy=$(echo "${computers}" | jq '[.computer[] | select(.offline == false) | .executors[] | select(.idle == false)] | length')
    idle=$(echo "${computers}" | jq '[.computer[] | select(.offline == false) | .executors[] | select(.idle == true)] | length')
    offline=$(echo "${computers}" | jq '[.computer[] | select(.offline == true)] | length')

    echo ""
    echo "=== Jenkins Agent Status ==="
    echo "Total nodes:      ${total}"
    echo "Online:           ${online}"
    echo "Offline:          ${offline}"
    echo "Busy executors:   ${busy}"
    echo "Idle executors:   ${idle}"
    echo ""

    # Per-node detail
    echo "--- Node Detail ---"
    echo "${computers}" | jq -r '
        .computer[] |
        "  \(.displayName)  online=\(.offline | not)  executors=\(.numExecutors)  busy=\([.executors[] | select(.idle == false)] | length)"
    '
    echo ""

    # Queue depth
    local queue
    queue=$(jenkins_api "/queue/api/json")
    local queued
    queued=$(echo "${queue}" | jq '.items | length')
    echo "Queued builds:    ${queued}"
    echo ""

    # Check if scale node exists
    local scale_status
    scale_status=$(echo "${computers}" | jq -r \
        --arg name "${SCALE_NODE_NAME}" \
        '.computer[] | select(.displayName == $name) | "exists=true offline=\(.offline)"')

    if [ -n "${scale_status}" ]; then
        log_info "Scale node '${SCALE_NODE_NAME}': ${scale_status}"
    else
        log_warn "Scale node '${SCALE_NODE_NAME}' is not registered"
    fi
}

# ---------------------------------------------------------------------------
# up - Register the third runner
# ---------------------------------------------------------------------------

cmd_up() {
    log_info "Scaling UP: registering ${SCALE_NODE_NAME}..."

    # Check if already exists
    local exists
    exists=$(jenkins_api "/computer/${SCALE_NODE_NAME}/api/json" 2>/dev/null && echo "yes" || echo "no")
    if [ "${exists}" = "yes" ]; then
        log_warn "${SCALE_NODE_NAME} is already registered"

        # Bring online if it was marked offline
        local is_offline
        is_offline=$(jenkins_api "/computer/${SCALE_NODE_NAME}/api/json" | jq -r '.offline')
        if [ "${is_offline}" = "true" ]; then
            log_info "Node is offline - bringing back online..."
            local crumb
            crumb=$(get_crumb)
            jenkins_api_post "/computer/${SCALE_NODE_NAME}/toggleOffline" \
                ${crumb} -d "offlineMessage=" || true
            log_info "${SCALE_NODE_NAME} brought online"
        else
            log_info "${SCALE_NODE_NAME} is already online"
        fi
        return 0
    fi

    # Create node via Jenkins API
    local crumb
    crumb=$(get_crumb)

    local node_json
    node_json=$(cat <<NODEJSON
{
  "name": "${SCALE_NODE_NAME}",
  "nodeDescription": "Auto-scaled Linux runner 3",
  "numExecutors": "${SCALE_NODE_EXECUTORS}",
  "remoteFS": "${SCALE_NODE_REMOTE_ROOT}",
  "labelString": "${SCALE_NODE_LABELS}",
  "mode": "EXCLUSIVE",
  "retentionStrategy": {
    "stapler-class": "hudson.slaves.RetentionStrategy\$Always"
  },
  "nodeProperties": {
    "stapler-class-bag": "true"
  },
  "launcher": {
    "stapler-class": "hudson.plugins.sshslaves.SSHLauncher",
    "host": "${SCALE_NODE_HOST}",
    "credentialsId": "${SCALE_NODE_CREDENTIALS_ID}",
    "port": "22",
    "javaPath": "",
    "jvmOptions": "",
    "prefixStartSlaveCmd": "",
    "suffixStartSlaveCmd": "",
    "launchTimeoutSeconds": "60",
    "maxNumRetries": "3",
    "retryWaitTime": "15",
    "sshHostKeyVerificationStrategy": {
      "stapler-class": "hudson.plugins.sshslaves.verifiers.NonVerifyingKeyVerificationStrategy"
    }
  },
  "type": "hudson.slaves.DumbSlave"
}
NODEJSON
)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${JENKINS_USER}:${JENKINS_PASS}" \
        -X POST "${JENKINS_URL}/computer/doCreateItem" \
        ${crumb} \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "name=${SCALE_NODE_NAME}" \
        --data-urlencode "type=hudson.slaves.DumbSlave" \
        --data-urlencode "json=${node_json}")

    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 400 ]; then
        log_info "${SCALE_NODE_NAME} registered successfully (HTTP ${http_code})"
    else
        log_error "Failed to register ${SCALE_NODE_NAME} (HTTP ${http_code})"
        log_error "Ensure the host ${SCALE_NODE_HOST} is reachable and SSH credentials '${SCALE_NODE_CREDENTIALS_ID}' exist"
        exit 1
    fi

    # Wait for agent to come online
    log_info "Waiting for ${SCALE_NODE_NAME} to connect..."
    local attempts=0
    while [ ${attempts} -lt 30 ]; do
        local online
        online=$(jenkins_api "/computer/${SCALE_NODE_NAME}/api/json" 2>/dev/null \
            | jq -r '.offline' 2>/dev/null || echo "true")
        if [ "${online}" = "false" ]; then
            log_info "${SCALE_NODE_NAME} is ONLINE"
            return 0
        fi
        sleep 5
        attempts=$((attempts + 1))
    done

    log_warn "${SCALE_NODE_NAME} registered but not yet online after 150s - check connectivity to ${SCALE_NODE_HOST}"
}

# ---------------------------------------------------------------------------
# down - Remove the third runner (only if idle)
# ---------------------------------------------------------------------------

cmd_down() {
    log_info "Scaling DOWN: removing ${SCALE_NODE_NAME}..."

    # Check if exists
    local node_info
    node_info=$(jenkins_api "/computer/${SCALE_NODE_NAME}/api/json" 2>/dev/null || true)
    if [ -z "${node_info}" ]; then
        log_warn "${SCALE_NODE_NAME} is not registered - nothing to do"
        return 0
    fi

    # Check if busy
    local busy_count
    busy_count=$(echo "${node_info}" | jq '[.executors[] | select(.idle == false)] | length')
    if [ "${busy_count}" -gt 0 ]; then
        log_error "${SCALE_NODE_NAME} has ${busy_count} busy executor(s) - cannot remove while builds are running"
        log_error "Wait for builds to finish or use 'status' to check"
        exit 1
    fi

    # Mark offline first, then delete
    local crumb
    crumb=$(get_crumb)

    jenkins_api_post "/computer/${SCALE_NODE_NAME}/toggleOffline" \
        ${crumb} -d "offlineMessage=Scaled+down+by+runner-scale.sh" 2>/dev/null || true

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${JENKINS_USER}:${JENKINS_PASS}" \
        -X POST "${JENKINS_URL}/computer/${SCALE_NODE_NAME}/doDelete" \
        ${crumb})

    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 400 ]; then
        log_info "${SCALE_NODE_NAME} removed successfully"
    else
        log_error "Failed to remove ${SCALE_NODE_NAME} (HTTP ${http_code})"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

usage() {
    echo "Usage: $(basename "$0") <up|down|status>"
    echo ""
    echo "  status  - Show agent overview and queue depth"
    echo "  up      - Register and bring online ${SCALE_NODE_NAME}"
    echo "  down    - Remove ${SCALE_NODE_NAME} (only if idle)"
    exit 1
}

case "${1:-}" in
    status) cmd_status ;;
    up)     cmd_up ;;
    down)   cmd_down ;;
    *)      usage ;;
esac
