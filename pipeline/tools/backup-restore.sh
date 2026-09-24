#!/bin/bash
# MAAS range backup and restore
# Usage: backup-restore.sh backup|restore|list|prune [target] [timestamp]
#
# Targets: all, forgejo, jenkins, mythic, payloads
#
# Examples:
#   backup-restore.sh backup all
#   backup-restore.sh backup forgejo
#   backup-restore.sh restore forgejo 20260917_143000
#   backup-restore.sh list
#   backup-restore.sh prune 30

set -euo pipefail

BACKUP_DIR="/var/backups/maas"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Infrastructure addresses
JENKINS_URL="http://10.5.99.3:8080"
JENKINS_USER="admin"
JENKINS_PASS="JenkinsPW1!"
JENKINS_HOME="/var/lib/jenkins"

FORGEJO_HOST="10.5.99.2"
FORGEJO_USER="root"
FORGEJO_DATA="/var/lib/gitea"
FORGEJO_BIN="/usr/local/bin/gitea"

MYTHIC_HOST="10.5.99.6"
MYTHIC_USER="root"
MYTHIC_DB_NAME="mythic_db"
MYTHIC_DB_USER="mythic_user"

PAYLOADS_DIR="/payloads"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*"; }
log_step()  { echo -e "${CYAN}[*]${NC} $*"; }

# ---------------------------------------------------------------------------
# Backup functions
# ---------------------------------------------------------------------------

backup_forgejo() {
    local dest="${BACKUP_DIR}/${TIMESTAMP}/forgejo"
    mkdir -p "${dest}"
    log_step "Backing up Forgejo (repos + database)..."

    # Use gitea dump via SSH to the Forgejo host
    ssh "${FORGEJO_USER}@${FORGEJO_HOST}" \
        "cd /tmp && sudo -u git ${FORGEJO_BIN} dump \
            --config /etc/gitea/app.ini \
            --type tar.gz \
            --file /tmp/forgejo-dump.tar.gz" \
        2>&1 || {
            log_warn "gitea dump failed - falling back to directory copy"
            ssh "${FORGEJO_USER}@${FORGEJO_HOST}" \
                "tar czf /tmp/forgejo-dump.tar.gz -C ${FORGEJO_DATA} ."
        }

    scp "${FORGEJO_USER}@${FORGEJO_HOST}:/tmp/forgejo-dump.tar.gz" \
        "${dest}/forgejo-dump.tar.gz"

    ssh "${FORGEJO_USER}@${FORGEJO_HOST}" "rm -f /tmp/forgejo-dump.tar.gz"

    # Also back up the app.ini config separately
    scp "${FORGEJO_USER}@${FORGEJO_HOST}:/etc/gitea/app.ini" \
        "${dest}/app.ini" 2>/dev/null || true

    local size
    size=$(du -sh "${dest}" | awk '{print $1}')
    log_info "Forgejo backup complete: ${dest} (${size})"
}

backup_jenkins() {
    local dest="${BACKUP_DIR}/${TIMESTAMP}/jenkins"
    mkdir -p "${dest}"
    log_step "Backing up Jenkins (jobs, nodes, credentials)..."

    local jenkins_host="10.5.99.3"

    # Job configurations
    ssh "root@${jenkins_host}" \
        "cd ${JENKINS_HOME} && tar czf /tmp/jenkins-jobs.tar.gz \
            --transform='s|^|jobs/|' \
            \$(find jobs -name 'config.xml' -o -name 'nextBuildNumber' 2>/dev/null)" \
        2>&1 || true

    scp "root@${jenkins_host}:/tmp/jenkins-jobs.tar.gz" \
        "${dest}/jenkins-jobs.tar.gz" 2>/dev/null || true

    # Node configurations
    ssh "root@${jenkins_host}" \
        "cd ${JENKINS_HOME} && tar czf /tmp/jenkins-nodes.tar.gz nodes/ 2>/dev/null" \
        2>&1 || true

    scp "root@${jenkins_host}:/tmp/jenkins-nodes.tar.gz" \
        "${dest}/jenkins-nodes.tar.gz" 2>/dev/null || true

    # Credentials and secrets
    ssh "root@${jenkins_host}" \
        "cd ${JENKINS_HOME} && tar czf /tmp/jenkins-creds.tar.gz \
            credentials.xml secrets/ identity.key.enc 2>/dev/null" \
        2>&1 || true

    scp "root@${jenkins_host}:/tmp/jenkins-creds.tar.gz" \
        "${dest}/jenkins-creds.tar.gz" 2>/dev/null || true

    # Plugin list (for reference, not full plugin binaries)
    ssh "root@${jenkins_host}" \
        "ls ${JENKINS_HOME}/plugins/*.jpi 2>/dev/null \
            | xargs -I{} basename {} .jpi" \
        > "${dest}/plugin-list.txt" 2>/dev/null || true

    # Clean up remote temp files
    ssh "root@${jenkins_host}" \
        "rm -f /tmp/jenkins-jobs.tar.gz /tmp/jenkins-nodes.tar.gz /tmp/jenkins-creds.tar.gz" \
        2>/dev/null || true

    local size
    size=$(du -sh "${dest}" | awk '{print $1}')
    log_info "Jenkins backup complete: ${dest} (${size})"
}

backup_mythic() {
    local dest="${BACKUP_DIR}/${TIMESTAMP}/mythic"
    mkdir -p "${dest}"
    log_step "Backing up Mythic (PostgreSQL database)..."

    # PostgreSQL dump via SSH
    ssh "${MYTHIC_USER}@${MYTHIC_HOST}" \
        "docker exec mythic_postgres pg_dump \
            -U ${MYTHIC_DB_USER} ${MYTHIC_DB_NAME} \
            | gzip > /tmp/mythic-db.sql.gz" \
        2>&1 || {
            # Fallback: try direct pg_dump if not dockerised
            ssh "${MYTHIC_USER}@${MYTHIC_HOST}" \
                "sudo -u postgres pg_dump ${MYTHIC_DB_NAME} \
                    | gzip > /tmp/mythic-db.sql.gz"
        }

    scp "${MYTHIC_USER}@${MYTHIC_HOST}:/tmp/mythic-db.sql.gz" \
        "${dest}/mythic-db.sql.gz"

    ssh "${MYTHIC_USER}@${MYTHIC_HOST}" "rm -f /tmp/mythic-db.sql.gz"

    # Also grab the Mythic .env config
    scp "${MYTHIC_USER}@${MYTHIC_HOST}:/opt/Mythic/.env" \
        "${dest}/mythic-env" 2>/dev/null || true

    local size
    size=$(du -sh "${dest}" | awk '{print $1}')
    log_info "Mythic backup complete: ${dest} (${size})"
}

backup_payloads() {
    local dest="${BACKUP_DIR}/${TIMESTAMP}/payloads"
    mkdir -p "${dest}"
    log_step "Backing up payloads directory..."

    if [ -d "${PAYLOADS_DIR}" ]; then
        tar czf "${dest}/payloads.tar.gz" -C "$(dirname "${PAYLOADS_DIR}")" \
            "$(basename "${PAYLOADS_DIR}")"
    else
        log_warn "${PAYLOADS_DIR} does not exist - skipping"
        return 0
    fi

    local size
    size=$(du -sh "${dest}" | awk '{print $1}')
    log_info "Payloads backup complete: ${dest} (${size})"
}

backup_all() {
    log_info "Starting full MAAS backup (timestamp: ${TIMESTAMP})..."
    echo ""
    backup_forgejo
    echo ""
    backup_jenkins
    echo ""
    backup_mythic
    echo ""
    backup_payloads
    echo ""

    local total_size
    total_size=$(du -sh "${BACKUP_DIR}/${TIMESTAMP}" | awk '{print $1}')
    log_info "Full backup complete: ${BACKUP_DIR}/${TIMESTAMP} (${total_size})"
}

# ---------------------------------------------------------------------------
# Restore functions
# ---------------------------------------------------------------------------

restore_forgejo() {
    local ts="${1:?Timestamp required for restore}"
    local src="${BACKUP_DIR}/${ts}/forgejo"

    if [ ! -d "${src}" ]; then
        log_error "No Forgejo backup found at ${src}"
        exit 1
    fi

    log_step "Restoring Forgejo from ${ts}..."
    log_warn "This will stop Forgejo, restore data, and restart it"

    scp "${src}/forgejo-dump.tar.gz" \
        "${FORGEJO_USER}@${FORGEJO_HOST}:/tmp/forgejo-dump.tar.gz"

    ssh "${FORGEJO_USER}@${FORGEJO_HOST}" bash -s <<'REMOTE'
        set -euo pipefail
        systemctl stop gitea || docker stop forgejo 2>/dev/null || true
        cd /tmp
        sudo -u git gitea restore --from /tmp/forgejo-dump.tar.gz \
            --config /etc/gitea/app.ini 2>/dev/null || {
            echo "[!] gitea restore not available - extracting manually"
            rm -rf /var/lib/gitea.bak
            mv /var/lib/gitea /var/lib/gitea.bak
            mkdir -p /var/lib/gitea
            tar xzf /tmp/forgejo-dump.tar.gz -C /var/lib/gitea
            chown -R git:git /var/lib/gitea
        }
        systemctl start gitea || docker start forgejo 2>/dev/null || true
        rm -f /tmp/forgejo-dump.tar.gz
REMOTE

    log_info "Forgejo restore complete"
}

restore_jenkins() {
    local ts="${1:?Timestamp required for restore}"
    local src="${BACKUP_DIR}/${ts}/jenkins"
    local jenkins_host="10.5.99.3"

    if [ ! -d "${src}" ]; then
        log_error "No Jenkins backup found at ${src}"
        exit 1
    fi

    log_step "Restoring Jenkins from ${ts}..."
    log_warn "This will restart Jenkins after restoring configs"

    # Restore jobs
    if [ -f "${src}/jenkins-jobs.tar.gz" ]; then
        scp "${src}/jenkins-jobs.tar.gz" "root@${jenkins_host}:/tmp/"
        ssh "root@${jenkins_host}" \
            "cd ${JENKINS_HOME} && tar xzf /tmp/jenkins-jobs.tar.gz && rm /tmp/jenkins-jobs.tar.gz"
        log_info "Jobs restored"
    fi

    # Restore nodes
    if [ -f "${src}/jenkins-nodes.tar.gz" ]; then
        scp "${src}/jenkins-nodes.tar.gz" "root@${jenkins_host}:/tmp/"
        ssh "root@${jenkins_host}" \
            "cd ${JENKINS_HOME} && tar xzf /tmp/jenkins-nodes.tar.gz && rm /tmp/jenkins-nodes.tar.gz"
        log_info "Node configs restored"
    fi

    # Restore credentials
    if [ -f "${src}/jenkins-creds.tar.gz" ]; then
        scp "${src}/jenkins-creds.tar.gz" "root@${jenkins_host}:/tmp/"
        ssh "root@${jenkins_host}" \
            "cd ${JENKINS_HOME} && tar xzf /tmp/jenkins-creds.tar.gz && rm /tmp/jenkins-creds.tar.gz"
        log_info "Credentials restored"
    fi

    # Restart Jenkins to pick up changes
    ssh "root@${jenkins_host}" "systemctl restart jenkins" 2>/dev/null || true

    log_info "Jenkins restore complete - waiting for restart..."
    sleep 10

    # Verify Jenkins is responding
    local attempts=0
    while [ ${attempts} -lt 12 ]; do
        if curl -sf "${JENKINS_URL}/login" >/dev/null 2>&1; then
            log_info "Jenkins is back online"
            return 0
        fi
        sleep 5
        attempts=$((attempts + 1))
    done
    log_warn "Jenkins may still be starting up"
}

restore_mythic() {
    local ts="${1:?Timestamp required for restore}"
    local src="${BACKUP_DIR}/${ts}/mythic"

    if [ ! -d "${src}" ]; then
        log_error "No Mythic backup found at ${src}"
        exit 1
    fi

    log_step "Restoring Mythic database from ${ts}..."

    scp "${src}/mythic-db.sql.gz" \
        "${MYTHIC_USER}@${MYTHIC_HOST}:/tmp/mythic-db.sql.gz"

    ssh "${MYTHIC_USER}@${MYTHIC_HOST}" bash -s <<REMOTE
        set -euo pipefail
        gunzip -c /tmp/mythic-db.sql.gz | \
            docker exec -i mythic_postgres psql \
                -U ${MYTHIC_DB_USER} -d ${MYTHIC_DB_NAME} 2>/dev/null || {
            echo "[!] Docker restore failed - trying direct psql"
            gunzip -c /tmp/mythic-db.sql.gz | \
                sudo -u postgres psql -d ${MYTHIC_DB_NAME}
        }
        rm -f /tmp/mythic-db.sql.gz
REMOTE

    log_info "Mythic database restore complete"
}

restore_payloads() {
    local ts="${1:?Timestamp required for restore}"
    local src="${BACKUP_DIR}/${ts}/payloads"

    if [ ! -f "${src}/payloads.tar.gz" ]; then
        log_error "No payloads backup found at ${src}"
        exit 1
    fi

    log_step "Restoring payloads from ${ts}..."
    log_warn "Existing payloads directory will be renamed to ${PAYLOADS_DIR}.bak"

    if [ -d "${PAYLOADS_DIR}" ]; then
        mv "${PAYLOADS_DIR}" "${PAYLOADS_DIR}.bak.${TIMESTAMP}"
    fi

    tar xzf "${src}/payloads.tar.gz" -C "$(dirname "${PAYLOADS_DIR}")"

    log_info "Payloads restore complete"
}

# ---------------------------------------------------------------------------
# list - Show available backups
# ---------------------------------------------------------------------------

cmd_list() {
    log_info "Available backups in ${BACKUP_DIR}:"
    echo ""

    if [ ! -d "${BACKUP_DIR}" ] || [ -z "$(ls -A "${BACKUP_DIR}" 2>/dev/null)" ]; then
        log_warn "No backups found"
        return 0
    fi

    printf "%-20s %-10s %s\n" "TIMESTAMP" "SIZE" "CONTENTS"
    printf "%-20s %-10s %s\n" "---------" "----" "--------"

    for dir in "${BACKUP_DIR}"/*/; do
        [ -d "${dir}" ] || continue
        local ts
        ts=$(basename "${dir}")
        local size
        size=$(du -sh "${dir}" | awk '{print $1}')
        local contents
        contents=$(ls "${dir}" | tr '\n' ' ')
        printf "%-20s %-10s %s\n" "${ts}" "${size}" "${contents}"
    done
}

# ---------------------------------------------------------------------------
# prune - Delete old backups
# ---------------------------------------------------------------------------

cmd_prune() {
    local days="${1:?Number of days required}"
    log_step "Pruning backups older than ${days} days..."

    if [ ! -d "${BACKUP_DIR}" ]; then
        log_warn "No backup directory found"
        return 0
    fi

    local count=0
    local cutoff
    cutoff=$(date -d "-${days} days" +%Y%m%d_%H%M%S 2>/dev/null || \
             date -v-"${days}"d +%Y%m%d_%H%M%S 2>/dev/null)

    for dir in "${BACKUP_DIR}"/*/; do
        [ -d "${dir}" ] || continue
        local ts
        ts=$(basename "${dir}")
        if [[ "${ts}" < "${cutoff}" ]]; then
            log_info "Removing ${ts}"
            rm -rf "${dir}"
            count=$((count + 1))
        fi
    done

    log_info "Pruned ${count} backup(s)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [target] [timestamp]

Commands:
  backup <target>              Create a backup
  restore <target> <timestamp> Restore from a specific backup
  list                         List available backups
  prune <days>                 Delete backups older than N days

Targets: all, forgejo, jenkins, mythic, payloads

Examples:
  $(basename "$0") backup all
  $(basename "$0") backup forgejo
  $(basename "$0") restore jenkins 20260917_143000
  $(basename "$0") list
  $(basename "$0") prune 30
EOF
    exit 1
}

mkdir -p "${BACKUP_DIR}"

case "${1:-}" in
    backup)
        case "${2:-all}" in
            all)      backup_all ;;
            forgejo)  backup_forgejo ;;
            jenkins)  backup_jenkins ;;
            mythic)   backup_mythic ;;
            payloads) backup_payloads ;;
            *)        log_error "Unknown target: ${2}"; usage ;;
        esac
        ;;
    restore)
        target="${2:?Target required (forgejo|jenkins|mythic|payloads)}"
        ts="${3:?Timestamp required}"
        case "${target}" in
            forgejo)  restore_forgejo "${ts}" ;;
            jenkins)  restore_jenkins "${ts}" ;;
            mythic)   restore_mythic "${ts}" ;;
            payloads) restore_payloads "${ts}" ;;
            *)        log_error "Unknown target: ${target}"; usage ;;
        esac
        ;;
    list)
        cmd_list
        ;;
    prune)
        cmd_prune "${2:?Number of days required}"
        ;;
    *)
        usage
        ;;
esac
