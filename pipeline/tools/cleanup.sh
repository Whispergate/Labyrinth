#!/bin/bash
# MAAS artifact cleanup automation
# Usage: cleanup.sh [--dry-run] [--max-age DAYS] [--max-count N]
#
# Cleans old payloads, Jenkins builds, stale Mythic callbacks,
# unused Docker images, and oversized build caches.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
MAX_AGE="${MAX_AGE:-30}"
MAX_COUNT="${MAX_COUNT:-50}"
PAYLOADS_DIR="${PAYLOADS_DIR:-/payloads}"
JENKINS_URL="${JENKINS_URL:-http://10.5.99.3:8080}"
MYTHIC_URL="${MYTHIC_URL:-https://10.5.99.6:7443}"
DRY_RUN="${DRY_RUN:-false}"
CACHE_WARN_GB="${CACHE_WARN_GB:-5}"
LOG_FILE="${LOG_FILE:-/var/log/maas/cleanup-$(date +%Y%m%d-%H%M%S).log}"

DELETED_COUNT=0
FREED_BYTES=0

# ── Argument parsing ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)    DRY_RUN=true; shift ;;
        --max-age)    MAX_AGE="$2"; shift 2 ;;
        --max-count)  MAX_COUNT="$2"; shift 2 ;;
        --payloads)   PAYLOADS_DIR="$2"; shift 2 ;;
        --jenkins)    JENKINS_URL="$2"; shift 2 ;;
        --mythic)     MYTHIC_URL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--dry-run] [--max-age DAYS] [--max-count N]"
            echo ""
            echo "Options:"
            echo "  --dry-run      Show what would be deleted without deleting"
            echo "  --max-age N    Delete artifacts older than N days (default: 30)"
            echo "  --max-count N  Keep at most N artifacts per loader (default: 50)"
            echo "  --payloads DIR Payloads directory (default: /payloads)"
            echo "  --jenkins URL  Jenkins URL (default: http://10.5.99.3:8080)"
            echo "  --mythic URL   Mythic URL (default: https://10.5.99.6:7443)"
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

dry_run_prefix() {
    if [ "$DRY_RUN" = "true" ]; then
        echo "[DRY-RUN] "
    fi
}

human_size() {
    local bytes=$1
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes/1073741824" | bc) GB"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes/1048576" | bc) MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes/1024" | bc) KB"
    else
        echo "${bytes} B"
    fi
}

# ── 1. Clean old payload artifacts ────────────────────────────────────
clean_payloads() {
    log "[*] Cleaning payloads older than ${MAX_AGE} days..."

    local archive_dir="${PAYLOADS_DIR}/archive"
    if [ ! -d "$archive_dir" ]; then
        log "[*] Archive directory ${archive_dir} does not exist, skipping"
        return
    fi

    # Find old build directories (depth 2 = /payloads/archive/<loader>/<build>)
    local old_dirs
    old_dirs=$(find "$archive_dir" -type d -mindepth 2 -maxdepth 2 -mtime +"$MAX_AGE" 2>/dev/null || true)

    if [ -z "$old_dirs" ]; then
        log "[+] No payload artifacts older than ${MAX_AGE} days"
        return
    fi

    local count=0
    while IFS= read -r dir; do
        [ -z "$dir" ] && continue
        local size
        size=$(du -sb "$dir" 2>/dev/null | cut -f1 || echo 0)
        log "$(dry_run_prefix)Removing: $dir ($(human_size "$size"))"
        if [ "$DRY_RUN" != "true" ]; then
            rm -rf "$dir"
            DELETED_COUNT=$((DELETED_COUNT + 1))
            FREED_BYTES=$((FREED_BYTES + size))
        fi
        count=$((count + 1))
    done <<< "$old_dirs"

    log "[+] $(dry_run_prefix)Processed ${count} old payload directories"

    # Enforce per-loader MAX_COUNT limit
    log "[*] Enforcing max ${MAX_COUNT} artifacts per loader..."
    for loader_dir in "$archive_dir"/*/; do
        [ -d "$loader_dir" ] || continue
        local loader_name
        loader_name=$(basename "$loader_dir")

        # List build dirs sorted newest first
        local build_dirs
        build_dirs=$(find "$loader_dir" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
            | sort -rn | tail -n +"$((MAX_COUNT + 1))" | cut -d' ' -f2- || true)

        if [ -z "$build_dirs" ]; then
            continue
        fi

        while IFS= read -r dir; do
            [ -z "$dir" ] && continue
            local size
            size=$(du -sb "$dir" 2>/dev/null | cut -f1 || echo 0)
            log "$(dry_run_prefix)Over limit (${loader_name}): $dir ($(human_size "$size"))"
            if [ "$DRY_RUN" != "true" ]; then
                rm -rf "$dir"
                DELETED_COUNT=$((DELETED_COUNT + 1))
                FREED_BYTES=$((FREED_BYTES + size))
            fi
        done <<< "$build_dirs"
    done
}

# ── 2. Clean old Jenkins builds ───────────────────────────────────────
clean_jenkins_builds() {
    log "[*] Cleaning Jenkins builds..."

    # Check if Jenkins is reachable
    if ! curl -sf -o /dev/null --connect-timeout 5 "${JENKINS_URL}/api/json" 2>/dev/null; then
        log "[!] Jenkins unreachable at ${JENKINS_URL}, skipping"
        return
    fi

    # Get list of loader jobs
    local jobs
    jobs=$(curl -sf "${JENKINS_URL}/api/json?tree=jobs[name]" 2>/dev/null \
        | jq -r '.jobs[].name // empty' 2>/dev/null \
        | grep -E '^loader-' || true)

    if [ -z "$jobs" ]; then
        log "[*] No loader jobs found in Jenkins"
        return
    fi

    while IFS= read -r job; do
        [ -z "$job" ] && continue
        log "[*] Processing Jenkins job: ${job}"

        # Get all build numbers sorted ascending (oldest first)
        local builds
        builds=$(curl -sf "${JENKINS_URL}/job/${job}/api/json?tree=builds[number,timestamp]" 2>/dev/null \
            | jq -r ".builds | sort_by(.number) | .[].number // empty" 2>/dev/null || true)

        if [ -z "$builds" ]; then
            continue
        fi

        local total
        total=$(echo "$builds" | wc -l)
        local to_delete=$((total - MAX_COUNT))

        if [ "$to_delete" -le 0 ]; then
            log "[+] ${job}: ${total} builds (within limit)"
            continue
        fi

        log "[*] ${job}: ${total} builds, removing oldest ${to_delete}"
        local deleted=0
        while IFS= read -r build_num && [ "$deleted" -lt "$to_delete" ]; do
            [ -z "$build_num" ] && continue
            log "$(dry_run_prefix)Deleting ${job}#${build_num}"
            if [ "$DRY_RUN" != "true" ]; then
                curl -sf -X POST "${JENKINS_URL}/job/${job}/${build_num}/doDelete" \
                    --user "${JENKINS_USER:-admin}:${JENKINS_TOKEN:-}" 2>/dev/null || true
                DELETED_COUNT=$((DELETED_COUNT + 1))
            fi
            deleted=$((deleted + 1))
        done <<< "$builds"
    done <<< "$jobs"
}

# ── 3. Clean stale Mythic callbacks ───────────────────────────────────
clean_mythic_callbacks() {
    log "[*] Cleaning stale Mythic callbacks..."

    if [ -z "${MYTHIC_API_TOKEN:-}" ]; then
        log "[!] MYTHIC_API_TOKEN not set, skipping Mythic cleanup"
        return
    fi

    # Check if Mythic is reachable
    if ! curl -sf -k -o /dev/null --connect-timeout 5 "${MYTHIC_URL}" 2>/dev/null; then
        log "[!] Mythic unreachable at ${MYTHIC_URL}, skipping"
        return
    fi

    # Query for callbacks older than MAX_AGE days via GraphQL
    local cutoff_date
    cutoff_date=$(date -d "-${MAX_AGE} days" -u +"%Y-%m-%dT%H:%M:%S.000Z" 2>/dev/null \
        || date -v-"${MAX_AGE}"d -u +"%Y-%m-%dT%H:%M:%S.000Z" 2>/dev/null \
        || echo "")

    if [ -z "$cutoff_date" ]; then
        log "[!] Could not compute cutoff date, skipping"
        return
    fi

    local query
    query=$(cat <<GRAPHQL
{
    "query": "query { callback(where: {last_checkin: {_lt: \"${cutoff_date}\"}, active: {_eq: true}}) { id display_id host user last_checkin } }"
}
GRAPHQL
)

    local result
    result=$(curl -sf -k -X POST "${MYTHIC_URL}/graphql/" \
        -H "Content-Type: application/json" \
        -H "apitoken: ${MYTHIC_API_TOKEN}" \
        -d "$query" 2>/dev/null || echo '{"data":{"callback":[]}}')

    local stale_callbacks
    stale_callbacks=$(echo "$result" | jq -r '.data.callback[]? | "\(.id)|\(.display_id)|\(.host)|\(.user)|\(.last_checkin)"' 2>/dev/null || true)

    if [ -z "$stale_callbacks" ]; then
        log "[+] No stale Mythic callbacks found"
        return
    fi

    local count=0
    while IFS='|' read -r cb_id display_id host user last_checkin; do
        [ -z "$cb_id" ] && continue
        log "$(dry_run_prefix)Deactivating callback #${display_id} (${user}@${host}, last seen: ${last_checkin})"
        if [ "$DRY_RUN" != "true" ]; then
            local mutation
            mutation=$(cat <<GRAPHQL
{
    "query": "mutation { update_callback_by_pk(pk_columns: {id: ${cb_id}}, _set: {active: false}) { id } }"
}
GRAPHQL
)
            curl -sf -k -X POST "${MYTHIC_URL}/graphql/" \
                -H "Content-Type: application/json" \
                -H "apitoken: ${MYTHIC_API_TOKEN}" \
                -d "$mutation" >/dev/null 2>&1 || true
            DELETED_COUNT=$((DELETED_COUNT + 1))
        fi
        count=$((count + 1))
    done <<< "$stale_callbacks"

    log "[+] $(dry_run_prefix)Processed ${count} stale callbacks"
}

# ── 4. Clean Docker images ────────────────────────────────────────────
clean_docker() {
    log "[*] Cleaning unused Docker images..."

    if ! command -v docker &>/dev/null; then
        log "[!] Docker not found, skipping"
        return
    fi

    # Show dangling images
    local dangling
    dangling=$(docker images -f "dangling=true" -q 2>/dev/null || true)

    if [ -z "$dangling" ]; then
        log "[+] No dangling Docker images"
    else
        local count
        count=$(echo "$dangling" | wc -l)
        log "$(dry_run_prefix)Removing ${count} dangling images"
        if [ "$DRY_RUN" != "true" ]; then
            docker image prune -f >/dev/null 2>&1 || true
        fi
    fi

    # Remove old maas-builder images (keep latest tag only)
    local old_images
    old_images=$(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}' 2>/dev/null \
        | grep 'maas-builder' | grep -v 'latest' \
        | awk '{print $2}' || true)

    if [ -n "$old_images" ]; then
        local count
        count=$(echo "$old_images" | wc -l)
        log "$(dry_run_prefix)Removing ${count} old maas-builder images"
        if [ "$DRY_RUN" != "true" ]; then
            echo "$old_images" | xargs -r docker rmi -f 2>/dev/null || true
        fi
    fi
}

# ── 5. Clean build caches ────────────────────────────────────────────
clean_caches() {
    log "[*] Checking cache sizes..."

    local cache_dirs=(
        "/var/cache/maas/gomod"
        "/var/cache/maas/gobuild"
        "/var/cache/maas/nimble"
        "/var/cache/maas/nim-cache"
        "/var/cache/maas/cargo-registry"
        "/var/cache/maas/cargo-git"
    )

    local warn_bytes=$((CACHE_WARN_GB * 1073741824))
    local any_warning=false

    for cache_dir in "${cache_dirs[@]}"; do
        if [ ! -d "$cache_dir" ]; then
            continue
        fi

        local size
        size=$(du -sb "$cache_dir" 2>/dev/null | cut -f1 || echo 0)

        if [ "$size" -ge "$warn_bytes" ]; then
            log "[!] WARNING: ${cache_dir} is $(human_size "$size") (exceeds ${CACHE_WARN_GB}GB limit)"
            any_warning=true

            # If more than double the limit, offer to clean
            local double_warn=$((warn_bytes * 2))
            if [ "$size" -ge "$double_warn" ]; then
                log "$(dry_run_prefix)Cache critically oversized, cleaning: ${cache_dir}"
                if [ "$DRY_RUN" != "true" ]; then
                    # Remove old cache entries (keep recent files)
                    find "$cache_dir" -type f -atime +"$MAX_AGE" -delete 2>/dev/null || true
                    find "$cache_dir" -type d -empty -delete 2>/dev/null || true
                fi
            fi
        else
            log "[+] ${cache_dir}: $(human_size "$size") (OK)"
        fi
    done

    if [ "$any_warning" = false ]; then
        log "[+] All caches within limits"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────
main() {
    log "=========================================="
    log "MAAS Cleanup - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    log "=========================================="
    log "  Max Age:   ${MAX_AGE} days"
    log "  Max Count: ${MAX_COUNT} per loader"
    log "  Dry Run:   ${DRY_RUN}"
    log ""

    clean_payloads
    echo ""
    clean_jenkins_builds
    echo ""
    clean_mythic_callbacks
    echo ""
    clean_docker
    echo ""
    clean_caches

    echo ""
    log "=========================================="
    log "Cleanup Summary"
    log "=========================================="
    log "  Items processed: ${DELETED_COUNT}"
    if [ "$FREED_BYTES" -gt 0 ]; then
        log "  Space freed:     $(human_size "$FREED_BYTES")"
    fi
    if [ "$DRY_RUN" = "true" ]; then
        log "  Mode: DRY RUN (no changes made)"
    fi
    log "  Log: ${LOG_FILE}"
}

main
