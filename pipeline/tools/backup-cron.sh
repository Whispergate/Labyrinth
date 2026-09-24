#!/bin/bash
# MAAS backup cron wrapper
# Run daily backups and prune old ones
#
# Install via crontab on a runner or the Jenkins host:
#   0 2 * * * /path/to/pipeline/tools/backup-cron.sh >> /var/log/maas-backup.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SCRIPT="${SCRIPT_DIR}/backup-restore.sh"
RETENTION_DAYS=30

echo "=== MAAS Backup - $(date '+%Y-%m-%d %H:%M:%S') ==="

# Run full backup
bash "${BACKUP_SCRIPT}" backup all

# Prune backups older than retention period
bash "${BACKUP_SCRIPT}" prune ${RETENTION_DAYS}

echo "=== Backup complete ==="
