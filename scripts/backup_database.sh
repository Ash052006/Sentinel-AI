#!/usr/bin/env bash
# =============================================================================
# Sentinel AI - Automated Database Backup Script
# =============================================================================
# Usage:
#   ./scripts/backup_database.sh [destination_directory]
# Example cron job (runs every night at 2:00 AM):
#   0 2 * * * /path/to/Sentinel\ AI/scripts/backup_database.sh /var/backups/sentinelai >> /var/log/sentinelai_backup.log 2>&1
# =============================================================================

set -euo pipefail

BACKUP_DIR="${1:-./backups}"
CONTAINER_NAME="${POSTGRES_CONTAINER:-sentinelai-postgres}"
DB_NAME="${POSTGRES_DB:-sentinelai}"
DB_USER="${POSTGRES_USER:-sentinelai_user}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_backup_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting backup of database '${DB_NAME}' from container '${CONTAINER_NAME}'..."

# Run pg_dump inside container and compress with gzip
if docker exec -t "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip -9 > "${BACKUP_FILE}"; then
    FILE_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup successfully created: ${BACKUP_FILE} (${FILE_SIZE})"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Database backup failed!" >&2
    exit 1
fi

# Rotate backups: remove archives older than RETENTION_DAYS
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Pruning backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "${DB_NAME}_backup_*.sql.gz" -type f -mtime +"${RETENTION_DAYS}" -exec rm -f {} \;

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup maintenance complete."
