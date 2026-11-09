#!/usr/bin/env bash
# =============================================================================
# Sentinel AI - Database Restore Script
# =============================================================================
# Usage:
#   ./scripts/restore_database.sh <path_to_backup_file.sql.gz>
# =============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path_to_backup_file.sql.gz>" >&2
    exit 1
fi

BACKUP_FILE="$1"
CONTAINER_NAME="${POSTGRES_CONTAINER:-sentinelai-postgres}"
DB_NAME="${POSTGRES_DB:-sentinelai}"
DB_USER="${POSTGRES_USER:-sentinelai_user}"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "ERROR: Backup file not found: ${BACKUP_FILE}" >&2
    exit 1
fi

echo "============================================================================="
echo "WARNING: This will overwrite data in '${DB_NAME}' on '${CONTAINER_NAME}'!"
echo "Target backup: ${BACKUP_FILE}"
echo "============================================================================="
read -r -p "Are you sure you want to proceed? [y/N]: " CONFIRMATION

if [[ ! "${CONFIRMATION}" =~ ^[Yy]$ ]]; then
    echo "Restore aborted by user."
    exit 0
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting restore into '${DB_NAME}'..."

if gzip -dc "${BACKUP_FILE}" | docker exec -i "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Database successfully restored from ${BACKUP_FILE}."
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Database restore failed!" >&2
    exit 1
fi
