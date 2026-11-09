#!/usr/bin/env bash
set -e

# Run database migrations if requested
if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "Running Alembic database migrations..."
    alembic upgrade head
    echo "Database migrations complete."
fi

# Execute the main container process
exec "$@"
