# =============================================================================
# Sentinel AI - Backend Production Dockerfile
# =============================================================================
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install minimal OS dependencies required for C extensions and health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create an unprivileged user for security compliance (non-root)
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/bash -m sentinel

# Copy application source and entrypoint script
COPY . .
RUN chmod +x docker-entrypoint.sh && \
    chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8000

# Health check verifies the live API server
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
