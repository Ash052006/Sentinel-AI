# Sentinel AI — Production Deployment & Operations Guide

This guide provides instructions for deploying, securing, operating, and backing up **Sentinel AI** in an enterprise production environment.

---

## 1. Production Architecture Overview

In production, Sentinel AI runs as an isolated, containerized topology orchestrated via Docker Compose or Kubernetes:

```
                  ┌───────────────────────────────┐
                  │    Internet / SOC Analysts    │
                  └──────────────┬────────────────┘
                                 │ HTTPS (Port 443 / 80)
                                 ▼
                  ┌───────────────────────────────┐
                  │       NGINX Gateway & SPA     │
                  │   - Hardened Security Headers │
                  │   - Gzip Asset Compression    │
                  │   - Reverse Proxy for /api    │
                  └──────┬─────────────────┬──────┘
                         │                 │
              /api/requests                Static Assets
                         ▼                 ▼
          ┌──────────────────────────┐   ┌──────────────────────┐
          │  FastAPI Backend Cluster │   │ React SPA Web App    │
          │  - Uvicorn/Gunicorn Pool │   │ - Vite Bundle        │
          │  - Alembic Auto-Migrate  │   │ - Dark Cyber Theme   │
          └─────┬──────────────┬─────┘   └──────────────────────┘
                │              │
                │ SQL          │ Pub/Sub
                ▼              ▼
     ┌───────────────────┐   ┌──────────────────────────┐
     │   PostgreSQL 17   │   │     Apache Kafka 3.9     │
     │  - Strict Models  │   │    (KRaft Broker)        │
     │  - Relational DB  │   │  - Security Events       │
     │  - Audit Logs     │   │  - Dead Letter Queue     │
     └───────────────────┘   └─────────────┬────────────┘
                                           │
                                           ▼
                             ┌──────────────────────────┐
                             │  Kafka Ingestion Worker  │
                             │  - Normalize & Detect    │
                             │  - Graph Materialization │
                             └──────────────────────────┘
```

---

## 2. Server Requirements

* **Operating System**: Linux (Ubuntu 22.04 LTS / 24.04 LTS, Debian 12, or RHEL 9 recommended).
* **CPU / Memory**:
  * Minimum: 2 vCPUs, 4 GB RAM.
  * Recommended: 4 vCPUs, 8 GB RAM (especially for real-time Kafka event streams and multi-agent debates).
* **Storage**: 40 GB+ SSD.
* **Prerequisites**:
  * Docker Engine 24.0+
  * Docker Compose v2.20+

---

## 3. 5-Minute One-Command Deployment

### Step 1: Clone Repository on the Server
```bash
git clone https://github.com/your-org/sentinel-ai.git /opt/sentinel-ai
cd /opt/sentinel-ai
```

### Step 2: Configure Production Environment Variables
Copy the template and populate your production secrets:
```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Generate secure random secrets:
```bash
# Generate JWT Secret
openssl rand -hex 32

# Generate Database Password
openssl rand -base64 24
```
Edit `.env.production` with your favorite editor (e.g., `nano .env.production`) and set:
* `JWT_SECRET=<your-generated-jwt-secret>`
* `POSTGRES_PASSWORD=<your-generated-db-password>`
* `DATABASE_URL=postgresql+psycopg://sentinelai_admin:<your-db-password>@postgres:5432/sentinelai`
* `GEMINI_API_KEY=<your-google-gemini-key>`

### Step 3: Launch the Platform
```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

### Step 4: Verify All Services Are Healthy
```bash
docker compose -f docker-compose.prod.yml ps
```
You should see all 5 containers in the `healthy` status:
* `sentinelai-postgres`
* `sentinelai-kafka`
* `sentinelai-backend`
* `sentinelai-kafka-worker`
* `sentinelai-frontend`

Test the live health endpoint:
```bash
curl http://localhost/health
# {"status":"healthy","environment":"production","database":"healthy"}
```

---

## 4. Enabling HTTPS / SSL (Let's Encrypt / Certbot)

For real-world production, the web portal must be served over encrypted HTTPS:

1. Point your domain (e.g. `sentinel.company.com`) to your server's public IP address.
2. Install Certbot:
   ```bash
   sudo apt-get install -y certbot python3-certbot-nginx
   ```
3. Issue a certificate:
   ```bash
   sudo certbot certonly --standalone -d sentinel.company.com
   ```
4. Mount the generated certificates (`/etc/letsencrypt/live/...`) into the `frontend` container in `docker-compose.prod.yml` and add port `443:443`.

---

## 5. Automated Database Backups & Disaster Recovery

An automated backup script is included in `scripts/backup_database.sh`.

### Test Manual Backup
```bash
./scripts/backup_database.sh /var/backups/sentinelai
```
This generates a timestamped, gzip-compressed SQL dump:
`sentinelai_backup_20261109_203000.sql.gz`

### Set Up Automated Daily Backups (Cron)
Open your server crontab:
```bash
crontab -e
```
Add this entry to run backups every night at 2:00 AM and retain the last 30 days:
```cron
0 2 * * * /opt/sentinel-ai/scripts/backup_database.sh /var/backups/sentinelai >> /var/log/sentinelai_backup.log 2>&1
```

### Restore Database from Backup
In case of server migration or disaster recovery:
```bash
./scripts/restore_database.sh /var/backups/sentinelai/sentinelai_backup_20261109_203000.sql.gz
```

---

## 6. Continuous Integration (CI/CD)

The repository includes a GitHub Actions pipeline in `.github/workflows/ci.yml`.

On every commit and pull request, it automatically runs:
1. **Frontend**: Dependency installation (`npm ci`), TypeScript compilation, Vite production build, and Vitest test suite.
2. **Backend**: PostgreSQL test container spin-up, dependency installation, Alembic schema migrations (`alembic upgrade head`), and Pytest test suite.
3. **Docker Smoke**: Multi-stage Docker image builds for both frontend and backend to prevent deployment regressions.

---

## 7. Operational Maintenance & Logs

* **View live backend logs**:
  ```bash
  docker compose -f docker-compose.prod.yml logs -f backend
  ```
* **View Kafka ingestion worker logs**:
  ```bash
  docker compose -f docker-compose.prod.yml logs -f kafka-worker
  ```
* **Graceful Rolling Update**:
  ```bash
  git pull origin main
  docker compose -f docker-compose.prod.yml up -d --build
  ```
