# =============================================================================
# Sentinel AI - Frontend Production Dockerfile (Multi-Stage)
# =============================================================================

# Stage 1: Build the optimized static bundle
FROM node:22-alpine AS builder

WORKDIR /app

# Install npm dependencies using cache-efficient layers
COPY package.json package-lock.json ./
RUN npm ci

# Copy application sources
COPY tsconfig*.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src

# Build the production bundle into /app/dist
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Serve using hardened Alpine NGINX
# -----------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runner

# Remove default nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy production nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# Health check verifies the web server serves the index page
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
