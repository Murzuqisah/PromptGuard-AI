# ─── Stage 1: Build Frontend ──────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
ENV VITE_API_BASE_URL=""
RUN npm run build

# ─── Stage 2: Production Image ───────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Install nginx for serving frontend
RUN apt-get update && apt-get install -y --no-install-recommends nginx curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend
COPY backend/ /app/backend/

# Copy built frontend
COPY --from=frontend-build /app/frontend/dist /var/www/html

# Nginx config: serve frontend + proxy API
RUN cat > /etc/nginx/sites-available/default << 'EOF'
server {
listen 80;
listen 10000;
server_name _;

# Frontend (SPA)
location / {
root /var/www/html;
index index.html;
try_files $uri $uri/ /index.html;
}

# API proxy
location /health { proxy_pass http://127.0.0.1:8000; }
location /scan { proxy_pass http://127.0.0.1:8000; }
location /scan-tool { proxy_pass http://127.0.0.1:8000; }
location /audit { proxy_pass http://127.0.0.1:8000; }
location /v1/ { proxy_pass http://127.0.0.1:8000; }
location /docs { proxy_pass http://127.0.0.1:8000; }
location /redoc { proxy_pass http://127.0.0.1:8000; }
location /openapi.json { proxy_pass http://127.0.0.1:8000; }
location /ws/ {
proxy_pass http://127.0.0.1:8000;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
}
}
EOF

# Create data directory for SQLite
RUN mkdir -p /app/data

# Copy .env.example as fallback
COPY .env.example /app/.env.example

# Startup script
RUN cat > /app/start.sh << 'EOF'
#!/bin/bash
set -e

# Replace nginx port with PORT env var if set (for Render/Railway)
if [ -n "$PORT" ] && [ "$PORT" != "80" ]; then
  sed -i "s/listen 10000;/listen $PORT;/" /etc/nginx/sites-available/default
fi

# Start nginx in background
nginx -g "daemon on;"

# Start uvicorn
exec uvicorn promptguard.api:app \
    --app-dir /app/backend \
    --host 127.0.0.1 \
    --port 8000 \
    --workers ${PROMPTGUARD_WORKERS:-2}
EOF
RUN chmod +x /app/start.sh

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

EXPOSE 80 10000

CMD ["/app/start.sh"]
