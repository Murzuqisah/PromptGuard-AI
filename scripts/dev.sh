#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Load .env from project root (skip lines with spaces in key names)
if [ -f "$ROOT/.env" ]; then
  set -a
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* || "$key" == *" "* ]] && continue
    export "$key=$value"
  done < "$ROOT/.env"
  set +a
fi

BACKEND_PORT="${PROMPTGUARD_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

cleanup() {
  kill 0 2>/dev/null
}
trap cleanup EXIT

# Backend
echo "Starting backend on http://localhost:$BACKEND_PORT"
cd "$ROOT/backend"
if [ ! -d ".venv" ]; then
  python -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
.venv/bin/uvicorn promptguard.api:app --reload --port "$BACKEND_PORT" &

# Frontend
echo "Starting frontend on http://localhost:$FRONTEND_PORT"
cd "$ROOT/frontend"
if [ ! -d "node_modules" ]; then
  npm install
fi
npm run dev -- --port "$FRONTEND_PORT" &

wait
