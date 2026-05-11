#!/usr/bin/env bash
set -euo pipefail

python -m uvicorn promptguard.api:app --app-dir backend --reload --port 8000

