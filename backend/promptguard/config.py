from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root: backend/promptguard/config.py -> backend/ -> project root
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")


API_PORT: int = int(os.getenv("PROMPTGUARD_PORT", "8000"))
API_HOST: str = os.getenv("PROMPTGUARD_HOST", "0.0.0.0")
CORS_ORIGINS: list[str] = os.getenv("PROMPTGUARD_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
LOG_LEVEL: str = os.getenv("PROMPTGUARD_LOG_LEVEL", "info")
AUDIT_MAX_EVENTS: int = int(os.getenv("PROMPTGUARD_AUDIT_MAX_EVENTS", "500"))
MAX_CONTENT_LENGTH: int = int(os.getenv("PROMPTGUARD_MAX_CONTENT_LENGTH", "100000"))

# API Authentication
API_KEYS: list[str] = [k.strip() for k in os.getenv("PROMPTGUARD_API_KEYS", "").split(",") if k.strip()]
API_AUTH_ENABLED: bool = os.getenv("PROMPTGUARD_API_AUTH_ENABLED", "false").lower() in ("1", "true", "yes")

# Gemini AI
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_ENABLED: bool = os.getenv("GEMINI_ENABLED", "true").lower() in ("1", "true", "yes")

# Webhooks
WEBHOOK_URLS: list[str] = [u.strip() for u in os.getenv("PROMPTGUARD_WEBHOOK_URLS", "").split(",") if u.strip()]
WEBHOOK_EVENTS: list[str] = os.getenv("PROMPTGUARD_WEBHOOK_EVENTS", "DENY,HUMAN_REVIEW").split(",")

# Multi-tenancy — maps API keys to tenant IDs. Format: key1:tenant-a,key2:tenant-b
# Keys not in this mapping belong to the "default" tenant
_tenant_raw = os.getenv("PROMPTGUARD_API_KEY_TENANTS", "")
API_KEY_TENANTS: dict[str, str] = {}
for _entry in _tenant_raw.split(","):
    if ":" in _entry:
        _key, _tenant = _entry.strip().rsplit(":", 1)
        API_KEY_TENANTS[_key.strip()] = _tenant.strip()
