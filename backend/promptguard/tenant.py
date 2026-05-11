"""Multi-tenant isolation.

Resolves tenant_id from the API key and provides tenant-scoped
audit trail access. When auth is disabled, all requests belong
to the "default" tenant.
"""

from __future__ import annotations

from .config import API_AUTH_ENABLED, API_KEY_TENANTS

DEFAULT_TENANT = "default"


def resolve_tenant(authorization: str | None) -> str:
    """Resolve tenant_id from the Authorization header."""
    if not API_AUTH_ENABLED or not authorization:
        return DEFAULT_TENANT
    token = authorization.removeprefix("Bearer ").strip()
    return API_KEY_TENANTS.get(token, DEFAULT_TENANT)
