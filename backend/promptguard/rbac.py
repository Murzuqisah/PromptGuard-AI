"""Role-based access control.

Roles:
- admin: full access (overrides, webhooks, policies, scanning, audit)
- analyst: scanning, audit, overrides, read policies
- viewer: scanning, audit only

When auth is disabled, all requests are treated as admin.
"""

from __future__ import annotations

from fastapi import Header, HTTPException

from .config import API_AUTH_ENABLED, API_KEYS, API_KEY_ROLES

ROLE_HIERARCHY = {"admin": 3, "analyst": 2, "viewer": 1}

# Minimum role required per action
PERMISSIONS: dict[str, str] = {
    "scan": "viewer",
    "audit": "viewer",
    "guard": "viewer",
    "batch": "viewer",
    "stats": "viewer",
    "override": "analyst",
    "policies_read": "analyst",
    "policies_write": "admin",
    "webhooks": "admin",
}


def get_current_role(authorization: str | None) -> str:
    """Extract role from the API key. Returns 'admin' if auth is disabled."""
    if not API_AUTH_ENABLED:
        return "admin"
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    if token not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return API_KEY_ROLES.get(token, "viewer")


def require_role(action: str, authorization: str | None = Header(default=None)) -> str:
    """Verify the caller has sufficient role for the given action. Returns the role."""
    role = get_current_role(authorization)
    required = PERMISSIONS.get(action, "admin")
    if ROLE_HIERARCHY.get(role, 0) < ROLE_HIERARCHY.get(required, 3):
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions. Required role: {required}, your role: {role}",
        )
    return role
