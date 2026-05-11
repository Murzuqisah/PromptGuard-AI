import unittest.mock as mock

from fastapi.testclient import TestClient

from promptguard.api import app

client = TestClient(app)


def test_rbac_disabled_allows_all():
    """When auth is disabled, all endpoints are accessible."""
    r = client.post("/v1/webhooks", json={"url": "http://example.com", "events": ["DENY"]})
    assert r.status_code == 200


def test_rbac_viewer_can_scan():
    """Viewer role can access scan endpoints."""
    with mock.patch("promptguard.rbac.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.rbac.API_KEYS", ["key-viewer"]), \
         mock.patch("promptguard.rbac.API_KEY_ROLES", {"key-viewer": "viewer"}):
        r = client.post("/scan", json={"channel": "prompt", "content": "Hello"},
                        headers={"Authorization": "Bearer key-viewer"})
        assert r.status_code == 200


def test_rbac_viewer_cannot_override():
    """Viewer role cannot access override endpoints (requires analyst)."""
    with mock.patch("promptguard.rbac.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.rbac.API_KEYS", ["key-viewer"]), \
         mock.patch("promptguard.rbac.API_KEY_ROLES", {"key-viewer": "viewer"}):
        r = client.post("/v1/override", json={
            "event_id": "test", "new_decision": "ALLOW",
            "reason": "test", "overridden_by": "test"
        }, headers={"Authorization": "Bearer key-viewer"})
        assert r.status_code == 403
        assert "Insufficient permissions" in r.json()["detail"]


def test_rbac_viewer_cannot_manage_webhooks():
    """Viewer role cannot manage webhooks (requires admin)."""
    with mock.patch("promptguard.rbac.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.rbac.API_KEYS", ["key-viewer"]), \
         mock.patch("promptguard.rbac.API_KEY_ROLES", {"key-viewer": "viewer"}):
        r = client.post("/v1/webhooks", json={"url": "http://x.com", "events": ["DENY"]},
                        headers={"Authorization": "Bearer key-viewer"})
        assert r.status_code == 403


def test_rbac_analyst_can_override():
    """Analyst role can access override endpoints."""
    with mock.patch("promptguard.rbac.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.rbac.API_KEYS", ["key-analyst"]), \
         mock.patch("promptguard.rbac.API_KEY_ROLES", {"key-analyst": "analyst"}):
        r = client.post("/v1/override", json={
            "event_id": "test-id", "new_decision": "ALLOW",
            "reason": "Confirmed safe.", "overridden_by": "analyst@co.com"
        }, headers={"Authorization": "Bearer key-analyst"})
        assert r.status_code == 200


def test_rbac_analyst_cannot_manage_webhooks():
    """Analyst role cannot manage webhooks (requires admin)."""
    with mock.patch("promptguard.rbac.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.rbac.API_KEYS", ["key-analyst"]), \
         mock.patch("promptguard.rbac.API_KEY_ROLES", {"key-analyst": "analyst"}):
        r = client.post("/v1/webhooks", json={"url": "http://x.com", "events": ["DENY"]},
                        headers={"Authorization": "Bearer key-analyst"})
        assert r.status_code == 403


def test_rbac_admin_can_do_everything():
    """Admin role has full access."""
    with mock.patch("promptguard.rbac.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.rbac.API_KEYS", ["key-admin"]), \
         mock.patch("promptguard.rbac.API_KEY_ROLES", {"key-admin": "admin"}):
        headers = {"Authorization": "Bearer key-admin"}
        assert client.post("/scan", json={"channel": "prompt", "content": "hi"}, headers=headers).status_code == 200
        assert client.post("/v1/webhooks", json={"url": "http://x.com", "events": ["DENY"]}, headers=headers).status_code == 200
        assert client.post("/v1/override", json={
            "event_id": "x", "new_decision": "DENY", "reason": "test", "overridden_by": "admin"
        }, headers=headers).status_code == 200
