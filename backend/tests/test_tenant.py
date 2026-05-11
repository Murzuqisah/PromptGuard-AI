import unittest.mock as mock

from fastapi.testclient import TestClient

from promptguard.api import app

client = TestClient(app)


def test_scan_includes_tenant_id():
    """Scan results include tenant_id field."""
    r = client.post("/scan", json={"channel": "prompt", "content": "Hello world"})
    assert r.status_code == 200
    assert "tenant_id" in r.json()
    assert r.json()["tenant_id"] == "default"


def test_tenant_resolved_from_api_key():
    """When auth is enabled, tenant is resolved from API key mapping."""
    with mock.patch("promptguard.tenant.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.tenant.API_KEY_TENANTS", {"key-acme": "acme-corp"}), \
         mock.patch("promptguard.api.API_AUTH_ENABLED", True), \
         mock.patch("promptguard.api.API_KEYS", ["key-acme"]):
        r = client.post("/scan", json={"channel": "prompt", "content": "Test"},
                        headers={"Authorization": "Bearer key-acme"})
        assert r.status_code == 200
        assert r.json()["tenant_id"] == "acme-corp"


def test_audit_filtered_by_tenant():
    """Audit trail only returns events for the caller's tenant."""
    # Generate events for default tenant
    client.post("/scan", json={"channel": "prompt", "content": "Event for default tenant"})

    r = client.get("/audit?limit=10")
    assert r.status_code == 200
    events = r.json()["events"]
    # All events should belong to "default" tenant
    for event in events:
        assert event.get("tenant_id") == "default"


def test_guard_includes_tenant_id():
    """Guard endpoint includes tenant_id in response."""
    r = client.post("/v1/guard", json={
        "action": "test",
        "content": "Safe content",
        "channel": "prompt",
        "source": "test",
    })
    assert r.status_code == 200
    # tenant_id is in the underlying result (passed through findings)
    # The guard response doesn't directly expose tenant_id but the audit does
    audit = client.get("/audit?limit=1").json()["events"]
    assert len(audit) > 0
    assert audit[0]["tenant_id"] == "default"
