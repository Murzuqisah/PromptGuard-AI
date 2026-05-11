from fastapi.testclient import TestClient

from promptguard.api import app

client = TestClient(app)


def test_queue_empty_initially():
    r = client.get("/v1/queue")
    assert r.status_code == 200
    assert r.json()["pending_count"] == 0


def test_guard_enqueues_human_review():
    """HUMAN_REVIEW decisions from /v1/guard are auto-enqueued."""
    # Trigger a HUMAN_REVIEW (secret detection with moderate severity)
    r = client.post("/v1/guard", json={
        "action": "send_message",
        "content": "The token is api_key='sk_test_1234567890abcdef' for the deployment.",
        "channel": "output",
        "source": "test-agent",
    })
    assert r.status_code == 200
    # Check queue has the item
    q = client.get("/v1/queue")
    assert q.json()["pending_count"] >= 1


def test_resolve_approve():
    """Approve a queued item."""
    # Get a pending item
    q = client.get("/v1/queue").json()
    pending = [i for i in q["items"] if i["status"] == "pending"]
    assert len(pending) > 0

    queue_id = pending[0]["queue_id"]
    r = client.post(f"/v1/queue/{queue_id}/resolve", json={
        "resolution": "approve",
        "resolved_by": "analyst@test.com",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "approved"
    assert r.json()["resolved_by"] == "analyst@test.com"


def test_resolve_reject():
    """Reject a queued item."""
    # Create another HUMAN_REVIEW event
    client.post("/v1/guard", json={
        "action": "access_file",
        "content": "Reading .ssh/id_rsa for backup purposes",
        "channel": "tool_call",
        "source": "test",
        "metadata": {"arguments": {"path": ".ssh/id_rsa"}},
    })
    q = client.get("/v1/queue").json()
    pending = [i for i in q["items"] if i["status"] == "pending"]
    assert len(pending) > 0

    queue_id = pending[0]["queue_id"]
    r = client.post(f"/v1/queue/{queue_id}/resolve", json={
        "resolution": "reject",
        "resolved_by": "admin@test.com",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"


def test_resolve_nonexistent_returns_404():
    r = client.post("/v1/queue/nonexistent-id/resolve", json={
        "resolution": "approve",
        "resolved_by": "test",
    })
    assert r.status_code == 404


def test_queue_all_shows_resolved():
    r = client.get("/v1/queue?status=all")
    assert r.status_code == 200
    items = r.json()["items"]
    statuses = {i["status"] for i in items}
    assert "approved" in statuses or "rejected" in statuses
