import unittest.mock as mock
import uuid

from fastapi.testclient import TestClient

from promptguard.api import app

client = TestClient(app)


def test_rate_limit_headers_present():
    # Use unique key to avoid interference from other tests
    headers = {"Authorization": f"Bearer test-{uuid.uuid4()}"}
    r = client.post("/scan", json={"channel": "prompt", "content": "Hello world"}, headers=headers)
    assert r.status_code == 200
    assert "X-RateLimit-Limit" in r.headers
    assert "X-RateLimit-Remaining" in r.headers
    assert "X-RateLimit-Reset" in r.headers


def test_rate_limit_enforced():
    """Verify 429 is returned when limit is exceeded."""
    unique_key = f"Bearer ratelimit-test-{uuid.uuid4()}"
    headers = {"Authorization": unique_key}

    with mock.patch("promptguard.middleware.RATE_LIMIT_REQUESTS", 2):
        r1 = client.post("/scan", json={"channel": "prompt", "content": "req 1"}, headers=headers)
        r2 = client.post("/scan", json={"channel": "prompt", "content": "req 2"}, headers=headers)
        r3 = client.post("/scan", json={"channel": "prompt", "content": "req 3"}, headers=headers)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert r3.json()["error"] == "rate_limit_exceeded"
    assert "Retry-After" in r3.headers


def test_health_bypasses_rate_limit():
    """Health endpoint should never be rate limited."""
    with mock.patch("promptguard.middleware.RATE_LIMIT_REQUESTS", 1):
        r1 = client.get("/health")
        r2 = client.get("/health")
        r3 = client.get("/health")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 200
