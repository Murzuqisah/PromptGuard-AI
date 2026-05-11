"""Human approval queue for HUMAN_REVIEW decisions.

When a scan returns HUMAN_REVIEW, the event can be queued for manual
approval. Analysts approve or reject via API, with full audit trail.
Items that exceed the timeout are auto-denied.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

_TIMEOUT_SECONDS = int(os.getenv("PROMPTGUARD_APPROVAL_TIMEOUT", "3600"))

# In-memory queue (production would use a database)
QUEUE: list[dict[str, Any]] = []


def enqueue(event: dict[str, Any]) -> dict[str, Any]:
    """Add a HUMAN_REVIEW event to the approval queue."""
    item = {
        "queue_id": event["event_id"],
        "event_id": event["event_id"],
        "channel": event.get("channel", ""),
        "decision": event.get("decision", "HUMAN_REVIEW"),
        "risk_score": event.get("risk_score", 0),
        "summary": event.get("summary", ""),
        "tenant_id": event.get("tenant_id", "default"),
        "source": event.get("source", ""),
        "action": event.get("action", ""),
        "status": "pending",
        "queued_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(seconds=_TIMEOUT_SECONDS)).isoformat(),
        "resolved_at": None,
        "resolved_by": None,
        "resolution": None,
    }
    QUEUE.append(item)
    return item


def get_pending(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Get all pending items, expiring timed-out ones."""
    _expire_timed_out()
    items = [i for i in QUEUE if i["status"] == "pending"]
    if tenant_id:
        items = [i for i in items if i["tenant_id"] == tenant_id]
    return items


def get_all(tenant_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Get all queue items (pending + resolved)."""
    _expire_timed_out()
    items = list(reversed(QUEUE))
    if tenant_id:
        items = [i for i in items if i["tenant_id"] == tenant_id]
    return items[:limit]


def resolve(queue_id: str, resolution: Literal["approve", "reject"], resolved_by: str) -> dict[str, Any] | None:
    """Approve or reject a queued item."""
    for item in QUEUE:
        if item["queue_id"] == queue_id and item["status"] == "pending":
            item["status"] = "approved" if resolution == "approve" else "rejected"
            item["resolution"] = resolution
            item["resolved_at"] = datetime.now(UTC).isoformat()
            item["resolved_by"] = resolved_by
            return item
    return None


def _expire_timed_out() -> None:
    """Auto-deny items that have exceeded the timeout."""
    now = datetime.now(UTC)
    for item in QUEUE:
        if item["status"] == "pending":
            expires = datetime.fromisoformat(item["expires_at"])
            if now > expires:
                item["status"] = "expired"
                item["resolution"] = "auto-denied (timeout)"
                item["resolved_at"] = now.isoformat()
                item["resolved_by"] = "system"
