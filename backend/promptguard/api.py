from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import (
    CORS_ORIGINS,
    MAX_CONTENT_LENGTH,
    API_KEYS,
    API_AUTH_ENABLED,
    WEBHOOK_URLS,
    WEBHOOK_EVENTS,
)
from .gemini import is_available as gemini_available
from .scanner import analyze_content, analyze_tool_call, get_audit_events
from .database import get_all_policies, get_policy, update_policy, create_policy, delete_policy

logger = logging.getLogger(__name__)

# ─── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    channel: Literal["prompt", "output", "file"] = "prompt"
    content: str = Field(min_length=1, max_length=MAX_CONTENT_LENGTH)


class ToolScanRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


class GuardRequest(BaseModel):
    """Gateway endpoint for AI systems to check before executing actions."""
    action: str = Field(description="Action the AI wants to perform (e.g., 'execute_command', 'send_message', 'access_file')")
    content: str = Field(min_length=1, max_length=MAX_CONTENT_LENGTH, description="The content/command to be checked")
    channel: Literal["prompt", "output", "file", "tool_call"] = "prompt"
    source: str = Field(default="unknown", description="Identifier of the calling system")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context from the calling system")


class BatchScanRequest(BaseModel):
    """Batch scan multiple items in one request."""
    items: list[ScanRequest] = Field(min_length=1, max_length=50)


class OverrideRequest(BaseModel):
    """Override a previous decision (requires auth)."""
    event_id: str = Field(description="Event ID to override")
    new_decision: Literal["ALLOW", "DENY"] = Field(description="New decision")
    reason: str = Field(min_length=1, max_length=500, description="Justification for override")
    overridden_by: str = Field(default="api", description="Identity of the overrider")


class WebhookRegisterRequest(BaseModel):
    """Register a webhook for real-time alerts."""
    url: str = Field(description="Webhook endpoint URL")
    events: list[str] = Field(default=["DENY", "HUMAN_REVIEW"], description="Events to subscribe to")
    secret: str = Field(default="", description="Optional shared secret for HMAC verification")


class PolicyCreateRequest(BaseModel):
    """Create a custom policy rule."""
    rule_id: str = Field(min_length=1, max_length=20, description="Unique rule ID (e.g., PG-CUSTOM-001)")
    name: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=50)
    severity: int = Field(ge=1, le=100)
    decision: Literal["ALLOW", "LOG", "HUMAN_REVIEW", "DENY"]
    explanation: str = Field(min_length=1, max_length=500)
    pattern: str = Field(default="", description="Regex pattern for detection")
    enabled: bool = True


class PolicyUpdateRequest(BaseModel):
    """Update a policy rule."""
    enabled: bool | None = None
    name: str | None = None
    severity: int | None = Field(default=None, ge=1, le=100)
    decision: Literal["ALLOW", "LOG", "HUMAN_REVIEW", "DENY"] | None = None
    explanation: str | None = None


# ─── State ────────────────────────────────────────────────────────────────────

OVERRIDES: list[dict[str, Any]] = []
REGISTERED_WEBHOOKS: list[dict[str, Any]] = []
STATS: dict[str, int] = {"total_scans": 0, "denied": 0, "allowed": 0, "review": 0, "logged": 0, "overrides": 0}

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PromptGuard AI",
    description="Enterprise AI firewall API. Integrates with security dashboards, CI/CD pipelines, and AI agent runtimes to block vulnerable commands in real-time.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Auth ─────────────────────────────────────────────────────────────────────

def _verify_api_key(authorization: str | None) -> None:
    if not API_AUTH_ENABLED:
        return
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    if token not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")


# ─── Webhooks ─────────────────────────────────────────────────────────────────

async def _fire_webhooks(event: dict[str, Any]) -> None:
    decision = event.get("decision", "")
    all_urls = WEBHOOK_URLS + [w["url"] for w in REGISTERED_WEBHOOKS if decision in w.get("events", [])]
    if not all_urls or decision not in WEBHOOK_EVENTS:
        return
    async with httpx.AsyncClient(timeout=5.0) as client:
        for url in all_urls:
            try:
                await client.post(url, json=event)
            except Exception as e:
                logger.warning(f"Webhook delivery failed to {url}: {e}")


def _update_stats(decision: str) -> None:
    STATS["total_scans"] += 1
    if decision == "DENY":
        STATS["denied"] += 1
    elif decision == "ALLOW":
        STATS["allowed"] += 1
    elif decision == "HUMAN_REVIEW":
        STATS["review"] += 1
    elif decision == "LOG":
        STATS["logged"] += 1


# ─── Core Endpoints ──────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "promptguard-ai",
        "version": "1.0.0",
        "ai_enabled": gemini_available(),
        "auth_enabled": API_AUTH_ENABLED,
        "webhooks_configured": len(WEBHOOK_URLS) + len(REGISTERED_WEBHOOKS),
    }


@app.post("/scan")
def scan(request: ScanRequest, background_tasks: BackgroundTasks, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _verify_api_key(authorization)
    result = analyze_content(request.content, request.channel)
    _update_stats(result["decision"])
    background_tasks.add_task(_fire_webhooks, result)
    return result


@app.post("/scan-tool")
def scan_tool(request: ToolScanRequest, background_tasks: BackgroundTasks, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _verify_api_key(authorization)
    result = analyze_tool_call(request.tool_name, request.arguments)
    _update_stats(result["decision"])
    background_tasks.add_task(_fire_webhooks, result)
    return result


@app.get("/audit")
def audit(limit: int = 50, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _verify_api_key(authorization)
    return {"events": get_audit_events(limit)}


# ─── Enterprise Integration Endpoints ────────────────────────────────────────

@app.post("/v1/guard")
def guard(request: GuardRequest, background_tasks: BackgroundTasks, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """
    Primary gateway endpoint for AI agent runtimes.

    Call this BEFORE executing any AI-generated action. Returns a decision
    that the calling system MUST respect:
    - ALLOW: proceed with the action
    - DENY: block the action immediately
    - HUMAN_REVIEW: queue for human approval
    - LOG: allow but record for audit

    Response includes `permitted` (bool) for simple integration.
    """
    _verify_api_key(authorization)

    if request.channel == "tool_call":
        result = analyze_tool_call(request.action, request.metadata.get("arguments", {"command": request.content}))
    else:
        result = analyze_content(request.content, request.channel)

    _update_stats(result["decision"])
    background_tasks.add_task(_fire_webhooks, {**result, "source": request.source, "action": request.action})

    permitted = result["decision"] in ("ALLOW", "LOG")

    return {
        "permitted": permitted,
        "decision": result["decision"],
        "risk_score": result["risk_score"],
        "event_id": result["event_id"],
        "summary": result["summary"],
        "findings_count": len(result["findings"]),
        "findings": result["findings"],
        "ai_enhanced": result.get("ai_enhanced", False),
        "action": request.action,
        "source": request.source,
        "timestamp": result["timestamp"],
    }


@app.post("/v1/batch")
def batch_scan(request: BatchScanRequest, background_tasks: BackgroundTasks, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Scan multiple items in a single request. Useful for CI/CD pipelines and bulk analysis."""
    _verify_api_key(authorization)

    results = []
    denied_count = 0
    for item in request.items:
        result = analyze_content(item.content, item.channel)
        _update_stats(result["decision"])
        if result["decision"] == "DENY":
            denied_count += 1
        results.append({
            "decision": result["decision"],
            "risk_score": result["risk_score"],
            "event_id": result["event_id"],
            "summary": result["summary"],
            "findings_count": len(result["findings"]),
        })

    overall = "DENY" if denied_count > 0 else "ALLOW"
    return {
        "overall_decision": overall,
        "total": len(results),
        "denied": denied_count,
        "results": results,
    }


@app.post("/v1/override")
def override_decision(request: OverrideRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """
    Override a previous scan decision. Requires authentication.
    Used by security teams to manually allow/deny flagged content.
    All overrides are audit-logged.
    """
    _verify_api_key(authorization)

    override_record = {
        "override_id": str(uuid4()),
        "event_id": request.event_id,
        "new_decision": request.new_decision,
        "reason": request.reason,
        "overridden_by": request.overridden_by,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    OVERRIDES.append(override_record)
    STATS["overrides"] += 1

    return {
        "status": "accepted",
        **override_record,
    }


@app.get("/v1/overrides")
def list_overrides(limit: int = 50, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """List recent decision overrides."""
    _verify_api_key(authorization)
    return {"overrides": OVERRIDES[-limit:][::-1]}


@app.post("/v1/webhooks")
def register_webhook(request: WebhookRegisterRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Register a webhook endpoint for real-time security alerts."""
    _verify_api_key(authorization)

    webhook = {
        "id": str(uuid4()),
        "url": request.url,
        "events": request.events,
        "registered_at": datetime.now(UTC).isoformat(),
    }
    REGISTERED_WEBHOOKS.append(webhook)

    return {"status": "registered", **webhook}


@app.get("/v1/webhooks")
def list_webhooks(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """List registered webhooks."""
    _verify_api_key(authorization)
    return {"webhooks": REGISTERED_WEBHOOKS}


@app.delete("/v1/webhooks/{webhook_id}")
def delete_webhook(webhook_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Remove a registered webhook."""
    _verify_api_key(authorization)
    global REGISTERED_WEBHOOKS
    REGISTERED_WEBHOOKS = [w for w in REGISTERED_WEBHOOKS if w["id"] != webhook_id]
    return {"status": "deleted", "id": webhook_id}


@app.get("/v1/stats")
def stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """
    Security metrics for dashboards.
    Returns scan counts, decision breakdown, and threat detection rate.
    """
    _verify_api_key(authorization)

    total = STATS["total_scans"] or 1
    return {
        **STATS,
        "threat_rate": round((STATS["denied"] + STATS["review"]) / total * 100, 1),
        "ai_enabled": gemini_available(),
    }


# ─── Policy CRUD Endpoints ────────────────────────────────────────────────────

@app.get("/v1/policies")
def list_policies(category: str | None = None, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """List all policy rules with their enabled/disabled state."""
    _verify_api_key(authorization)
    policies = get_all_policies()
    if category:
        policies = [p for p in policies if p["category"] == category]
    return {"policies": policies, "total": len(policies)}


@app.get("/v1/policies/{rule_id}")
def get_policy_detail(rule_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Get a single policy rule by ID."""
    _verify_api_key(authorization)
    policy = get_policy(rule_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {rule_id} not found")
    return policy


@app.patch("/v1/policies/{rule_id}")
def patch_policy(rule_id: str, request: PolicyUpdateRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Update a policy rule (enable/disable, change severity, etc)."""
    _verify_api_key(authorization)
    existing = get_policy(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Policy {rule_id} not found")
    updates = request.model_dump(exclude_none=True)
    updated = update_policy(rule_id, updates)
    return updated  # type: ignore


@app.post("/v1/policies")
def create_custom_policy(request: PolicyCreateRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Create a custom policy rule."""
    _verify_api_key(authorization)
    existing = get_policy(request.rule_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"Policy {request.rule_id} already exists")
    policy = create_policy(request.model_dump())
    return policy  # type: ignore


@app.delete("/v1/policies/{rule_id}")
def delete_custom_policy(rule_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Delete a custom policy rule. Built-in rules cannot be deleted."""
    _verify_api_key(authorization)
    deleted = delete_policy(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Policy {rule_id} not found or is a built-in rule")
    return {"status": "deleted", "rule_id": rule_id}
