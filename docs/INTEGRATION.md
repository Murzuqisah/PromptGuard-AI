# PromptGuard AI — Enterprise Integration Guide

This guide covers everything you need to integrate PromptGuard AI into your backend systems, AI agent runtimes, CI/CD pipelines, and security dashboards.

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Guard Gateway — Primary Integration](#guard-gateway)
4. [Content Scanning](#content-scanning)
5. [Tool Call Scanning](#tool-call-scanning)
6. [Batch Scanning](#batch-scanning)
7. [Webhook Alerts](#webhook-alerts)
8. [Decision Overrides](#decision-overrides)
9. [Policy Management](#policy-management)
10. [SARIF Export](#sarif-export)
11. [Metrics & Monitoring](#metrics--monitoring)
12. [Integration Patterns](#integration-patterns)
13. [SDK Examples](#sdk-examples)
14. [Error Handling](#error-handling)
15. [Rate Limiting](#rate-limiting)
16. [Deployment](#deployment)

---

## Overview

PromptGuard AI is a security gateway that sits between your AI systems and the actions they perform. Every prompt, model output, file upload, and tool call is inspected before execution.

**Base URL**: `http://your-promptguard-host:8000`

**Decision Model**:

| Decision | Meaning | Action Required |
|----------|---------|-----------------|
| `ALLOW` | Content is safe | Proceed normally |
| `LOG` | Low-risk, worth recording | Proceed, log for audit |
| `HUMAN_REVIEW` | Needs human approval | Queue for review, do NOT auto-execute |
| `DENY` | Blocked | Do NOT execute the action |

**Simple integration**: Check the `permitted` field (boolean) in the response. If `false`, block the action.

---

## Authentication

### Enabling API Keys

Set these environment variables on the PromptGuard server:

```env
PROMPTGUARD_API_AUTH_ENABLED=true
PROMPTGUARD_API_KEYS=pk_prod_abc123,pk_prod_def456,pk_ci_pipeline_789
```

### RBAC (Role-Based Access Control)

Assign roles to API keys:

```env
PROMPTGUARD_API_KEY_ROLES=pk_prod_abc123:admin,pk_prod_def456:analyst,pk_ci_pipeline_789:viewer
```

| Role | Scan/Guard/Audit | Overrides/Policies | Webhooks |
|------|-----------------|-------------------|----------|
| viewer | ✅ | ❌ | ❌ |
| analyst | ✅ | ✅ | ❌ |
| admin | ✅ | ✅ | ✅ |

### Multi-Tenancy

Assign API keys to tenants for isolated audit trails:

```env
PROMPTGUARD_API_KEY_TENANTS=pk_prod_abc123:acme-corp,pk_prod_def456:acme-corp,pk_ci_pipeline_789:beta-inc
```

- Scan results include `tenant_id`
- Audit trail is filtered per-tenant (tenant A cannot see tenant B's events)
- Webhook payloads include `tenant_id` for routing

### Using API Keys

Pass the key as a Bearer token in the `Authorization` header:

```http
Authorization: Bearer pk_prod_abc123
```

### Error Responses

| Status | Meaning |
|--------|---------|
| `401` | Missing Authorization header |
| `403` | Invalid API key or insufficient role |

### Best Practices

- Use separate API keys per service/environment (production, staging, CI)
- Rotate keys periodically
- Never embed keys in client-side code
- Use environment variables or secret managers (AWS Secrets Manager, Vault)

---

## Guard Gateway

**`POST /v1/guard`** — The primary integration point. Call this before your AI agent executes any action.

### Request

```json
{
  "action": "execute_command",
  "content": "rm -rf /tmp/old-cache",
  "channel": "tool_call",
  "source": "deployment-agent",
  "metadata": {
    "arguments": {"command": "rm -rf /tmp/old-cache"},
    "user_id": "user-123",
    "session_id": "sess-abc"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | What the AI wants to do |
| `content` | string | Yes | The content/command to check |
| `channel` | enum | No | `prompt`, `output`, `file`, `tool_call` (default: `prompt`) |
| `source` | string | No | Identifier of the calling system |
| `metadata` | object | No | Additional context (passed through to audit) |

### Response

```json
{
  "permitted": false,
  "decision": "DENY",
  "risk_score": 55,
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "summary": "DENY with risk score 55; detected dangerous_tool_call.",
  "findings_count": 1,
  "findings": [
    {
      "rule_id": "PG-TOOL-001",
      "name": "Destructive filesystem command",
      "category": "dangerous_tool_call",
      "severity": 55,
      "decision": "DENY",
      "evidence": "rm -rf...",
      "explanation": "The tool call contains a destructive filesystem operation."
    }
  ],
  "ai_enhanced": false,
  "action": "execute_command",
  "source": "deployment-agent",
  "timestamp": "2024-01-15T10:30:00.000000+00:00"
}
```

### Integration Logic

```
IF response.permitted == true:
    execute the action
ELSE:
    block the action
    log response.summary for debugging
    IF response.decision == "HUMAN_REVIEW":
        queue for manual approval
```

---

## Content Scanning

**`POST /scan`** — Scan prompt, model output, or file content.

### Request

```json
{
  "channel": "prompt",
  "content": "Summarize this quarterly report for the executive team."
}
```

| Channel | Use Case |
|---------|----------|
| `prompt` | User input before sending to LLM |
| `output` | Model response before showing to user |
| `file` | Uploaded document content |

### Response

```json
{
  "event_id": "uuid",
  "timestamp": "2024-01-15T10:30:00+00:00",
  "channel": "prompt",
  "decision": "ALLOW",
  "risk_score": 0,
  "summary": "No policy, injection, secret, or dangerous tool-call signals were detected.",
  "findings": [],
  "masked_content": "...",
  "content_sha256": "abc123...",
  "ai_enhanced": false
}
```

---

## Tool Call Scanning

**`POST /scan-tool`** — Scan a tool/function call before execution.

### Request

```json
{
  "tool_name": "shell",
  "arguments": {
    "command": "ls -la /home/user/documents"
  }
}
```

### When to Use

Call this endpoint when your AI agent wants to:

- Execute shell commands
- Access the filesystem
- Make network requests
- Install packages
- Modify system configuration
- Access databases

---

## Batch Scanning

**`POST /v1/batch`** — Scan multiple items in one request. Ideal for CI/CD pipelines.

### Request

```json
{
  "items": [
    {"channel": "prompt", "content": "First item to scan."},
    {"channel": "prompt", "content": "Second item to scan."},
    {"channel": "output", "content": "Model output to verify."}
  ]
}
```

### Response

```json
{
  "overall_decision": "DENY",
  "total": 3,
  "denied": 1,
  "results": [
    {"decision": "ALLOW", "risk_score": 0, "event_id": "...", "summary": "...", "findings_count": 0},
    {"decision": "DENY", "risk_score": 80, "event_id": "...", "summary": "...", "findings_count": 2},
    {"decision": "ALLOW", "risk_score": 0, "event_id": "...", "summary": "...", "findings_count": 0}
  ]
}
```

**Pipeline logic**: If `overall_decision` is `DENY`, fail the pipeline step.

---

## Webhook Alerts

Push real-time security alerts to your SIEM, Slack, PagerDuty, or any HTTP endpoint.

### Register a Webhook

**`POST /v1/webhooks`**

```json
{
  "url": "https://your-siem.com/api/v1/alerts",
  "events": ["DENY", "HUMAN_REVIEW"]
}
```

### Webhook Payload

When a matching event occurs, PromptGuard POSTs the full scan result to your URL:

```json
{
  "event_id": "uuid",
  "timestamp": "2024-01-15T10:30:00+00:00",
  "channel": "prompt",
  "decision": "DENY",
  "risk_score": 80,
  "summary": "DENY with risk score 80; detected prompt_injection.",
  "findings": [...],
  "source": "chatbot-agent",
  "action": "process_user_input"
}
```

### Manage Webhooks

```bash
# List
GET /v1/webhooks

# Delete
DELETE /v1/webhooks/{webhook_id}
```

### Environment-Based Webhooks

Configure default webhooks via environment variable (no API call needed):

```env
PROMPTGUARD_WEBHOOK_URLS=https://siem.company.com/hook,https://hooks.slack.com/services/xxx
PROMPTGUARD_WEBHOOK_EVENTS=DENY,HUMAN_REVIEW
```

---

## Decision Overrides

Security teams can override previous decisions with a full audit trail.

**`POST /v1/override`**

```json
{
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "new_decision": "ALLOW",
  "reason": "False positive confirmed by security team after manual review.",
  "overridden_by": "admin@company.com"
}
```

### List Overrides

**`GET /v1/overrides?limit=50`**

---

## Human Approval Queue

When a scan returns `HUMAN_REVIEW`, the event is automatically queued for manual approval.

### View Pending Items

**`GET /v1/queue`**

```json
{
  "items": [
    {
      "queue_id": "event-uuid",
      "channel": "output",
      "risk_score": 35,
      "summary": "HUMAN_REVIEW with risk score 35; detected secret_leakage.",
      "status": "pending",
      "queued_at": "2024-01-15T10:30:00+00:00",
      "expires_at": "2024-01-15T11:30:00+00:00"
    }
  ],
  "pending_count": 1
}
```

Use `?status=all` to include resolved items.

### Approve or Reject

**`POST /v1/queue/{queue_id}/resolve`**

```json
{
  "resolution": "approve",
  "resolved_by": "analyst@company.com"
}
```

Response:

```json
{
  "queue_id": "event-uuid",
  "status": "approved",
  "resolved_at": "2024-01-15T10:35:00+00:00",
  "resolved_by": "analyst@company.com"
}
```

### Timeout Auto-Deny

Items not resolved within the timeout (default: 1 hour) are automatically denied by the system. Configure via:

```env
PROMPTGUARD_APPROVAL_TIMEOUT=3600
```

---

## Policy Management

Manage detection rules at runtime — enable/disable rules, adjust severity, or create custom rules.

### List All Policies

**`GET /v1/policies`**

Optional filter: `GET /v1/policies?category=prompt_injection`

### Enable/Disable a Rule

**`PATCH /v1/policies/PG-INJ-001`**

```json
{"enabled": false}
```

This immediately stops the rule from triggering in scans.

### Adjust Severity

**`PATCH /v1/policies/PG-SEC-003`**

```json
{"severity": 50, "decision": "DENY"}
```

### Create a Custom Rule

**`POST /v1/policies`**

```json
{
  "rule_id": "PG-CUSTOM-001",
  "name": "Internal API endpoint detection",
  "category": "policy_violation",
  "severity": 40,
  "decision": "DENY",
  "explanation": "Detected reference to internal API endpoint that should not be exposed.",
  "pattern": "api\\.internal\\.company\\.com",
  "enabled": true
}
```

### Delete a Custom Rule

**`DELETE /v1/policies/PG-CUSTOM-001`**

Note: Built-in rules cannot be deleted, only disabled.

---

## SARIF Export

Export findings in SARIF 2.1.0 format for GitHub Advanced Security integration.

**`GET /v1/export/sarif?limit=100`**

### GitHub Actions Integration

```yaml
- name: Run PromptGuard scan
  run: |
    curl -s http://promptguard:8000/v1/export/sarif \
      -H "Authorization: Bearer ${{ secrets.PROMPTGUARD_KEY }}" \
      -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Metrics & Monitoring

**`GET /v1/stats`**

```json
{
  "total_scans": 15420,
  "denied": 892,
  "allowed": 12100,
  "review": 430,
  "logged": 1998,
  "overrides": 12,
  "threat_rate": 8.6,
  "ai_enabled": true
}
```

### Grafana/Prometheus Integration

Poll `/v1/stats` at regular intervals and feed into your monitoring stack:

```python
import requests
import time

while True:
    stats = requests.get("http://promptguard:8000/v1/stats",
                         headers={"Authorization": "Bearer pk_monitoring"}).json()
    # Push to Prometheus pushgateway or StatsD
    push_metrics(stats)
    time.sleep(30)
```

### Health Check

**`GET /health`**

```json
{
  "status": "ok",
  "service": "promptguard-ai",
  "version": "1.0.0",
  "ai_enabled": true,
  "auth_enabled": true,
  "webhooks_configured": 3
}
```

Use this for load balancer health checks and uptime monitoring.

---

## Integration Patterns

### Pattern 1: AI Agent Runtime Guard

```text
User Input → Agent → PromptGuard /v1/guard → Execute (if permitted)
```

```python
def agent_execute(action: str, content: str):
    response = requests.post(f"{GUARD_URL}/v1/guard", json={
        "action": action,
        "content": content,
        "channel": "tool_call",
        "source": "my-agent",
    }, headers={"Authorization": f"Bearer {API_KEY}"})

    result = response.json()
    if not result["permitted"]:
        raise SecurityError(f"Blocked: {result['summary']}")

    return perform_action(action, content)
```

### Pattern 2: LLM Proxy (Input + Output Scanning)

```text
User → Scan Input → LLM → Scan Output → User
```

```python
def safe_llm_call(user_prompt: str) -> str:
    # Scan input
    input_check = requests.post(f"{GUARD_URL}/scan", json={
        "channel": "prompt", "content": user_prompt
    }).json()
    if input_check["decision"] == "DENY":
        return "I cannot process this request."

    # Call LLM
    llm_response = call_llm(user_prompt)

    # Scan output
    output_check = requests.post(f"{GUARD_URL}/scan", json={
        "channel": "output", "content": llm_response
    }).json()
    if output_check["decision"] == "DENY":
        return output_check["masked_content"]  # Return masked version

    return llm_response
```

### Pattern 3: CI/CD Pipeline Gate

```text
Code Change → Batch Scan Prompts/Configs → Pass/Fail Pipeline
```

```yaml
# GitHub Actions
- name: Security scan with PromptGuard
  run: |
    RESULT=$(curl -s -X POST http://promptguard:8000/v1/batch \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${{ secrets.PROMPTGUARD_KEY }}" \
      -d @scan-items.json)

    DENIED=$(echo $RESULT | jq .denied)
    if [ "$DENIED" -gt "0" ]; then
      echo "::error::PromptGuard blocked $DENIED items"
      exit 1
    fi
```

### Pattern 4: SIEM Integration

```text
PromptGuard → Webhook + Native Connectors → SIEM (Splunk/Datadog/CloudWatch/Elastic)
```

Two options:

**Option A: Webhooks** — Register webhooks for `DENY` and `HUMAN_REVIEW` events. PromptGuard pushes alerts in real-time.

**Option B: Native Connectors** — Configure via env vars. Events are dispatched automatically:

```env
# Splunk
PROMPTGUARD_SPLUNK_HEC_URL=https://splunk:8088/services/collector/event
PROMPTGUARD_SPLUNK_HEC_TOKEN=your-hec-token

# AWS CloudWatch
PROMPTGUARD_CLOUDWATCH_LOG_GROUP=/promptguard/events

# Datadog
PROMPTGUARD_DATADOG_API_KEY=your-dd-key
PROMPTGUARD_DATADOG_SITE=datadoghq.com

# Elasticsearch
PROMPTGUARD_ELASTIC_URL=https://es:9200
PROMPTGUARD_ELASTIC_INDEX=promptguard-events
```

Connectors auto-enable when credentials are present. Check `/health` to see which are active.

### Pattern 5: Human-in-the-Loop

```text
Agent → /v1/guard → HUMAN_REVIEW → Queue → Analyst Approves → /v1/override → Execute
```

```python
result = guard_check(action, content)
if result["decision"] == "HUMAN_REVIEW":
    queue_for_review(result["event_id"], action, content)
    # Later, after human approval:
    requests.post(f"{GUARD_URL}/v1/override", json={
        "event_id": result["event_id"],
        "new_decision": "ALLOW",
        "reason": "Approved by analyst after review.",
        "overridden_by": "analyst@company.com"
    })
```

---

## SDK Examples

### Python

```python
import requests

class PromptGuardClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def guard(self, action: str, content: str, channel: str = "prompt", source: str = "sdk") -> dict:
        r = requests.post(f"{self.base_url}/v1/guard", json={
            "action": action, "content": content,
            "channel": channel, "source": source,
        }, headers=self.headers)
        r.raise_for_status()
        return r.json()

    def is_permitted(self, action: str, content: str, **kwargs) -> bool:
        return self.guard(action, content, **kwargs)["permitted"]

    def scan(self, content: str, channel: str = "prompt") -> dict:
        r = requests.post(f"{self.base_url}/scan", json={
            "channel": channel, "content": content,
        }, headers=self.headers)
        r.raise_for_status()
        return r.json()

# Usage
guard = PromptGuardClient("http://localhost:8000", "pk_prod_abc123")

if guard.is_permitted("execute_command", "ls -la /tmp"):
    execute("ls -la /tmp")
else:
    print("Action blocked by PromptGuard")
```

### JavaScript / TypeScript

```typescript
class PromptGuardClient {
  constructor(private baseUrl: string, private apiKey: string) {}

  private get headers() {
    return {
      "Authorization": `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
    };
  }

  async guard(action: string, content: string, channel = "prompt", source = "sdk") {
    const res = await fetch(`${this.baseUrl}/v1/guard`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ action, content, channel, source }),
    });
    if (!res.ok) throw new Error(`PromptGuard error: ${res.status}`);
    return res.json();
  }

  async isPermitted(action: string, content: string): Promise<boolean> {
    const result = await this.guard(action, content);
    return result.permitted;
  }
}

// Usage
const guard = new PromptGuardClient("http://localhost:8000", "pk_prod_abc123");

if (await guard.isPermitted("send_email", emailBody)) {
  sendEmail(emailBody);
} else {
  throw new Error("Blocked by PromptGuard");
}
```

### Go

```go
package promptguard

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type Client struct {
    BaseURL string
    APIKey  string
}

type GuardResponse struct {
    Permitted bool   `json:"permitted"`
    Decision  string `json:"decision"`
    RiskScore int    `json:"risk_score"`
    Summary   string `json:"summary"`
    EventID   string `json:"event_id"`
}

func (c *Client) Guard(action, content, channel string) (*GuardResponse, error) {
    body, _ := json.Marshal(map[string]string{
        "action": action, "content": content, "channel": channel, "source": "go-sdk",
    })
    req, _ := http.NewRequest("POST", c.BaseURL+"/v1/guard", bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+c.APIKey)
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("promptguard: status %d", resp.StatusCode)
    }

    var result GuardResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| `200` | Success | Process the response |
| `401` | Unauthorized | Check API key configuration |
| `403` | Forbidden | API key is invalid |
| `404` | Not found | Check endpoint URL |
| `409` | Conflict | Resource already exists (e.g., duplicate policy) |
| `422` | Validation error | Check request body format |
| `429` | Rate limited | Back off and retry after `Retry-After` seconds |
| `500` | Server error | Retry with exponential backoff |

### Retry Strategy

```python
import time
import requests

def guard_with_retry(action, content, max_retries=3):
    for attempt in range(max_retries):
        try:
            r = requests.post(f"{GUARD_URL}/v1/guard", json={
                "action": action, "content": content,
                "channel": "tool_call", "source": "my-agent",
            }, headers=HEADERS, timeout=5)

            if r.status_code == 429:
                retry_after = int(r.headers.get("Retry-After", 60))
                time.sleep(retry_after)
                continue

            r.raise_for_status()
            return r.json()

        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                # Fail-safe: deny on timeout
                return {"permitted": False, "decision": "DENY", "summary": "PromptGuard timeout"}
            time.sleep(2 ** attempt)

    return {"permitted": False, "decision": "DENY", "summary": "PromptGuard unavailable"}
```

### Fail-Safe Behavior

When PromptGuard is unreachable, your system should **default to DENY** for security-critical actions:

```python
try:
    result = guard_check(action, content)
except Exception:
    result = {"permitted": False, "decision": "DENY", "summary": "Guard unavailable — fail-safe deny"}
```

---

## Rate Limiting

PromptGuard enforces per-client rate limits (configurable on the server).

**Default**: 60 requests per 60 seconds per client.

### Response Headers

Every response includes:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705312260
```

### 429 Response

```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded. Max 60 requests per 60s.",
  "retry_after": 60
}
```

### Tips

- Use batch scanning (`/v1/batch`) to reduce request count
- Use separate API keys per service for independent rate limits
- Contact your PromptGuard admin to increase limits for high-throughput services

---

## Deployment

### Docker Compose (Development)

```bash
cp .env.example .env
# Edit .env with your GEMINI_API_KEY and API keys
docker compose up --build
```

### Production Checklist

- [ ] Set `PROMPTGUARD_API_AUTH_ENABLED=true`
- [ ] Generate strong API keys and set `PROMPTGUARD_API_KEYS`
- [ ] Configure `PROMPTGUARD_CORS_ORIGINS` to your frontend domain only
- [ ] Set `GEMINI_API_KEY` for AI-enhanced detection
- [ ] Configure webhook URLs for SIEM integration
- [ ] Set appropriate rate limits for your traffic
- [ ] Place behind a reverse proxy (nginx/ALB) with TLS
- [ ] Set up health check monitoring on `/health`
- [ ] Configure log aggregation for structured logs

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMPTGUARD_PORT` | `8000` | API port |
| `PROMPTGUARD_HOST` | `0.0.0.0` | Bind address |
| `PROMPTGUARD_CORS_ORIGINS` | `localhost:5173,localhost:3000` | CORS origins |
| `PROMPTGUARD_API_AUTH_ENABLED` | `false` | Enable API key auth |
| `PROMPTGUARD_API_KEYS` | *(empty)* | Comma-separated API keys |
| `PROMPTGUARD_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `PROMPTGUARD_RATE_LIMIT_REQUESTS` | `60` | Requests per window |
| `PROMPTGUARD_RATE_LIMIT_WINDOW` | `60` | Window in seconds |
| `PROMPTGUARD_AUDIT_MAX_EVENTS` | `500` | Max audit events in memory |
| `PROMPTGUARD_MAX_CONTENT_LENGTH` | `100000` | Max content length |
| `PROMPTGUARD_DATABASE_PATH` | `./data/promptguard.db` | SQLite database path |
| `PROMPTGUARD_WEBHOOK_URLS` | *(empty)* | Default webhook URLs |
| `PROMPTGUARD_WEBHOOK_EVENTS` | `DENY,HUMAN_REVIEW` | Webhook trigger events |
| `GEMINI_API_KEY` | *(empty)* | Gemini API key |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model |
| `GEMINI_ENABLED` | `true` | Enable AI analysis |

---

## API Endpoint Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health and status |
| POST | `/scan` | Scan content (prompt/output/file) |
| POST | `/scan-tool` | Scan tool call |
| GET | `/audit` | Audit trail events |
| POST | `/v1/guard` | **Gateway** — check before executing |
| POST | `/v1/batch` | Batch scan multiple items |
| POST | `/v1/override` | Override a decision |
| GET | `/v1/overrides` | List overrides |
| GET | `/v1/queue` | Approval queue (pending/all) |
| POST | `/v1/queue/{id}/resolve` | Approve or reject queued item |
| POST | `/v1/webhooks` | Register webhook |
| GET | `/v1/webhooks` | List webhooks |
| DELETE | `/v1/webhooks/{id}` | Remove webhook |
| GET | `/v1/stats` | Security metrics |
| GET | `/v1/export/sarif` | SARIF 2.1.0 export |
| GET | `/v1/policies` | List policy rules |
| GET | `/v1/policies/{id}` | Get policy detail |
| PATCH | `/v1/policies/{id}` | Update policy |
| POST | `/v1/policies` | Create custom policy |
| DELETE | `/v1/policies/{id}` | Delete custom policy |

---

## Support

- GitHub Issues: [github.com/Murzuqisah/PromptGuard-AI/issues](https://github.com/Murzuqisah/PromptGuard-AI/issues)
- API Docs (OpenAPI): `http://your-host:8000/docs`
- Redoc: `http://your-host:8000/redoc`
