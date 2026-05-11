# PromptGuard AI — Architecture

## Goal

PromptGuard AI provides a control point for enterprise LLM and agent workflows. Every user prompt, model output, file upload, and tool call is inspected before it is trusted.

## System Overview

```text
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React + Vite + Tailwind CSS)                     │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Scanner  │  │ Audit Trail  │  │ Policy Management    │  │
│  └──────────┘  └──────────────┘  └──────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (VITE_API_BASE_URL)
┌────────────────────────▼────────────────────────────────────┐
│  Backend (FastAPI)                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Middleware: CORS → Rate Limiter → Correlation ID      │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Auth: RBAC (admin/analyst/viewer) + Multi-tenant      │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ API Layer                                             │   │
│  │  /scan, /scan-tool, /audit, /health                   │   │
│  │  /v1/guard, /v1/batch, /v1/override, /v1/webhooks     │   │
│  │  /v1/stats, /v1/export/sarif, /v1/policies            │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Hybrid Detection Engine                               │   │
│  │  ├─ Input Normalization (unicode, homoglyphs, base64) │   │
│  │  ├─ Pass 1: Regex Rules (35 patterns, <1ms)           │   │
│  │  ├─ Pass 2: Gemini AI Analysis (~500ms)               │   │
│  │  │   └─ Skipped if regex already produced DENY        │   │
│  │  └─ Finding merge & deduplication                     │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Policy Decision Engine                                │   │
│  │  Risk scoring → ALLOW / LOG / HUMAN_REVIEW / DENY     │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Output Layer                                          │   │
│  │  ├─ Audit Trail (in-memory, tenant-scoped)            │   │
│  │  ├─ Webhook Delivery (HTTP endpoints)                 │   │
│  │  └─ SIEM Connectors (Splunk, CloudWatch, Datadog, ES) │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Persistence: SQLite (policy rules, enable/disable)    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Frontend

- **Tech**: React 19, TypeScript, Vite, Tailwind CSS v4, React Router, Lucide Icons
- **Pages**: Scanner (`/`), Audit Trail (`/audit`), Policy Management (`/policy`)
- **Fallback**: local browser-based scanner when API is unavailable
- **Build**: multi-stage Docker with nginx for production

### Backend

- **Tech**: Python, FastAPI, Pydantic, python-dotenv, httpx, SQLite
- **Config**: all settings loaded from `.env` at project root
- **Middleware stack**: CORS → Rate Limiter → Correlation ID
- **Auth**: RBAC with admin/analyst/viewer roles, multi-tenant isolation

### Detection Engine

**Multi-layer pipeline**:

| Layer | Component | Latency | Purpose |
|-------|-----------|---------|---------|
| 1 | Input Normalization | <1ms | Defeat obfuscation (unicode, homoglyphs, base64, spacing) |
| 2 | Regex Rules (35) | <1ms | Fast deterministic blocking of known patterns |
| 3 | Gemini AI | ~500ms | Semantic analysis of novel/subtle threats |
| 4 | Finding Merge | <1ms | Deduplicate regex + AI findings |

AI is skipped when:
- `GEMINI_API_KEY` is not set
- `GEMINI_ENABLED` is `false`
- Regex already produced a `DENY` decision

### Policy Persistence

- SQLite database at `PROMPTGUARD_DATABASE_PATH`
- Auto-seeds 35 built-in rules on first run
- Rules can be enabled/disabled via API
- Custom rules can be created/deleted
- Built-in rules are protected from deletion

### SIEM Connectors

| Connector | Protocol | Schema |
|-----------|----------|--------|
| Splunk HEC | HTTPS POST | `sourcetype: promptguard:scan` |
| AWS CloudWatch | PutLogEvents | JSON log events |
| Datadog | HTTPS POST | `ddsource: promptguard` with ddtags |
| Elastic/OpenSearch | HTTPS POST | ECS-compatible `@timestamp` fields |

Connectors auto-enable when their env vars are configured.

## Decision Model

Risk is additive and capped at 100. Explicit rule decisions override score-based thresholds.

```text
Score 0–19      → ALLOW
Score 20–54     → LOG
Score 55–79     → HUMAN_REVIEW
Score 80–100    → DENY

Any DENY rule   → DENY (regardless of score)
Any REVIEW rule → HUMAN_REVIEW (minimum)
```

## RBAC

| Role | Scan/Guard/Audit/Stats | Overrides/Policies | Webhooks |
|------|------------------------|-------------------|----------|
| viewer | ✅ | ❌ | ❌ |
| analyst | ✅ | ✅ | ❌ |
| admin | ✅ | ✅ | ✅ |

## Multi-Tenancy

- API keys map to tenant IDs via `PROMPTGUARD_API_KEY_TENANTS`
- All scan results include `tenant_id`
- Audit trail is filtered per-tenant (tenant A cannot see tenant B's events)
- Webhook payloads include `tenant_id` for downstream routing

## Data Handling

- Audit log stores: event ID, timestamp, tenant_id, channel, decision, risk score, summary, finding count, content SHA-256
- Raw content is never persisted in the audit trail
- Secrets are masked before being returned in API responses
- Structured JSON logs with correlation IDs for distributed tracing

## Configuration

All environment variables are defined in a single `.env` file at the project root. Both the backend (via `python-dotenv`) and frontend (via Vite's `envDir`) read from this file.

See `.env.example` for the full list of variables.
