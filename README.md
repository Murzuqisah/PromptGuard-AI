# PromptGuard AI

PromptGuard AI is an enterprise agent firewall for LLM applications. It sits between users, models, and agent tools, then scores prompts, model outputs, uploaded text, and tool calls before allowing the action to continue.

Built as a hackathon-ready MVP for the Agent Security & AI Governance track: fast to demo, easy to run locally, and designed to integrate with any AI system as a security gateway.

## What It Does

- **Gateway API** — any AI agent, CI/CD pipeline, or LLM runtime can call `/v1/guard` before executing actions. Returns `permitted: true/false` in real-time.
- **Hybrid detection** — 35 regex rules (<1ms) + Gemini AI semantic analysis (~500ms) with finding merge and deduplication.
- **SIEM integration** — native connectors for Splunk HEC, AWS CloudWatch, Datadog, and Elasticsearch/OpenSearch.
- **RBAC** — role-based access control with admin, analyst, and viewer roles.
- **Multi-tenant** — isolated audit trails and scan results per tenant.
- **Policy persistence** — SQLite-backed rule management with enable/disable and custom rules via API.
- **Webhook alerts** — real-time notifications to any HTTP endpoint on DENY/REVIEW events.
- **Decision overrides** — security teams can override decisions via API with full audit trail.
- **Batch scanning** — scan multiple items in one request for pipeline integrations.
- **SARIF export** — export findings in SARIF 2.1.0 format for GitHub Advanced Security.
- **Structured logging** — JSON logs with per-request correlation IDs for distributed tracing.
- **Rate limiting** — sliding window per-client rate limiting with configurable thresholds.

## Quick Start

```bash
cp .env.example .env
# Add GEMINI_API_KEY to .env (optional, enables AI analysis)
./scripts/dev.sh
```

Backend: `http://localhost:8000` · Frontend: `http://localhost:5173`

## All API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health, AI status, SIEM connectors |
| POST | `/scan` | Scan prompt/output/file content |
| POST | `/scan-tool` | Scan tool call with arguments |
| GET | `/audit` | Retrieve audit trail (tenant-scoped) |
| POST | `/v1/guard` | **Gateway** — check before executing AI actions |
| POST | `/v1/batch` | Batch scan multiple items |
| POST | `/v1/override` | Override a previous decision |
| GET | `/v1/overrides` | List decision overrides |
| POST | `/v1/webhooks` | Register alert webhook |
| GET | `/v1/webhooks` | List registered webhooks |
| DELETE | `/v1/webhooks/{id}` | Remove a webhook |
| GET | `/v1/stats` | Security metrics for dashboards |
| GET | `/v1/export/sarif` | SARIF 2.1.0 export |
| GET | `/v1/policies` | List policy rules |
| GET | `/v1/policies/{id}` | Get policy detail |
| PATCH | `/v1/policies/{id}` | Update policy (enable/disable) |
| POST | `/v1/policies` | Create custom policy |
| DELETE | `/v1/policies/{id}` | Delete custom policy |

## RBAC

| Role | Scan/Guard/Audit | Overrides/Policies | Webhooks |
|------|-----------------|-------------------|----------|
| viewer | ✅ | ❌ | ❌ |
| analyst | ✅ | ✅ | ❌ |
| admin | ✅ | ✅ | ✅ |

```env
PROMPTGUARD_API_AUTH_ENABLED=true
PROMPTGUARD_API_KEYS=key-admin,key-analyst,key-viewer
PROMPTGUARD_API_KEY_ROLES=key-admin:admin,key-analyst:analyst,key-viewer:viewer
PROMPTGUARD_API_KEY_TENANTS=key-admin:acme-corp,key-analyst:acme-corp
```

## SIEM Connectors

Configure via environment variables — connectors auto-enable when credentials are present.

| Platform | Env Vars |
|----------|----------|
| Splunk HEC | `PROMPTGUARD_SPLUNK_HEC_URL`, `PROMPTGUARD_SPLUNK_HEC_TOKEN` |
| AWS CloudWatch | `PROMPTGUARD_CLOUDWATCH_LOG_GROUP`, `_LOG_STREAM`, `_REGION` |
| Datadog | `PROMPTGUARD_DATADOG_API_KEY`, `PROMPTGUARD_DATADOG_SITE` |
| Elastic/OpenSearch | `PROMPTGUARD_ELASTIC_URL`, `_INDEX`, `_API_KEY` |

## Environment Variables

All configuration lives in a single `.env` file at the project root. See `.env.example`.

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMPTGUARD_PORT` | `8000` | Backend API port |
| `PROMPTGUARD_HOST` | `0.0.0.0` | Backend bind address |
| `PROMPTGUARD_CORS_ORIGINS` | `localhost:5173,localhost:3000` | Allowed CORS origins |
| `PROMPTGUARD_LOG_LEVEL` | `info` | Logging level |
| `PROMPTGUARD_AUDIT_MAX_EVENTS` | `500` | Max audit events in memory |
| `PROMPTGUARD_MAX_CONTENT_LENGTH` | `100000` | Max scan content length |
| `PROMPTGUARD_API_AUTH_ENABLED` | `false` | Enable API key auth |
| `PROMPTGUARD_API_KEYS` | *(empty)* | Comma-separated API keys |
| `PROMPTGUARD_API_KEY_ROLES` | *(empty)* | Key-to-role mapping |
| `PROMPTGUARD_API_KEY_TENANTS` | *(empty)* | Key-to-tenant mapping |
| `PROMPTGUARD_DATABASE_PATH` | `./data/promptguard.db` | SQLite database path |
| `PROMPTGUARD_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `PROMPTGUARD_RATE_LIMIT_REQUESTS` | `60` | Requests per window |
| `PROMPTGUARD_RATE_LIMIT_WINDOW` | `60` | Window in seconds |
| `GEMINI_API_KEY` | *(empty)* | Google Gemini API key |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model |
| `GEMINI_ENABLED` | `true` | Enable AI analysis |
| `PROMPTGUARD_WEBHOOK_URLS` | *(empty)* | Default webhook URLs |
| `PROMPTGUARD_WEBHOOK_EVENTS` | `DENY,HUMAN_REVIEW` | Webhook trigger events |
| `PROMPTGUARD_SPLUNK_HEC_URL` | *(empty)* | Splunk HEC endpoint |
| `PROMPTGUARD_SPLUNK_HEC_TOKEN` | *(empty)* | Splunk HEC token |
| `PROMPTGUARD_CLOUDWATCH_LOG_GROUP` | *(empty)* | CloudWatch log group |
| `PROMPTGUARD_DATADOG_API_KEY` | *(empty)* | Datadog API key |
| `PROMPTGUARD_ELASTIC_URL` | *(empty)* | Elasticsearch URL |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Frontend API URL |
| `FRONTEND_PORT` | `5173` | Frontend dev port |

## Detection Rules

| Category | Rules | Actions |
|----------|-------|---------|
| Prompt Injection | 7 | DENY, HUMAN_REVIEW |
| Policy Violation | 6 | DENY |
| Secret Leakage | 12 | DENY, HUMAN_REVIEW, LOG |
| Tool Governance | 10 | DENY, HUMAN_REVIEW |
| AI Analysis | ∞ | DENY, HUMAN_REVIEW, LOG |
| **Total** | **35 + AI** | |

## Documentation

- [Enterprise Integration Guide](docs/INTEGRATION.md) — full API reference with SDK examples
- [Architecture](docs/ARCHITECTURE.md) — system design and decision model
- [Deployment Guide](docs/DEPLOYMENT.md) — AWS, GCP, and self-hosted with Terraform
- [OpenAPI Spec](docs/openapi.json) — machine-readable API schema
- Interactive docs: `http://localhost:8000/docs` (Swagger) / `http://localhost:8000/redoc`

## Development

```bash
cd backend && source .venv/bin/activate && pytest -v  # 46 tests
cd frontend && npm run build                           # Production build
```

## Docker

```bash
docker compose up --build
```

## Tech Stack

- **Backend**: Python, FastAPI, Pydantic, python-dotenv, Google Gemini AI, httpx, SQLite
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS v4, React Router, Lucide Icons
- **Infrastructure**: Docker, nginx, docker-compose, Terraform (AWS/GCP)

## Milestones

- ✅ M1: Core scanner, API, frontend, Docker, CI
- ✅ M2: 35 detection rules, React dashboard, input normalization
- ✅ M3: Gemini AI hybrid detection
- ✅ M4: Enterprise API (guard, batch, webhooks, overrides, stats)
- ✅ M5: Rate limiting, policy persistence, SARIF, OpenAPI, deployment guides, structured logging
- ✅ M6 (partial): RBAC, multi-tenant, SIEM connectors
- Next: human approval queues, SDK packages, WebSocket streaming
