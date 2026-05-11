# Hackathon Execution Plan

## Positioning

PromptGuard AI is an AI security gateway built with an AI-assisted development workflow. The product story is AI governance; the engineering story is secure agentic SDLC.

## Milestone 1: Foundation ✅

- Scaffold backend, frontend, docs, Docker, and CI.
- Implement deterministic prompt, output, and tool-call scanning.
- Add unit tests for the four demo scenarios.

## Milestone 2: Expanded Detection ✅

- 35 detection rules across 4 categories.
- Prompt injection: instruction override, credential exfiltration, role manipulation, prompt leaking, encoding evasion, indirect injection, multi-language bypass.
- Policy violations: social engineering, malware generation, SQL injection, XSS, SSRF, privilege escalation.
- Secret leakage: AWS, GitHub, Slack, Stripe, Google, JWTs, private keys, bearer tokens, DB strings, webhooks.
- Tool governance: destructive commands, reverse shells, Docker escape, network exfil, memory dumps, firewall disable, cron injection, env harvesting.

## Milestone 3: Modern Dashboard ✅

- React 19 + TypeScript + Vite + Tailwind CSS v4.
- Three routed pages: Scanner, Audit Trail, Policy Management.
- Dark theme with shadcn-style components.
- Local fallback scanner when API is offline.
- Category filtering, severity badges, enable/disable toggles on policy page.

## Milestone 4: AI Integration ✅

- Google Gemini AI as a second-pass semantic analysis layer.
- Hybrid detection: regex (fast, deterministic) + AI (deep, semantic).
- AI skipped when regex already produces DENY (saves latency/cost).
- Findings merged and deduplicated between regex and AI.
- AI severity capped at 55 to prevent unilateral DENY without regex confirmation.
- Graceful degradation: works without API key in regex-only mode.
- Frontend shows AI status in sidebar and "AI Enhanced" badge on results.

## Milestone 5: Enterprise API ✅

- Guard gateway (`/v1/guard`) — primary integration point for AI agents.
- Batch scanning (`/v1/batch`) — CI/CD pipeline integration.
- Webhook alerts — real-time notifications to any HTTP endpoint.
- Decision overrides — security team manual approval with audit trail.
- Security metrics (`/v1/stats`) — dashboard-ready statistics.
- API key authentication with Bearer tokens.

## Milestone 6: Production Hardening ✅

- Rate limiting: sliding window per-client with configurable thresholds.
- Policy persistence: SQLite-backed rule management with CRUD API.
- SARIF 2.1.0 export for GitHub Advanced Security.
- OpenAPI documentation with tags, examples, and static spec.
- Deployment guides with Terraform templates (AWS ECS, GCP Cloud Run).
- Structured JSON logging with per-request correlation IDs.
- Input normalization: unicode, homoglyphs, base64, spacing tricks.

## Milestone 7: Enterprise Features ✅ (partial)

- RBAC: admin, analyst, viewer roles with hierarchical permissions.
- Multi-tenant: isolated audit trails, tenant-scoped scan results.
- SIEM connectors: Splunk HEC, AWS CloudWatch, Datadog, Elasticsearch/OpenSearch.

## Remaining

- Human approval queues for HUMAN_REVIEW decisions.
- Python and npm SDK packages.
- Real-time WebSocket event streaming.

## Judging Narrative

- **Technology integration**: API gateway, 35-rule scanner engine, Gemini AI semantic analysis, React dashboard, SIEM connectors, RBAC, multi-tenant, SQLite persistence, Terraform IaC, Docker, CI.
- **Business value**: enterprises need AI governance before broad LLM and agent rollout. PromptGuard provides the missing control plane.
- **Originality**: focuses on the overlooked security layer between users, models, and tools. Hybrid regex+AI approach gives best of both worlds.
- **Presentation**: live attack scenarios produce memorable allow/deny outcomes. AI badge shows when semantic analysis contributed. SIEM integration demonstrates enterprise readiness.
- **Completeness**: 46 tests, structured logging, rate limiting, RBAC, multi-tenant, SARIF export, OpenAPI spec, deployment guides, and comprehensive documentation.
