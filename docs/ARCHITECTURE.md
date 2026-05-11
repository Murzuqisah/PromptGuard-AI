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
│  │ API Layer: /scan, /scan-tool, /audit, /health        │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Hybrid Detection Engine                               │   │
│  │  ├─ Pass 1: Regex Rules (35 patterns, <1ms)           │   │
│  │  │   ├─ Prompt Injection Rules (7)                    │   │
│  │  │   ├─ Policy Violation Rules (6)                    │   │
│  │  │   ├─ Secret Leakage Rules (12)                     │   │
│  │  │   └─ Tool Governance Rules (10)                    │   │
│  │  ├─ Pass 2: Gemini AI Analysis (~500ms)               │   │
│  │  │   └─ Semantic threat detection (skipped if DENY)   │   │
│  │  └─ Finding merge & deduplication                     │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Policy Decision Engine                                │   │
│  │  Risk scoring → ALLOW / LOG / HUMAN_REVIEW / DENY     │   │
│  └──────────────────────┬───────────────────────────────┘   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │ Audit Trail (in-memory, capped at AUDIT_MAX_EVENTS)   │   │
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

- **Tech**: Python, FastAPI, Pydantic, python-dotenv
- **Config**: all settings loaded from `.env` at project root via `python-dotenv`
- **Endpoints**:
  - `GET /health` — service health check
  - `POST /scan` — scan prompt, output, or file content
  - `POST /scan-tool` — scan tool call with arguments
  - `GET /audit` — retrieve audit trail events

### Detection Engine

**Hybrid approach**: regex + AI working together.

| Pass | Engine | Latency | Purpose |
|------|--------|---------|---------|
| 1 | Regex (35 rules) | <1ms | Fast deterministic blocking of known patterns |
| 2 | Gemini AI | ~500ms | Semantic analysis of novel/subtle threats |

AI is skipped when:
- `GEMINI_API_KEY` is not set
- `GEMINI_ENABLED` is `false`
- Regex already produced a `DENY` decision (no need for further analysis)

35 deterministic regex-based rules across 4 categories:

| Category | Count | Covers |
|----------|-------|--------|
| Prompt Injection | 7 | Instruction override, credential exfiltration, role manipulation, prompt leaking, encoding evasion, indirect injection, multi-language bypass |
| Policy Violation | 6 | Social engineering, malware generation, SQL injection, XSS, SSRF, privilege escalation |
| Secret Leakage | 12 | AWS keys, JWTs, GitHub/Slack/Stripe/Google tokens, private keys, bearer tokens, DB strings, webhooks |
| Tool Governance | 10 | Destructive commands, reverse shells, Docker escape, network exfil, memory dumps, firewall disable, cron injection, env harvesting |

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

## Configuration

All environment variables are defined in a single `.env` file at the project root. Both the backend (via `python-dotenv`) and frontend (via Vite's `envDir`) read from this file.

See `.env.example` for the full list of variables.

## Gemini AI Integration

The AI layer uses Google's Gemini API (`google-genai` SDK). It:

1. Receives the content and channel type
2. Analyzes for threats across all 4 categories using a structured system prompt
3. Returns JSON with threat assessment, risk score, and findings
4. Findings are merged with regex results (deduplicated by category + name)
5. AI severity is capped at 55 to ensure it escalates to `HUMAN_REVIEW` but doesn't unilaterally `DENY` without regex confirmation

To enable: set `GEMINI_API_KEY` in your `.env` file. Get a key from [Google AI Studio](https://aistudio.google.com/apikey).

## Data Handling

- The audit log stores: event ID, timestamp, channel, decision, risk score, summary, finding count, and content SHA-256 hash.
- Raw content is never persisted in the audit trail.
- Secrets are masked before being returned in API responses.

## Future Integration Points

- LLM provider proxying: route requests through PromptGuard after `ALLOW` decisions.
- SIEM webhooks: forward audit events to Splunk, Datadog, or CloudWatch.
- SARIF export: publish findings to GitHub code scanning.
- Policy persistence: store rule configurations in a database with tenant isolation.
- Human approval queues: hold `HUMAN_REVIEW` decisions until manual approval.
