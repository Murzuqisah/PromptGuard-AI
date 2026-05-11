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

## Milestone 4: Production Readiness ✅

- Environment-based configuration (single `.env` at project root).
- Docker multi-stage build for frontend (nginx).
- SPA routing support in production.
- Dev script to run both services concurrently.
- No hardcoded secrets or URLs.

## Milestone 5: AI Integration ✅

- Google Gemini AI as a second-pass semantic analysis layer.
- Hybrid detection: regex (fast, deterministic) + AI (deep, semantic).
- AI skipped when regex already produces DENY (saves latency/cost).
- Findings merged and deduplicated between regex and AI.
- AI severity capped at 55 to prevent unilateral DENY without regex confirmation.
- Graceful degradation: works without API key in regex-only mode.
- Frontend shows AI status in sidebar and "AI Enhanced" badge on results.

## Milestone 6: Demo & Submission

- Public GitHub repository.
- Deployed dashboard URL.
- Two-minute demo video showing all four scenarios.
- Slide deck: problem, architecture, demo, business value, roadmap.
- Cover image showing the dashboard decision packet.

## Judging Narrative

- **Technology integration**: API gateway, 35-rule scanner engine, Gemini AI semantic analysis, React dashboard, audit trail, Docker, CI security scanning.
- **Business value**: enterprises need AI governance before broad LLM and agent rollout.
- **Originality**: focuses on the overlooked control plane between users, models, and tools. Hybrid regex+AI approach gives best of both worlds.
- **Presentation**: live attack scenarios produce memorable allow/deny outcomes. AI badge shows when semantic analysis contributed.
- **Completeness**: environment config, documentation, tests, Docker, CI, and graceful degradation all in place.
