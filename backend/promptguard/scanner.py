from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from hashlib import sha256
from re import Match
from typing import Any
from uuid import uuid4

from .config import AUDIT_MAX_EVENTS
from .database import get_disabled_rule_ids
from .gemini import analyze as gemini_analyze, is_available as gemini_available
from .normalizers import normalize
from .rules import Channel, Decision, PROMPT_RULES, SECRET_RULES, TOOL_RULES, Rule

AUDIT_EVENTS: list[dict[str, Any]] = []


def analyze_content(content: str, channel: Channel | str = Channel.PROMPT) -> dict[str, Any]:
    channel_value = Channel(channel)

    # Layer 1: Input normalization
    normalized = normalize(content)

    rules = [*SECRET_RULES]
    if channel_value in {Channel.PROMPT, Channel.FILE}:
        rules.extend(PROMPT_RULES)

    # Layer 2: Pattern matching (on both raw and normalized)
    matches = _find_matches(content, rules)
    if normalized != content:
        norm_matches = _find_matches(normalized, rules)
        matches = _merge_findings(matches, norm_matches)

    # Layer 3: Gemini AI semantic analysis
    ai_findings = _run_ai_if_needed(content, channel_value.value, matches)
    if ai_findings:
        matches = _merge_findings(matches, ai_findings)

    # Layer 4: Secret masking
    masked_content = mask_secrets(content)

    # Layer 5: Risk scoring & decision
    result = _build_result(
        subject=content,
        channel=channel_value.value,
        matches=matches,
        masked_content=masked_content,
        ai_enhanced=ai_findings is not None,
        normalized_input=normalized if normalized != content else None,
    )
    _record_audit(result)
    return result


def analyze_tool_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    subject = f"{tool_name} {arguments}"

    # Normalize tool call content
    normalized = normalize(subject)

    matches = _find_matches(subject, [*TOOL_RULES, *SECRET_RULES])
    if normalized != subject:
        norm_matches = _find_matches(normalized, [*TOOL_RULES, *SECRET_RULES])
        matches = _merge_findings(matches, norm_matches)

    ai_findings = _run_ai_if_needed(subject, "tool_call", matches)
    if ai_findings:
        matches = _merge_findings(matches, ai_findings)

    result = _build_result(
        subject=subject,
        channel="tool_call",
        matches=matches,
        masked_content=mask_secrets(subject),
        metadata={"tool_name": tool_name, "arguments": arguments},
        ai_enhanced=ai_findings is not None,
    )
    _record_audit(result)
    return result


def get_audit_events(limit: int = 50) -> list[dict[str, Any]]:
    return AUDIT_EVENTS[-limit:][::-1]


def mask_secrets(content: str) -> str:
    masked = content
    for rule in SECRET_RULES:
        masked = rule.pattern.sub(lambda match: _mask_match(match), masked)
    return masked


def _run_ai_if_needed(content: str, channel: str, regex_matches: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """Call Gemini if regex didn't already produce a DENY and AI is available."""
    if not gemini_available():
        return None

    # Skip AI if regex already found a hard DENY
    if any(m["decision"] == Decision.DENY.value for m in regex_matches):
        return None

    try:
        result = asyncio.run(gemini_analyze(content, channel))
    except RuntimeError:
        # Already in an async context
        loop = asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = loop.run_until_complete(
                loop.run_in_executor(pool, asyncio.run, gemini_analyze(content, channel))
            )

    if not result or not result.get("threat_detected"):
        return None

    # Convert AI findings to our format
    findings: list[dict[str, Any]] = []
    for f in result.get("findings", []):
        findings.append({
            "rule_id": "PG-AI-001",
            "name": f.get("name", "AI-detected threat"),
            "category": f.get("category", "ai_analysis"),
            "severity": min(55, f.get("severity", 30)),
            "decision": result.get("decision", "HUMAN_REVIEW"),
            "evidence": "AI analysis",
            "explanation": f.get("explanation", "Detected by Gemini AI analysis."),
        })

    return findings if findings else None


def _merge_findings(regex_findings: list[dict[str, Any]], ai_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge AI findings with regex findings, avoiding duplicates by category+name."""
    existing = {(f["category"], f["name"].lower()) for f in regex_findings}
    merged = list(regex_findings)
    for f in ai_findings:
        if (f["category"], f["name"].lower()) not in existing:
            merged.append(f)
    return merged


def _find_matches(content: str, rules: list[Rule]) -> list[dict[str, Any]]:
    disabled = get_disabled_rule_ids()
    findings: list[dict[str, Any]] = []
    for rule in rules:
        if rule.rule_id in disabled:
            continue
        for match in rule.pattern.finditer(content):
            findings.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "category": rule.category,
                    "severity": rule.severity,
                    "decision": rule.decision.value,
                    "evidence": _safe_excerpt(match),
                    "explanation": rule.explanation,
                }
            )
    return findings


def _build_result(
    subject: str,
    channel: str,
    matches: list[dict[str, Any]],
    masked_content: str,
    metadata: dict[str, Any] | None = None,
    ai_enhanced: bool = False,
    normalized_input: str | None = None,
) -> dict[str, Any]:
    risk_score = min(100, sum(finding["severity"] for finding in matches))
    decision = _decision_for(risk_score, matches)
    result: dict[str, Any] = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "channel": channel,
        "decision": decision.value,
        "risk_score": risk_score,
        "summary": _summary(decision, risk_score, matches),
        "findings": matches,
        "masked_content": masked_content,
        "content_sha256": sha256(subject.encode("utf-8")).hexdigest(),
        "metadata": metadata or {},
        "ai_enhanced": ai_enhanced,
    }
    if normalized_input:
        result["normalized_input"] = normalized_input[:200]
    return result


def _decision_for(risk_score: int, matches: list[dict[str, Any]]) -> Decision:
    explicit = {finding["decision"] for finding in matches}
    if Decision.DENY.value in explicit or risk_score >= 80:
        return Decision.DENY
    if Decision.HUMAN_REVIEW.value in explicit or risk_score >= 55:
        return Decision.HUMAN_REVIEW
    if risk_score >= 20:
        return Decision.LOG
    return Decision.ALLOW


def _summary(decision: Decision, risk_score: int, matches: list[dict[str, Any]]) -> str:
    if not matches:
        return "No policy, injection, secret, or dangerous tool-call signals were detected."
    categories = sorted({finding["category"] for finding in matches})
    return f"{decision.value} with risk score {risk_score}; detected {', '.join(categories)}."


def _safe_excerpt(match: Match[str]) -> str:
    value = match.group(0)
    if len(value) <= 16:
        return value
    return f"{value[:6]}...{value[-4:]}"


def _mask_match(match: Match[str]) -> str:
    value = match.group(0)
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...[REDACTED]...{value[-4:]}"


def _record_audit(result: dict[str, Any]) -> None:
    AUDIT_EVENTS.append(
        {
            "event_id": result["event_id"],
            "timestamp": result["timestamp"],
            "channel": result["channel"],
            "decision": result["decision"],
            "risk_score": result["risk_score"],
            "summary": result["summary"],
            "finding_count": len(result["findings"]),
            "content_sha256": result["content_sha256"],
            "ai_enhanced": result.get("ai_enhanced", False),
        }
    )
    if len(AUDIT_EVENTS) > AUDIT_MAX_EVENTS:
        AUDIT_EVENTS[:] = AUDIT_EVENTS[-AUDIT_MAX_EVENTS:]
