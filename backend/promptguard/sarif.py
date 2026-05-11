"""SARIF 2.1.0 export for GitHub Advanced Security integration.

Converts PromptGuard scan findings into the Static Analysis Results
Interchange Format (SARIF) used by GitHub code scanning.
"""

from __future__ import annotations

from typing import Any

from .scanner import get_audit_events

_SEVERITY_MAP = {
    "DENY": "error",
    "HUMAN_REVIEW": "warning",
    "LOG": "note",
    "ALLOW": "none",
}

_CATEGORY_TO_RULE_INDEX: dict[str, str] = {
    "prompt_injection": "security",
    "policy_violation": "security",
    "secret_leakage": "security",
    "dangerous_tool_call": "security",
    "ai_analysis": "security",
}


def generate_sarif(limit: int = 100) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 document from recent audit events."""
    events = get_audit_events(limit)

    results: list[dict[str, Any]] = []
    rules_seen: dict[str, dict[str, Any]] = {}

    for event in events:
        if event.get("decision") == "ALLOW":
            continue

        # Each event becomes a result
        result: dict[str, Any] = {
            "ruleId": f"promptguard/{event.get('channel', 'unknown')}",
            "level": _SEVERITY_MAP.get(event.get("decision", ""), "warning"),
            "message": {"text": event.get("summary", "Security finding detected by PromptGuard AI.")},
            "properties": {
                "event_id": event.get("event_id", ""),
                "channel": event.get("channel", ""),
                "risk_score": event.get("risk_score", 0),
                "decision": event.get("decision", ""),
                "timestamp": event.get("timestamp", ""),
                "ai_enhanced": event.get("ai_enhanced", False),
            },
        }
        results.append(result)

        # Track unique rules
        rule_id = result["ruleId"]
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f"PromptGuard-{event.get('channel', 'scan').replace('_', '-')}",
                "shortDescription": {"text": f"PromptGuard {event.get('channel', '')} security check"},
                "fullDescription": {"text": f"Security analysis of {event.get('channel', '')} content by PromptGuard AI hybrid detection engine."},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": ["security", "ai-firewall"]},
            }

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PromptGuard AI",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Murzuqisah/PromptGuard-AI",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif
