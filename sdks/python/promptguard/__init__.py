"""PromptGuard AI Python SDK.

A typed client for the PromptGuard AI firewall API with retry logic
and fail-safe behavior.

Usage:
    from promptguard import PromptGuardClient

    client = PromptGuardClient("http://localhost:8000", api_key="your-key")

    if client.is_permitted("execute_command", "rm -rf /tmp"):
        execute(...)
    else:
        print("Blocked by PromptGuard")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class GuardResult:
    permitted: bool
    decision: str
    risk_score: int
    event_id: str
    summary: str
    findings_count: int
    findings: list[dict[str, Any]]
    ai_enhanced: bool
    action: str
    source: str
    timestamp: str


@dataclass
class ScanResult:
    event_id: str
    decision: str
    risk_score: int
    summary: str
    findings: list[dict[str, Any]]
    masked_content: str
    ai_enhanced: bool
    channel: str
    timestamp: str
    tenant_id: str = "default"


class PromptGuardError(Exception):
    """Raised when the PromptGuard API returns an error."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"PromptGuard API error {status_code}: {detail}")


@dataclass
class PromptGuardClient:
    """Client for the PromptGuard AI firewall API."""

    base_url: str
    api_key: str = ""
    timeout: float = 10.0
    max_retries: int = 3
    fail_safe_decision: str = "DENY"
    _session: requests.Session = field(default_factory=requests.Session, repr=False)

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")
        if self.api_key:
            self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        self._session.headers["Content-Type"] = "application/json"

    def guard(self, action: str, content: str, channel: str = "prompt", source: str = "python-sdk", metadata: dict | None = None) -> GuardResult:
        """Check if an action is permitted before executing it."""
        data = self._request("POST", "/v1/guard", json={
            "action": action,
            "content": content,
            "channel": channel,
            "source": source,
            "metadata": metadata or {},
        })
        return GuardResult(**{k: data[k] for k in GuardResult.__dataclass_fields__ if k in data})

    def is_permitted(self, action: str, content: str, **kwargs) -> bool:
        """Simple boolean check — returns False on any error (fail-safe)."""
        try:
            return self.guard(action, content, **kwargs).permitted
        except Exception:
            return self.fail_safe_decision == "ALLOW"

    def scan(self, content: str, channel: str = "prompt") -> ScanResult:
        """Scan content for threats."""
        data = self._request("POST", "/scan", json={"channel": channel, "content": content})
        return ScanResult(**{k: data[k] for k in ScanResult.__dataclass_fields__ if k in data})

    def scan_tool(self, tool_name: str, arguments: dict[str, Any]) -> ScanResult:
        """Scan a tool call before execution."""
        data = self._request("POST", "/scan-tool", json={"tool_name": tool_name, "arguments": arguments})
        return ScanResult(**{k: data[k] for k in ScanResult.__dataclass_fields__ if k in data})

    def batch_scan(self, items: list[dict[str, str]]) -> dict[str, Any]:
        """Scan multiple items in one request."""
        return self._request("POST", "/v1/batch", json={"items": items})

    def health(self) -> dict[str, Any]:
        """Check service health."""
        return self._request("GET", "/health")

    def stats(self) -> dict[str, Any]:
        """Get security metrics."""
        return self._request("GET", "/v1/stats")

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        """Make a request with retry logic."""
        url = f"{self.base_url}{path}"
        for attempt in range(self.max_retries):
            try:
                r = self._session.request(method, url, timeout=self.timeout, **kwargs)
                if r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 60))
                    time.sleep(min(retry_after, 120))
                    continue
                if r.status_code >= 400:
                    detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
                    raise PromptGuardError(r.status_code, detail)
                return r.json()
            except (requests.ConnectionError, requests.Timeout):
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)
        raise PromptGuardError(503, "Max retries exceeded")
