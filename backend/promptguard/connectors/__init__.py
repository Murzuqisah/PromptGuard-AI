"""SIEM integration connectors.

Each connector formats PromptGuard events into the target platform's
expected schema and delivers them via the platform's ingestion API.

Usage:
    Configure via env vars. Events are dispatched automatically when
    a connector is enabled and a matching decision occurs.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BaseConnector:
    """Base class for SIEM connectors."""

    name: str = "base"

    def __init__(self) -> None:
        self.enabled = False

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Transform a PromptGuard event into the platform's schema."""
        return event

    async def send(self, event: dict[str, Any]) -> bool:
        """Send a formatted event to the SIEM. Returns True on success."""
        return False


class SplunkHECConnector(BaseConnector):
    """Splunk HTTP Event Collector connector.

    Env vars:
        PROMPTGUARD_SPLUNK_HEC_URL: HEC endpoint (e.g., https://splunk:8088/services/collector/event)
        PROMPTGUARD_SPLUNK_HEC_TOKEN: HEC token
    """

    name = "splunk"

    def __init__(self) -> None:
        self.url = os.getenv("PROMPTGUARD_SPLUNK_HEC_URL", "")
        self.token = os.getenv("PROMPTGUARD_SPLUNK_HEC_TOKEN", "")
        self.enabled = bool(self.url and self.token)

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "event": {
                "event_id": event.get("event_id"),
                "decision": event.get("decision"),
                "risk_score": event.get("risk_score"),
                "channel": event.get("channel"),
                "summary": event.get("summary"),
                "tenant_id": event.get("tenant_id", "default"),
                "ai_enhanced": event.get("ai_enhanced", False),
                "finding_count": len(event.get("findings", [])),
            },
            "sourcetype": "promptguard:scan",
            "source": "promptguard-ai",
            "time": int(datetime.fromisoformat(event.get("timestamp", datetime.now(UTC).isoformat())).timestamp()),
        }

    async def send(self, event: dict[str, Any]) -> bool:
        payload = self.format_event(event)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    self.url,
                    json=payload,
                    headers={"Authorization": f"Splunk {self.token}"},
                )
                return r.status_code == 200
        except Exception as e:
            logger.warning(f"Splunk HEC delivery failed: {e}")
            return False


class CloudWatchConnector(BaseConnector):
    """AWS CloudWatch Logs connector.

    Env vars:
        PROMPTGUARD_CLOUDWATCH_LOG_GROUP: Log group name
        PROMPTGUARD_CLOUDWATCH_LOG_STREAM: Log stream name
        PROMPTGUARD_CLOUDWATCH_REGION: AWS region (default: us-east-1)

    Requires boto3 and AWS credentials in environment.
    """

    name = "cloudwatch"

    def __init__(self) -> None:
        self.log_group = os.getenv("PROMPTGUARD_CLOUDWATCH_LOG_GROUP", "")
        self.log_stream = os.getenv("PROMPTGUARD_CLOUDWATCH_LOG_STREAM", "promptguard-events")
        self.region = os.getenv("PROMPTGUARD_CLOUDWATCH_REGION", "us-east-1")
        self.enabled = bool(self.log_group)
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("logs", region_name=self.region)
        return self._client

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": event.get("event_id"),
            "decision": event.get("decision"),
            "risk_score": event.get("risk_score"),
            "channel": event.get("channel"),
            "summary": event.get("summary"),
            "tenant_id": event.get("tenant_id", "default"),
            "timestamp": event.get("timestamp"),
            "source": "promptguard-ai",
        }

    async def send(self, event: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        try:
            client = self._get_client()
            formatted = self.format_event(event)
            client.put_log_events(
                logGroupName=self.log_group,
                logStreamName=self.log_stream,
                logEvents=[{
                    "timestamp": int(datetime.now(UTC).timestamp() * 1000),
                    "message": json.dumps(formatted),
                }],
            )
            return True
        except Exception as e:
            logger.warning(f"CloudWatch delivery failed: {e}")
            return False


class DatadogConnector(BaseConnector):
    """Datadog Logs connector.

    Env vars:
        PROMPTGUARD_DATADOG_API_KEY: Datadog API key
        PROMPTGUARD_DATADOG_SITE: Datadog site (default: datadoghq.com)
    """

    name = "datadog"

    def __init__(self) -> None:
        self.api_key = os.getenv("PROMPTGUARD_DATADOG_API_KEY", "")
        self.site = os.getenv("PROMPTGUARD_DATADOG_SITE", "datadoghq.com")
        self.enabled = bool(self.api_key)

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "ddsource": "promptguard",
            "ddtags": f"decision:{event.get('decision')},channel:{event.get('channel')},tenant:{event.get('tenant_id', 'default')}",
            "hostname": "promptguard-ai",
            "service": "promptguard",
            "status": "error" if event.get("decision") == "DENY" else "warn",
            "message": event.get("summary", ""),
            "event_id": event.get("event_id"),
            "risk_score": event.get("risk_score"),
            "decision": event.get("decision"),
            "channel": event.get("channel"),
            "ai_enhanced": event.get("ai_enhanced", False),
        }

    async def send(self, event: dict[str, Any]) -> bool:
        payload = self.format_event(event)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    f"https://http-intake.logs.{self.site}/api/v2/logs",
                    json=[payload],
                    headers={
                        "DD-API-KEY": self.api_key,
                        "Content-Type": "application/json",
                    },
                )
                return r.status_code in (200, 202)
        except Exception as e:
            logger.warning(f"Datadog delivery failed: {e}")
            return False


class ElasticConnector(BaseConnector):
    """Elasticsearch / OpenSearch connector.

    Env vars:
        PROMPTGUARD_ELASTIC_URL: Elasticsearch URL (e.g., https://es:9200)
        PROMPTGUARD_ELASTIC_INDEX: Index name (default: promptguard-events)
        PROMPTGUARD_ELASTIC_API_KEY: API key (optional, for Elastic Cloud)
    """

    name = "elastic"

    def __init__(self) -> None:
        self.url = os.getenv("PROMPTGUARD_ELASTIC_URL", "")
        self.index = os.getenv("PROMPTGUARD_ELASTIC_INDEX", "promptguard-events")
        self.api_key = os.getenv("PROMPTGUARD_ELASTIC_API_KEY", "")
        self.enabled = bool(self.url)

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "@timestamp": event.get("timestamp"),
            "event.kind": "alert",
            "event.category": "intrusion_detection",
            "event.outcome": "failure" if event.get("decision") == "DENY" else "success",
            "promptguard.event_id": event.get("event_id"),
            "promptguard.decision": event.get("decision"),
            "promptguard.risk_score": event.get("risk_score"),
            "promptguard.channel": event.get("channel"),
            "promptguard.summary": event.get("summary"),
            "promptguard.tenant_id": event.get("tenant_id", "default"),
            "promptguard.ai_enhanced": event.get("ai_enhanced", False),
        }

    async def send(self, event: dict[str, Any]) -> bool:
        payload = self.format_event(event)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    f"{self.url}/{self.index}/_doc",
                    json=payload,
                    headers=headers,
                )
                return r.status_code in (200, 201)
        except Exception as e:
            logger.warning(f"Elastic delivery failed: {e}")
            return False


# --- Registry ---

ALL_CONNECTORS: list[BaseConnector] = [
    SplunkHECConnector(),
    CloudWatchConnector(),
    DatadogConnector(),
    ElasticConnector(),
]


def get_enabled_connectors() -> list[BaseConnector]:
    """Return list of connectors that are configured and enabled."""
    return [c for c in ALL_CONNECTORS if c.enabled]


async def dispatch_to_siem(event: dict[str, Any]) -> None:
    """Send event to all enabled SIEM connectors."""
    for connector in get_enabled_connectors():
        await connector.send(event)
