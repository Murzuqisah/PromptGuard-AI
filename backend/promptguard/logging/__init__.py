"""Structured JSON logging with correlation ID support.

Provides:
- JSON log formatter for production environments
- Correlation ID context variable (set per-request by middleware)
- get_logger() helper that includes correlation_id in every log line
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from ..config import LOG_LEVEL

# Correlation ID context — set per request by middleware
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id.get("-"),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data"):
            log_entry.update(record.extra_data)
        return json.dumps(log_entry, default=str)


def setup_logging() -> None:
    """Configure root logger with JSON formatter."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance. Correlation ID is automatically included via formatter."""
    return logging.getLogger(name)
