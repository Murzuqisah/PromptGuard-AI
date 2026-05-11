"""Sliding window rate limiter middleware.

Tracks requests per client (IP or API key) within a configurable time window.
Returns 429 Too Many Requests when the limit is exceeded.
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import RATE_LIMIT_ENABLED, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # client_id -> list of request timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not RATE_LIMIT_ENABLED:
            return await call_next(request)

        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        client_id = self._get_client_id(request)
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW

        # Prune old entries
        timestamps = self._requests[client_id]
        self._requests[client_id] = [t for t in timestamps if t > window_start]

        if len(self._requests[client_id]) >= RATE_LIMIT_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW}s.",
                    "retry_after": RATE_LIMIT_WINDOW,
                },
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
            )

        self._requests[client_id].append(now)

        response = await call_next(request)
        remaining = RATE_LIMIT_REQUESTS - len(self._requests[client_id])
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(int(now + RATE_LIMIT_WINDOW))
        return response

    def _get_client_id(self, request: Request) -> str:
        """Identify client by API key if present, otherwise by IP."""
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return f"key:{auth[7:].strip()}"
        return f"ip:{request.client.host if request.client else 'unknown'}"


# ─── Correlation ID Middleware ────────────────────────────────────────────────

from uuid import uuid4
from ..logging import correlation_id


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Assigns a unique correlation ID to each request for distributed tracing."""

    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = request.headers.get("x-correlation-id", str(uuid4()))
        token = correlation_id.set(req_id)
        try:
            response = await call_next(request)
            response.headers["X-Correlation-ID"] = req_id
            return response
        finally:
            correlation_id.reset(token)
