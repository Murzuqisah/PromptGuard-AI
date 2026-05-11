"""Correlation ID middleware.

Assigns a unique correlation ID to each request. The ID is:
- Read from X-Correlation-ID header if provided by the caller
- Generated as a UUID4 if not provided
- Set in the contextvars for use by the logger
- Returned in the response X-Correlation-ID header
"""

from __future__ import annotations

from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..logging import correlation_id


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = request.headers.get("x-correlation-id", str(uuid4()))
        token = correlation_id.set(req_id)
        try:
            response = await call_next(request)
            response.headers["X-Correlation-ID"] = req_id
            return response
        finally:
            correlation_id.reset(token)
