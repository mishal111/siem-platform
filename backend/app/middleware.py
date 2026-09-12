import asyncio
import json
import logging
import time
from collections import OrderedDict
from uuid import uuid4

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("siem.http")


class RequestMiddleware:
    """Bound actual body bytes, including chunked bodies, before JSON parsing."""

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int,
        body_timeout=10,
        max_concurrent=100,
        requests_per_minute=6000,
        require_https=False,
    ):
        self.app = app
        self.max_bytes = max_bytes
        self.body_timeout = body_timeout
        self.max_concurrent = max_concurrent
        self.requests_per_minute = requests_per_minute
        self.require_https = require_https
        self.active = 0
        self.peers = OrderedDict()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid4().hex
        started = time.monotonic()
        status = 500
        admitted = False

        async def send_response(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
                message["headers"].extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                    ]
                )
                if status == 429 and not any(
                    key.lower() == b"retry-after" for key, _ in message["headers"]
                ):
                    message["headers"].append((b"retry-after", b"60"))
            await send(message)

        async def error(code: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=code)(scope, receive, send_response)

        try:
            if (
                self.require_https
                and scope.get("scheme") != "https"
                and scope.get("path") not in ("/api/v1/health", "/api/v1/health/ready")
            ):
                await error(400, "HTTPS is required")
                return
            if self.active >= self.max_concurrent:
                await error(503, "Server capacity reached; retry shortly")
                return
            peer = (scope.get("client") or ("unknown",))[0]
            window = int(time.monotonic()) // 60
            previous, count = self.peers.pop(peer, (window, 0))
            count = count + 1 if previous == window else 1
            self.peers[peer] = (window, count)
            if len(self.peers) > 4096:
                self.peers.popitem(last=False)
            if count > self.requests_per_minute:
                await error(429, "Request rate limit exceeded")
                return
            self.active += 1
            admitted = True
            headers = dict(scope["headers"])
            if headers.get(b"content-encoding", b"identity").lower() != b"identity":
                await error(415, "Compressed request bodies are not supported")
                return
            if b"content-length" in headers:
                try:
                    declared = int(headers[b"content-length"])
                    if declared < 0:
                        raise ValueError
                except ValueError:
                    await error(400, "Invalid Content-Length")
                    return
                if declared > self.max_bytes:
                    await error(413, "Request body exceeds the configured size limit")
                    return

            body = bytearray()
            try:
                async with asyncio.timeout(self.body_timeout):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        body.extend(message.get("body", b""))
                        if len(body) > self.max_bytes:
                            await error(413, "Request body exceeds the configured size limit")
                            return
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                await error(408, "Request body timed out")
                return

            # Reject non-standard NaN/Infinity before they reach BSON or error serialization.
            if body and b"application/json" in headers.get(b"content-type", b"").lower():
                try:
                    json.loads(body, parse_constant=reject_nonfinite)
                except (ValueError, RecursionError, UnicodeError):
                    await error(400, "Malformed JSON body")
                    return

            delivered = False

            async def replay() -> Message:
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, send_response)
        finally:
            if admitted:
                self.active -= 1
            # No headers, query values, bodies, or raw exception text in request logs.
            logger.info(
                json.dumps(
                    {
                        "event": "http_request",
                        "request_id": request_id,
                        "method": scope["method"],
                        "status": status,
                        "duration_ms": round((time.monotonic() - started) * 1000, 2),
                    }
                )
            )


def reject_nonfinite(value: str) -> None:
    raise ValueError("Non-finite JSON number")
