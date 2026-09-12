import asyncio

from app.middleware import RequestMiddleware


def test_chunked_body_cannot_bypass_limit():
    messages = iter(
        [
            {"type": "http.request", "body": b"a" * 700, "more_body": True},
            {"type": "http.request", "body": b"b" * 700, "more_body": False},
        ]
    )
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    async def unreachable(scope, receive, send):
        raise AssertionError("Oversized body reached the application")

    middleware = RequestMiddleware(unreachable, max_bytes=1024)
    asyncio.run(middleware({"type": "http", "method": "POST", "headers": []}, receive, send))
    assert sent[0]["status"] == 413


def test_body_timeout_releases_capacity():
    sent = []

    async def receive():
        await asyncio.sleep(10)

    async def send(message):
        sent.append(message)

    async def unreachable(*args):
        raise AssertionError("Timed-out body reached app")

    middleware = RequestMiddleware(unreachable, 1024, body_timeout=0.01)
    asyncio.run(middleware({"type": "http", "method": "POST", "headers": []}, receive, send))
    assert sent[0]["status"] == 408
    assert middleware.active == 0


def test_concurrency_limit_rejects_without_reading_body():
    sent = []

    async def unreachable(*args):
        raise AssertionError("Capacity-limited request was read")

    async def send(message):
        sent.append(message)

    middleware = RequestMiddleware(unreachable, 1024, max_concurrent=1)
    middleware.active = 1
    asyncio.run(middleware({"type": "http", "method": "POST", "headers": []}, unreachable, send))
    assert sent[0]["status"] == 503 and middleware.active == 1


def test_request_rate_limit_does_not_trust_forwarded_header(client):
    # The direct transport peer is authoritative unless the deployment's trusted proxy sets it.
    middleware = client.app.middleware_stack.app.app
    while not isinstance(middleware, RequestMiddleware):
        middleware = middleware.app
    middleware.requests_per_minute = 2
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health", headers={"X-Forwarded-For": "192.0.2.1"}).status_code == 200
    response = client.get("/api/v1/health", headers={"X-Forwarded-For": "192.0.2.2"})
    assert response.status_code == 429 and response.headers["retry-after"]
