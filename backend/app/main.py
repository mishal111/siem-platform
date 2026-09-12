import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pymongo.errors import PyMongoError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings
from app.management import router as management_router
from app.middleware import RequestMiddleware
from app.repository import EventRepository
from app.routes import router

logger = logging.getLogger("siem")


def create_app(settings: Settings | None = None, repository: Any = None) -> FastAPI:
    settings = settings or Settings()
    logging.basicConfig(level=settings.log_level, format="%(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = repository if repository is not None else EventRepository(settings)
        app.state.repository = store
        try:
            await asyncio.to_thread(store.initialize)
            logger.info('{"event":"backend_started"}')
            yield
        except PyMongoError:
            logger.error('{"event":"database_lifecycle_failure"}')
            raise RuntimeError("Database initialization or shutdown failed") from None
        finally:
            await asyncio.to_thread(store.close)

    app = FastAPI(
        title="SIEM API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.deployment_mode == "development" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.deployment_mode == "development" else None,
    )
    app.state.settings = settings
    app.add_middleware(
        RequestMiddleware,
        max_bytes=settings.max_request_bytes,
        body_timeout=settings.request_body_timeout_seconds,
        max_concurrent=settings.max_concurrent_requests,
        requests_per_minute=settings.requests_per_minute,
        require_https=settings.deployment_mode == "hardened",
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["X-API-Key", "Authorization", "Content-Type"],
            expose_headers=["X-Request-ID"],
        )

    @app.exception_handler(PyMongoError)
    async def database_error(request: Request, exc: PyMongoError) -> JSONResponse:
        logger.error('{"event":"database_operation_failed"}')
        return JSONResponse(
            status_code=503,
            content={"detail": "Database temporarily unavailable; retry the request"},
            headers={"Retry-After": "3"},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default includes rejected input, which may contain raw telemetry or secrets.
        errors = [
            {"type": item["type"], "loc": list(item["loc"]), "msg": item["msg"]}
            for item in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    app.include_router(router)
    app.include_router(management_router)
    return app
