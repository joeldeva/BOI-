from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from fraudshield.api.routes import analyses, audit, indicators, jobs, legacy, system
from fraudshield.core.config import Settings
from fraudshield.core.errors import FraudShieldError
from fraudshield.core.logging import configure_logging
from fraudshield.core.metrics import Metrics
from fraudshield.services.container import ServiceContainer


logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("fraudshield.audit")


class TrustedApplicationHostMiddleware(TrustedHostMiddleware):
    """Validate application hosts while keeping cluster probes address-agnostic.

    Kubernetes and Prometheus normally address pods by IP. These operational
    endpoints do not generate absolute URLs or use the Host header, and their
    reachability is constrained by the service and NetworkPolicy layer.
    """

    host_independent_paths = frozenset({"/health/live", "/health/ready", "/metrics"})

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and scope.get("path") in self.host_independent_paths:
            await self.app(scope, receive, send)
            return
        await super().__call__(scope, receive, send)


def _audit_resource(path: str) -> tuple[str, str | None]:
    segments = [segment for segment in path.split("/") if segment]
    if segments[:2] == ["api", "v1"]:
        segments = segments[2:]
    if not segments:
        return "system", None
    aliases = {
        "apk-analyses": "apk_analysis",
        "audit-events": "audit_event",
        "jobs": "job",
        "indicators": "indicator",
    }
    resource_type = aliases.get(segments[0], segments[0].replace("-", "_"))
    resource_id = segments[1] if len(segments) > 1 and segments[1] not in {
        "seed",
        "verify",
        "summary",
        "analyze",
    } else None
    return resource_type, resource_id


def _should_audit(path: str) -> bool:
    return path.startswith("/api/") or path in {
        "/analyze-apk",
        "/report.pdf",
    } or path.startswith("/report/")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.from_env()
    resolved.ensure_directories()
    resolved.validate()
    configure_logging(resolved.debug)
    services = ServiceContainer.build(resolved)
    metrics = Metrics(resolved.metrics_enabled)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            services.db.close()

    app = FastAPI(
        title="FraudShield DeceptiScope APK Intelligence API",
        version=resolved.version,
        description=(
            "Evidence-grounded, multi-engine defensive Android APK analysis. "
            "Language models never control risk scores or malware classifications."
        ),
        contact={"name": "FraudShield Project"},
        license_info={
            "name": "GNU Affero General Public License v3.0",
            "url": "https://www.gnu.org/licenses/agpl-3.0.html",
        },
        docs_url="/docs" if resolved.docs_enabled else None,
        redoc_url="/redoc" if resolved.docs_enabled else None,
        openapi_url="/openapi.json" if resolved.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.container = services
    app.state.audit_degraded = False
    app.state.metrics = metrics
    app.state.apk_analysis_semaphore = asyncio.Semaphore(resolved.max_concurrent_apk_analyses)
    app.add_middleware(
        TrustedApplicationHostMiddleware,
        allowed_hosts=list(resolved.trusted_hosts),
        www_redirect=False,
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-API-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", "")[:128] or uuid.uuid4().hex
        request.state.request_id = request_id
        started = time.perf_counter()
        response: JSONResponse | None = None
        if (
            resolved.environment == "production"
            and request.app.state.audit_degraded
            and request.method not in {"GET", "HEAD", "OPTIONS"}
        ):
            response = JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "audit_unavailable",
                        "message": "Security audit persistence is unavailable",
                        "details": {},
                        "request_id": request_id,
                    }
                },
            )
        content_length = request.headers.get("content-length")
        upload_limits = {
            "/api/v1/apk-analyses": resolved.max_apk_bytes + 2 * 1024 * 1024,
            "/api/v1/jobs/apk-analysis": resolved.max_apk_bytes + 2 * 1024 * 1024,
            "/api/v1/deceptiscope/analyze": resolved.max_apk_bytes + 2 * 1024 * 1024,
            "/analyze-apk": resolved.max_apk_bytes + 2 * 1024 * 1024,
        }
        if response is None and content_length and request.url.path in upload_limits:
            try:
                too_large = int(content_length) > upload_limits[request.url.path]
            except ValueError:
                too_large = False
            if too_large:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "request_too_large",
                            "message": "Request body exceeds the configured upload limit",
                            "details": {"maximum_bytes": upload_limits[request.url.path]},
                            "request_id": request_id,
                        }
                    },
                )
        if response is None:
            response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        if request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if resolved.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if _should_audit(request.url.path):
            principal = getattr(request.state, "principal", None)
            resource_type, resource_id = _audit_resource(request.url.path)
            try:
                audit_event = services.audit.append(
                    request_id=request_id,
                    actor_id=principal.subject if principal else "unauthenticated",
                    auth_type=principal.auth_type if principal else "none",
                    roles=list(principal.roles) if principal else [],
                    action=f"{resource_type}.{request.method.lower()}",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    client_address=request.client.host if request.client else "unknown",
                    user_agent=request.headers.get("user-agent", ""),
                    details={
                        "duration_ms": round(elapsed_ms, 1),
                        "query_keys": sorted(request.query_params.keys()),
                        "auth_failure": getattr(request.state, "auth_failure", None),
                    },
                )
                audit_logger.info(
                    "security_audit_event",
                    extra={
                        "event_type": "security_audit",
                        "event_id": audit_event["id"],
                        "request_id": request_id,
                        "actor_id": audit_event["actor_id"],
                        "action": audit_event["action"],
                        "resource_type": audit_event["resource_type"],
                        "resource_id": audit_event["resource_id"],
                        "status_code": audit_event["status_code"],
                        "event_hash": audit_event["event_hash"],
                    },
                )
                request.app.state.audit_degraded = False
            except Exception:
                request.app.state.audit_degraded = True
                metrics.audit_failure()
                logger.exception("Security audit event could not be persisted")
        route = request.scope.get("route")
        route_name = getattr(route, "path", "__unmatched__")
        metrics.observe_request(
            method=request.method,
            route=route_name,
            status_code=response.status_code,
            seconds=elapsed_ms / 1000,
        )
        logger.info(
            "%s %s -> %s in %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            extra={"request_id": request_id},
        )
        return response

    @app.exception_handler(FraudShieldError)
    async def fraudshield_error(request: Request, exc: FraudShieldError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "request_validation_error",
                    "message": "Request parameters or body are invalid",
                    "details": {"errors": jsonable_encoder(exc.errors())},
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": "http_error",
                    "message": str(exc.detail),
                    "details": {},
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled request error")
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "The request could not be completed",
                    "details": {},
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    app.include_router(system.router)
    app.include_router(analyses.router)
    app.include_router(audit.router)
    app.include_router(jobs.router)
    app.include_router(indicators.router)
    app.include_router(legacy.router)
    return app


app = create_app()
