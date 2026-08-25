from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from fraudshield.api.dependencies import container
from fraudshield.core.security import require_api_key
from fraudshield.deceptiscope.experiments import CATALOG_VERSION, TrustedExperimentRegistry
from fraudshield.services.container import ServiceContainer


router = APIRouter(tags=["System"])


@router.get("/")
def root(services: Annotated[ServiceContainer, Depends(container)]) -> dict:
    return {
        "service": services.settings.app_name,
        "version": services.settings.version,
        "status": "online",
        "api": "/api/v1",
        "docs": "/docs" if services.settings.docs_enabled else None,
    }


@router.get("/health")
def health(services: Annotated[ServiceContainer, Depends(container)]) -> dict:
    database_ok = services.db.ping()
    return {
        "status": "healthy" if database_ok else "degraded",
        "database": "up" if database_ok else "down",
        "version": services.settings.version,
    }


@router.get("/health/live", include_in_schema=False)
def liveness(services: Annotated[ServiceContainer, Depends(container)]) -> dict:
    return {"status": "alive", "version": services.settings.version}


@router.get("/metrics", include_in_schema=False)
def metrics(
    request: Request,
    services: Annotated[ServiceContainer, Depends(container)],
) -> Response:
    if not request.app.state.metrics.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Metrics are disabled")
    request.app.state.metrics.set_job_summary(services.jobs.summary())
    payload, content_type = request.app.state.metrics.render()
    return Response(content=payload, media_type=content_type)


@router.get("/health/ready")
def readiness(
    request: Request,
    response: Response,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    database_ok = services.db.ping()
    checks = {
        "database": database_ok,
        "baseline": services.settings.baseline_path.is_file(),
        "storage": services.artifacts.ping(),
        "audit": not request.app.state.audit_degraded,
    }
    ready = all(checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "ready": ready,
        "checks": checks,
    }


@router.get("/api/v1/system/capabilities", dependencies=[Depends(require_api_key)])
def capabilities(services: Annotated[ServiceContainer, Depends(container)]) -> dict:
    return {
        "static_apk_analysis": True,
        "apk_only_product": True,
        "multi_engine": services.apk_pipeline.engines.capabilities(),
        "dynamic_lite": services.apk_pipeline.dynamic.status(),
        "llm": {
            "provider": services.settings.llm_provider,
            "configured": services.settings.llm_provider != "disabled",
            "controls_risk_score": False,
        },
        "ai_experiments": {
            "catalog_version": CATALOG_VERSION,
            "plan_limit": services.settings.ai_experiment_plan_limit,
            "max_investigation_rounds": services.settings.max_investigation_rounds,
            "max_experiments_per_round": services.settings.max_experiments_per_round,
            "execution_mode": "planned-only",
            "catalog": TrustedExperimentRegistry().catalog_payload(),
        },
        "pdf_reports": True,
        "durable_jobs": True,
        "inline_analysis": services.settings.inline_analysis_enabled,
        "database": services.db.backend,
        "authentication": services.settings.auth_mode,
        "tamper_evident_audit": True,
    }


@router.get("/api/v1/dashboard/summary", dependencies=[Depends(require_api_key)])
def dashboard_summary(services: Annotated[ServiceContainer, Depends(container)]) -> dict:
    analyses = services.analyses.summary()
    return {
        "apk_analyses": analyses,
        "indicator_count": services.indicators.count(),
        "jobs": services.jobs.summary(),
    }
