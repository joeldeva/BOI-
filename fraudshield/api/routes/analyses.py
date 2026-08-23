from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile, status
from starlette.concurrency import run_in_threadpool

from fraudshield.api.dependencies import container
from fraudshield.core.errors import ValidationError
from fraudshield.core.schemas import MethodInterpretationRequest
from fraudshield.core.security import require_api_key, require_inline_analysis
from fraudshield.deceptiscope.narrative import interpret_methods_locally
from fraudshield.deceptiscope.report import build_analysis_pdf
from fraudshield.deceptiscope.validator import store_apk_upload
from fraudshield.services.container import ServiceContainer


router = APIRouter(prefix="/api/v1", tags=["DeceptiScope"], dependencies=[Depends(require_api_key)])
VALID_CATEGORIES = {"banking", "finance", "utility", "other"}


def _category(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in VALID_CATEGORIES:
        raise ValidationError(
            "invalid_category",
            "Unsupported application category",
            allowed=sorted(VALID_CATEGORIES),
        )
    return normalized


@router.post(
    "/apk-analyses",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key), Depends(require_inline_analysis)],
)
async def analyze_apk(
    services: Annotated[ServiceContainer, Depends(container)],
    request: Request,
    file: Annotated[UploadFile, File(description="Android APK; retained only when configured")],
    category: Annotated[str, Form()] = "banking",
    dynamic: Annotated[bool, Form()] = False,
) -> dict:
    normalized_category = _category(category)
    stored = await store_apk_upload(file, services.settings)
    try:
        async with request.app.state.apk_analysis_semaphore:
            return await run_in_threadpool(
                services.apk_pipeline.analyze_uploaded,
                path=stored.path,
                original_name=stored.original_name,
                sha256=stored.sha256,
                size_bytes=stored.size_bytes,
                category=normalized_category,
                dynamic=dynamic,
            )
    finally:
        # The pipeline performs the normal cleanup. This second, idempotent cleanup
        # also covers cancellation while a request is waiting for the semaphore.
        if not services.settings.retain_uploads:
            stored.path.unlink(missing_ok=True)


@router.get("/apk-analyses")
def list_analyses(
    services: Annotated[ServiceContainer, Depends(container)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Annotated[str | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> dict:
    normalized_severity = severity.upper() if severity else None
    if normalized_severity and normalized_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValidationError("invalid_severity", "Invalid severity filter")
    if status_filter and status_filter not in {"pending", "running", "completed", "failed"}:
        raise ValidationError("invalid_status", "Invalid status filter")
    items, total = services.analyses.list(
        limit=limit,
        offset=offset,
        severity=normalized_severity,
        status=status_filter,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/apk-analyses/{analysis_id}")
def get_analysis(
    analysis_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    return services.analyses.get(analysis_id)


@router.get("/apk-analyses/{analysis_id}/report.pdf")
def get_analysis_report(
    analysis_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> Response:
    analysis = services.analyses.get(analysis_id)
    if analysis["status"] != "completed":
        raise ValidationError("analysis_incomplete", "A PDF is available only for completed analyses")
    pdf = build_analysis_pdf(analysis)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="FraudShield-{analysis_id}.pdf"'},
    )


@router.post("/method-review", dependencies=[Depends(require_api_key)])
def review_methods(request: MethodInterpretationRequest) -> dict:
    return {
        "items": interpret_methods_locally(request.methods),
        "notice": "This endpoint reviews only the supplied snippets and does not claim full decompilation.",
    }


@router.post(
    "/demo/apk-analysis",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def demo_apk_analysis(
    services: Annotated[ServiceContainer, Depends(container)],
    category: Annotated[str, Query()] = "banking",
) -> dict:
    return services.apk_pipeline.analyze_demo(_category(category))
