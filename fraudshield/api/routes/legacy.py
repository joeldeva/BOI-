from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status

from fraudshield.api.dependencies import container
from fraudshield.api.routes.analyses import _category
from fraudshield.core.errors import ValidationError
from fraudshield.core.security import require_api_key
from fraudshield.deceptiscope.report import build_analysis_pdf
from fraudshield.deceptiscope.validator import store_apk_upload
from fraudshield.services.container import ServiceContainer
from starlette.concurrency import run_in_threadpool


def require_legacy_api(request: Request) -> None:
    if not request.app.state.settings.legacy_api_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Legacy API is disabled")


router = APIRouter(
    tags=["Legacy compatibility"],
    dependencies=[Depends(require_legacy_api), Depends(require_api_key)],
)


@router.post("/analyze-apk", deprecated=True)
@router.post("/api/v1/deceptiscope/analyze", deprecated=True)
async def analyze_apk_legacy(
    services: Annotated[ServiceContainer, Depends(container)],
    request: Request,
    file: Annotated[UploadFile, File(description="Android APK")],
    category: Annotated[str, Form()] = "banking",
    dynamic: Annotated[bool, Form()] = False,
) -> dict:
    normalized_category = _category(category)
    stored = await store_apk_upload(file, services.settings)
    try:
        async with request.app.state.apk_analysis_semaphore:
            analysis = await run_in_threadpool(
                services.apk_pipeline.analyze_uploaded,
                path=stored.path,
                original_name=stored.original_name,
                sha256=stored.sha256,
                size_bytes=stored.size_bytes,
                category=normalized_category,
                dynamic=dynamic,
            )
    finally:
        if not services.settings.retain_uploads:
            stored.path.unlink(missing_ok=True)
    result = analysis["result"]
    return {
        "analysis_id": analysis["id"],
        "metadata": {
            "package_name": result["extraction"]["app"].get("package_name"),
            "app_name": result["extraction"]["app"].get("app_label"),
            "overall_score": result["risk"]["overall_score"],
            "severity": result["risk"]["severity"],
            "fraud_delta_score": result["fraud_delta"]["score"],
            "data_origin": analysis["data_origin"],
        },
        "executive_summary": analysis["narrative"],
        "technical_details": result,
        "emitted_indicators": result["emitted_indicators"],
    }


@router.post("/seed-demo", deprecated=True)
def seed_demo_legacy(services: Annotated[ServiceContainer, Depends(container)]) -> dict:
    apk = services.apk_pipeline.analyze_demo("banking")
    return {
        "status": "demo_seeded",
        "data_origin": "synthetic",
        "apk_analysis_id": apk["id"],
        "emitted_indicators_count": len(apk["result"]["emitted_indicators"]),
        "malware_assessment": apk["result"]["malware_assessment"],
    }


@router.get("/report.pdf", deprecated=True)
def latest_report_legacy(services: Annotated[ServiceContainer, Depends(container)]) -> Response:
    return _pdf_response(services.analyses.latest_completed())


@router.get("/report/{analysis_id}", deprecated=True)
@router.get("/report/{analysis_id}.pdf", deprecated=True)
def report_legacy(
    analysis_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> Response:
    return _pdf_response(services.analyses.get(analysis_id))


def _pdf_response(analysis: dict) -> Response:
    if analysis["status"] != "completed":
        raise ValidationError("analysis_incomplete", "A PDF is available only for completed analyses")
    pdf = build_analysis_pdf(analysis)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="FraudShield-{analysis["id"]}.pdf"'},
    )
