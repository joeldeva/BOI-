from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from fraudshield.api.dependencies import container
from fraudshield.core.schemas import DemoSeedRequest
from fraudshield.core.security import require_api_key
from fraudshield.services.container import ServiceContainer


router = APIRouter(
    prefix="/api/v1/demo",
    tags=["Reproducible demo"],
    dependencies=[Depends(require_api_key)],
)


@router.post("/seed", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_api_key)])
def seed_demo(
    payload: DemoSeedRequest,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    apk_analysis = services.apk_pipeline.analyze_demo(payload.category)
    result = apk_analysis["result"]
    return {
        "status": "demo_seeded",
        "data_origin": "synthetic",
        "apk_analysis_id": apk_analysis["id"],
        "apk_risk": {
            "score": apk_analysis["overall_score"],
            "severity": apk_analysis["severity"],
        },
        "malware_assessment": result["malware_assessment"],
        "engine_summary": result["engine_analysis"]["summary"],
        "notice": "This is explicit synthetic APK evidence; it is never represented as an uploaded sample.",
    }
