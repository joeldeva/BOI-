from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from fraudshield.api.dependencies import container
from fraudshield.core.schemas import IndicatorCreate
from fraudshield.core.security import require_api_key
from fraudshield.services.container import ServiceContainer


router = APIRouter(
    prefix="/api/v1/indicators",
    tags=["Threat indicators"],
    dependencies=[Depends(require_api_key)],
)


@router.get("")
def list_indicators(
    services: Annotated[ServiceContainer, Depends(container)],
    q: Annotated[str | None, Query(max_length=200)] = None,
    type_filter: Annotated[str | None, Query(alias="type", max_length=64)] = None,
    severity: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    items, total = services.indicators.list(
        query=q,
        indicator_type=type_filter,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_api_key)])
def create_indicator(
    payload: IndicatorCreate,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    return services.indicators.upsert(
        indicator_type=payload.type,
        value=payload.value,
        severity=payload.severity.value,
        confidence=payload.confidence,
        description=payload.description,
        metadata=payload.metadata,
        context={"source": "manual_api"},
    )
