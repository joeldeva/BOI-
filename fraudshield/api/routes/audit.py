from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from fraudshield.api.dependencies import container
from fraudshield.core.security import require_api_key
from fraudshield.services.container import ServiceContainer


router = APIRouter(
    prefix="/api/v1/audit-events",
    tags=["Security audit"],
    dependencies=[Depends(require_api_key)],
)


@router.get("")
def list_audit_events(
    services: Annotated[ServiceContainer, Depends(container)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    actor_id: Annotated[str | None, Query(max_length=256)] = None,
    request_id: Annotated[str | None, Query(max_length=128)] = None,
) -> dict:
    items, total = services.audit.list(
        limit=limit,
        offset=offset,
        actor_id=actor_id,
        request_id=request_id,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/verify")
def verify_audit_chain(
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    return services.audit.verify_chain()


@router.get("/{event_id}")
def get_audit_event(
    event_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    return services.audit.get(event_id)
