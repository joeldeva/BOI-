from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, Form, Header, Query, Request, UploadFile, status

from fraudshield.api.dependencies import container
from fraudshield.api.routes.analyses import _category
from fraudshield.core.errors import ConflictError, ValidationError
from fraudshield.core.security import require_api_key
from fraudshield.deceptiscope.validator import store_apk_upload
from fraudshield.services.container import ServiceContainer


router = APIRouter(
    prefix="/api/v1/jobs",
    tags=["Durable jobs"],
    dependencies=[Depends(require_api_key)],
)


def _public_job(job: dict) -> dict:
    public = dict(job)
    payload = dict(public.get("payload") or {})
    payload.pop("artifact_path", None)
    payload.pop("artifact_uri", None)
    public["payload"] = payload
    public["links"] = {"self": f"/api/v1/jobs/{job['id']}"}
    return public


def _actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return principal.subject if principal else "unknown"


@router.post("/apk-analysis", status_code=status.HTTP_202_ACCEPTED)
async def queue_apk_analysis(
    request: Request,
    services: Annotated[ServiceContainer, Depends(container)],
    file: Annotated[UploadFile, File(description="Android APK stored for an isolated worker")],
    category: Annotated[str, Form()] = "banking",
    dynamic: Annotated[bool, Form()] = False,
    priority: Annotated[int, Form(ge=0, le=1000)] = 100,
    max_attempts: Annotated[int, Form(ge=1, le=20)] = 3,
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            min_length=8,
            max_length=256,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
    ] = None,
) -> dict:
    normalized_category = _category(category)
    stored = await store_apk_upload(file, services.settings)
    try:
        requested_payload = {
            "original_name": stored.original_name,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "category": normalized_category,
            "dynamic": bool(dynamic),
        }
        if idempotency_key:
            existing = services.jobs.find_by_idempotency_key(idempotency_key)
            if existing is not None:
                comparable = {
                    key: existing["payload"].get(key)
                    for key in requested_payload
                }
                if existing["kind"] != "apk_analysis" or comparable != requested_payload:
                    raise ConflictError(
                        "idempotency_conflict",
                        "Idempotency-Key was already used for a different request",
                    )
                return _public_job(existing)
        artifact = services.artifacts.put_file(
            stored.path,
            namespace="apk-jobs",
            object_name=f"{stored.sha256}.apk",
            sha256=stored.sha256,
            content_type="application/vnd.android.package-archive",
        )
        payload = {"artifact_uri": artifact.uri, **requested_payload}
        job, created = services.jobs.enqueue(
            kind="apk_analysis",
            payload=payload,
            created_by=_actor(request),
            priority=priority,
            max_attempts=max_attempts,
            idempotency_key=idempotency_key,
        )
        if not created and job["status"] not in {"queued", "running"}:
            services.artifacts.delete(artifact.uri)
    except Exception:
        if "artifact" in locals():
            services.artifacts.delete(artifact.uri)
        raise
    finally:
        stored.path.unlink(missing_ok=True)
    return _public_job(job)


@router.get("")
def list_jobs(
    services: Annotated[ServiceContainer, Depends(container)],
    status_filter: Annotated[
        Literal["queued", "running", "completed", "failed", "cancelled"] | None,
        Query(alias="status"),
    ] = None,
    created_by: Annotated[str | None, Query(max_length=256)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    items, total = services.jobs.list(
        status=status_filter,
        created_by=created_by,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [_public_job(item) for item in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{job_id}")
def get_job(
    job_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    return _public_job(services.jobs.get(job_id))


@router.post("/{job_id}/cancel")
def cancel_job(
    job_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    job = services.jobs.get(job_id)
    cancelled = services.jobs.cancel(job_id)
    if job["kind"] == "apk_analysis" and not services.settings.retain_uploads:
        artifact_uri = str(job["payload"].get("artifact_uri", ""))
        if artifact_uri:
            services.artifacts.delete(artifact_uri)
    return _public_job(cancelled)


@router.post("/{job_id}/retry")
def retry_job(
    job_id: str,
    services: Annotated[ServiceContainer, Depends(container)],
) -> dict:
    job = services.jobs.get(job_id)
    if job["kind"] == "apk_analysis":
        artifact_uri = str(job["payload"].get("artifact_uri", ""))
        if not artifact_uri or not services.artifacts.exists(artifact_uri):
            raise ValidationError(
                "job_artifact_unavailable",
                "The original APK is no longer retained; submit a new job",
            )
    return _public_job(services.jobs.retry(job_id))
