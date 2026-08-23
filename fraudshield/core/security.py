from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import Header, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
KNOWN_ROLES = frozenset({"viewer", "analyst", "investigator", "auditor", "admin"})
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read"}),
    "analyst": frozenset({"read", "analysis:run"}),
    "investigator": frozenset({"read", "analysis:run", "indicator:write"}),
    "auditor": frozenset({"read", "audit:read"}),
    "admin": frozenset({"*"}),
}


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    roles: tuple[str, ...]
    auth_type: str
    claims: dict[str, Any]

    def permits(self, permission: str) -> bool:
        return any(
            "*" in ROLE_PERMISSIONS.get(role, frozenset())
            or permission in ROLE_PERMISSIONS.get(role, frozenset())
            for role in self.roles
        )


def safe_filename(value: str, fallback: str) -> str:
    name = Path(value or fallback).name
    name = SAFE_NAME.sub("_", name).strip("._")
    return name[:180] or fallback


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _claim(claims: dict[str, Any], dotted_name: str) -> Any:
    value: Any = claims
    for part in dotted_name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _roles(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        candidates = re.split(r"[\s,]+", value)
    elif isinstance(value, (list, tuple, set)):
        candidates = [str(item) for item in value]
    else:
        candidates = []
    normalized: set[str] = set()
    for candidate in candidates:
        role = candidate.strip().lower()
        for prefix in ("fraudshield:", "fraudshield_", "fraudshield-"):
            if role.startswith(prefix):
                role = role[len(prefix) :]
        if role in KNOWN_ROLES:
            normalized.add(role)
    return tuple(sorted(normalized))


_jwk_clients: dict[str, Any] = {}
_jwk_lock = threading.Lock()


def _decode_oidc_token(token: str, settings: Any) -> dict[str, Any]:
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC validation dependency is unavailable",
        ) from exc
    with _jwk_lock:
        client = _jwk_clients.get(settings.oidc_jwks_url)
        if client is None:
            client = PyJWKClient(
                settings.oidc_jwks_url,
                cache_keys=True,
                cache_jwk_set=True,
                lifespan=300,
                timeout=5,
            )
            _jwk_clients[settings.oidc_jwks_url] = client
    try:
        signing_key = client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=list(settings.oidc_algorithms),
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            leeway=settings.oidc_clock_skew_seconds,
            options={
                "require": [
                    "exp",
                    "iat",
                    "iss",
                    "aud",
                    settings.oidc_subject_claim,
                ]
            },
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def authenticate_request(
    request: Request,
    *,
    authorization: str | None,
    x_api_key: str | None,
) -> Principal:
    settings = request.app.state.settings
    if settings.auth_mode == "disabled":
        principal = Principal(
            subject="local-development",
            roles=("admin",),
            auth_type="disabled",
            claims={},
        )
    elif settings.auth_mode == "api_key":
        if not settings.api_key:
            principal = Principal(
                subject="local-development",
                roles=("admin",),
                auth_type="disabled",
                claims={},
            )
        elif not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key):
            request.state.auth_failure = "invalid_api_key"
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        else:
            principal = Principal(
                subject="service-api-key",
                roles=("admin",),
                auth_type="api_key",
                claims={},
            )
    else:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            request.state.auth_failure = "missing_bearer_token"
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer access token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        claims = await run_in_threadpool(_decode_oidc_token, token, settings)
        subject = _claim(claims, settings.oidc_subject_claim)
        roles = _roles(_claim(claims, settings.oidc_roles_claim))
        if not subject or not roles:
            request.state.auth_failure = "missing_subject_or_role"
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not grant a FraudShield role",
            )
        principal = Principal(
            subject=str(subject)[:256],
            roles=roles,
            auth_type="oidc",
            claims={
                "iss": claims.get("iss"),
                "aud": claims.get("aud"),
                "jti": claims.get("jti"),
            },
        )
    request.state.principal = principal
    return principal


def permission_for_request(request: Request) -> str:
    method = request.method.upper()
    path = request.url.path
    if path.startswith("/api/v1/audit-events"):
        return "audit:read"
    if "/demo/" in path or path in {"/seed-demo"}:
        return "demo:run"
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    if path.startswith("/api/v1/jobs"):
        if path.endswith(("/cancel", "/retry")):
            return "admin"
        return "analysis:run"
    if path == "/api/v1/method-review":
        return "analysis:run"
    if path.startswith("/api/v1/indicators"):
        return "indicator:write"
    if path.startswith(("/api/v1/apk-analyses", "/api/v1/deceptiscope", "/analyze-apk")):
        return "analysis:run"
    return "admin"


def require_inline_analysis(request: Request) -> None:
    if not request.app.state.settings.inline_analysis_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Inline analysis is disabled; submit work through /api/v1/jobs",
        )


async def require_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> Principal:
    """Backward-compatible dependency name; now performs OIDC/API-key auth and RBAC."""

    principal = await authenticate_request(
        request,
        authorization=authorization,
        x_api_key=x_api_key,
    )
    permission = permission_for_request(request)
    if permission == "demo:run" and not request.app.state.settings.demo_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo routes are disabled")
    if not principal.permits(permission):
        request.state.auth_failure = f"missing_permission:{permission}"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role does not grant permission: {permission}",
        )
    return principal


def require_roles(*allowed_roles: str) -> Callable[..., Awaitable[Principal]]:
    allowed = frozenset(allowed_roles)

    async def dependency(
        request: Request,
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ) -> Principal:
        principal = await authenticate_request(
            request,
            authorization=authorization,
            x_api_key=x_api_key,
        )
        if not allowed.intersection(principal.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role is not permitted for this operation",
            )
        return principal

    return dependency
