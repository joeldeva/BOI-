from __future__ import annotations

from fastapi import Request

from fraudshield.services.container import ServiceContainer


def container(request: Request) -> ServiceContainer:
    return request.app.state.container

