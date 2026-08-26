from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(str, Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class AnalysisStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody


class IndicatorCreate(StrictModel):
    type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=2048)
    severity: Severity
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    description: str = Field(default="", max_length=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MethodInterpretationRequest(StrictModel):
    methods: list[dict[str, Any]] = Field(min_length=1, max_length=20)

    @field_validator("methods")
    @classmethod
    def cap_method_source(cls, methods: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for method in methods:
            source = str(method.get("source", ""))
            if len(source) > 12_000:
                raise ValueError("each method source must be at most 12,000 characters")
        return methods
