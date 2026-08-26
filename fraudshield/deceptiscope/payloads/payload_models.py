from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class PayloadType(str, Enum):
    DEX = "DEX"
    JAR = "JAR"
    UNKNOWN = "UNKNOWN"


class PayloadAnalysisStatus(str, Enum):
    ANALYZED = "ANALYZED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_MAGIC = "INVALID_MAGIC"
    OVERSIZED = "OVERSIZED"
    FAILED = "FAILED"


class RecoveredPayload(BaseModel):
    """Represents a dynamically loaded DEX/JAR payload recovered from sandbox execution."""

    model_config = ConfigDict(extra="forbid")

    payload_id: str = Field(pattern=r"^PAYLOAD-\d{3}$")
    parent_sample_sha256: str = Field(min_length=64, max_length=64)
    sha256: str = Field(min_length=64, max_length=64)
    payload_type: PayloadType = PayloadType.DEX
    size_bytes: int = Field(ge=0)
    source: str = "FILE_RECOVERED"  # FILE_RECOVERED, MEMORY_DUMP
    loader: str = "DexClassLoader"  # DexClassLoader, InMemoryDexClassLoader, PathClassLoader, DexFile
    runtime_evidence_id: str | None = None
    storage_reference: str | None = None
    analysis_status: PayloadAnalysisStatus = PayloadAnalysisStatus.ANALYZED
    extracted_capabilities: list[str] = Field(default_factory=list)
    method_level_evidence: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
