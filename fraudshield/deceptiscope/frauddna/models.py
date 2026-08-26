from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class FraudDNAFingerprint(BaseModel):
    """Normalized cross-sample fingerprint for Android banking malware campaign tracking."""

    model_config = ConfigDict(extra="forbid")

    apk_sha256: str = Field(min_length=64, max_length=64)
    app_identity: str = Field(min_length=64, max_length=64)
    package_name: str
    app_label: str = ""
    signer_fingerprints: list[str] = Field(default_factory=list)
    icon_phash: str | None = None
    dex_fingerprints: list[str] = Field(default_factory=list)
    dex_fuzzy_hash: str | None = None
    behavior_signatures: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    banking_capabilities: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    firebase_project_ids: list[str] = Field(default_factory=list)
    recovered_payload_hashes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ComponentSimilarity(BaseModel):
    """Detailed similarity breakdown across all FraudDNA dimensions."""

    model_config = ConfigDict(extra="forbid")

    signer_match: bool = False
    package_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    dex_similarity: float | None = Field(ge=0.0, le=1.0, default=None)
    behavior_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    icon_similarity: float | None = Field(ge=0.0, le=1.0, default=None)
    infrastructure_overlap: float = Field(ge=0.0, le=1.0, default=0.0)
    firebase_overlap: bool = False
    payload_overlap: bool = False
    overall_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    match_reasons: list[str] = Field(default_factory=list)


class RelatedSample(BaseModel):
    """Represents another APK correlated via FraudDNA fingerprint analysis."""

    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(min_length=64, max_length=64)
    similarity: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    campaign_id: str | None = None
    app_label: str | None = None
    package_name: str | None = None


class Campaign(BaseModel):
    """Represents a correlated banking malware campaign or threat actor family."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(pattern=r"^(CAMP-\d{3}|F-\d{3})$")
    name: str
    member_sha256s: list[str] = Field(default_factory=list)
    primary_signatures: list[str] = Field(default_factory=list)
    shared_infrastructure: list[str] = Field(default_factory=list)
    shared_firebase_projects: list[str] = Field(default_factory=list)
    shared_signer_fingerprints: list[str] = Field(default_factory=list)
    created_at: str | None = None
