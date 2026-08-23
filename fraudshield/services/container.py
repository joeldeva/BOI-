from __future__ import annotations

from dataclasses import dataclass

from fraudshield.core.config import Settings
from fraudshield.core.database import Database
from fraudshield.core.repository import (
    AnalysisRepository,
    AuditRepository,
    IndicatorRepository,
    JobRepository,
)
from fraudshield.core.storage import ArtifactStore, build_artifact_store
from fraudshield.deceptiscope.pipeline import APKAnalysisPipeline


@dataclass(slots=True)
class ServiceContainer:
    settings: Settings
    db: Database
    analyses: AnalysisRepository
    audit: AuditRepository
    indicators: IndicatorRepository
    jobs: JobRepository
    artifacts: ArtifactStore
    apk_pipeline: APKAnalysisPipeline

    @classmethod
    def build(cls, settings: Settings) -> "ServiceContainer":
        db = Database(
            settings.effective_database_url,
            pool_min_size=settings.database_pool_min_size,
            pool_max_size=settings.database_pool_max_size,
        )
        db.initialize()
        analyses = AnalysisRepository(db)
        audit = AuditRepository(
            db,
            settings.audit_hmac_key,
            key_id=settings.audit_hmac_key_id,
            previous_keys=settings.audit_keyring,
        )
        indicators = IndicatorRepository(db)
        jobs = JobRepository(db)
        artifacts = build_artifact_store(settings)
        return cls(
            settings=settings,
            db=db,
            analyses=analyses,
            audit=audit,
            indicators=indicators,
            jobs=jobs,
            artifacts=artifacts,
            apk_pipeline=APKAnalysisPipeline(settings, analyses, indicators),
        )
