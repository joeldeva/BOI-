from __future__ import annotations

from fraudshield.core.database import Database
from fraudshield.core.repository import AnalysisRepository, IndicatorRepository


def test_indicator_dedup_and_sightings(settings) -> None:
    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    analyses = AnalysisRepository(database)
    indicators = IndicatorRepository(database)
    analysis = analyses.create(
        file_name="one.apk",
        sha256="a" * 64,
        size_bytes=100,
        category="banking",
        data_origin="uploaded",
    )
    first = indicators.upsert(
        indicator_type="domain",
        value="C2.Example.COM.",
        severity="HIGH",
        confidence=0.7,
        source_analysis_id=analysis["id"],
    )
    second = indicators.upsert(
        indicator_type="domain",
        value="c2.example.com",
        severity="CRITICAL",
        confidence=0.9,
        source_analysis_id=analysis["id"],
    )
    assert first["id"] == second["id"]
    assert second["normalized_value"] == "c2.example.com"
    assert second["severity"] == "CRITICAL"
    assert second["sightings_count"] == 1

