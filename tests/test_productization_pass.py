from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from fraudshield.core.config import Settings
from fraudshield.core.database import Database
from fraudshield.core.repository import AnalysisRepository, IndicatorRepository
from fraudshield.deceptiscope import dynamic as dynamic_module
from fraudshield.deceptiscope.engines import MultiEngineAnalyzer
from fraudshield.deceptiscope.lineage.markers import SyntheticMarkerManager
from fraudshield.deceptiscope.pipeline import APKAnalysisPipeline
from fraudshield.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        environment="development",
        data_dir=tmp_path / "runtime",
        database_path=tmp_path / "runtime" / "test.db",
        upload_dir=tmp_path / "runtime" / "uploads",
        report_dir=tmp_path / "runtime" / "reports",
        auth_mode="disabled",
        llm_provider="disabled",
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


# 1. /api/v1/demo/apk-analysis does not exist
def test_demo_apk_analysis_route_does_not_exist(client: TestClient) -> None:
    res = client.post("/api/v1/demo/apk-analysis", json={})
    assert res.status_code == 404


# 2. /api/v1/demo/seed does not exist
def test_demo_seed_route_does_not_exist(client: TestClient) -> None:
    res = client.post("/api/v1/demo/seed", json={"category": "banking"})
    assert res.status_code == 404


# 3. legacy /seed-demo does not exist
def test_legacy_seed_demo_route_does_not_exist(client: TestClient) -> None:
    res = client.post("/seed-demo")
    assert res.status_code == 404


# 4. no production demo router mounted
def test_no_production_demo_router_mounted(client: TestClient) -> None:
    routes: list[str] = []
    for route in client.app.routes:
        if hasattr(route, "path"):
            routes.append(getattr(route, "path"))
        if hasattr(route, "routes"):
            for sub_route in getattr(route, "routes"):
                if hasattr(sub_route, "path"):
                    routes.append(getattr(sub_route, "path"))
    assert not any("/demo" in r for r in routes)
    assert not any("seed-demo" in r for r in routes)


# 5. analyze_demo absent from APKAnalysisPipeline
def test_analyze_demo_absent_from_pipeline(settings: Settings, tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    db.initialize()
    pipeline = APKAnalysisPipeline(
        settings=settings,
        analyses=AnalysisRepository(db),
        indicators=IndicatorRepository(db),
    )
    assert not hasattr(pipeline, "analyze_demo")
    assert not hasattr(pipeline, "_complete_demo")


# 6. demo_result absent from MultiEngineAnalyzer
def test_demo_result_absent_from_engines(settings: Settings) -> None:
    analyzer = MultiEngineAnalyzer(settings)
    assert not hasattr(analyzer, "demo_result")


# 7. frontend has no seedDemo API
def test_frontend_has_no_seed_demo_api() -> None:
    api_ts_path = Path("frontend/src/services/api.ts")
    if api_ts_path.exists():
        content = api_ts_path.read_text(encoding="utf-8")
        assert "seedDemo(" not in content
        assert "DemoSeedResponse" not in content


# 8. empty history shows no fabricated data
def test_empty_history_shows_no_fabricated_data(client: TestClient) -> None:
    res = client.get("/api/v1/apk-analyses")
    assert res.status_code == 200
    data = res.json()
    assert data["items"] == []
    assert data["total"] == 0


# 9. uploaded analysis appears in history with required fields
def test_uploaded_analysis_appears_in_history(client: TestClient, malicious_apk: bytes) -> None:
    upload_res = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("malware_sample.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert upload_res.status_code == 201
    analysis_id = upload_res.json()["id"]

    list_res = client.get("/api/v1/apk-analyses")
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    assert len(items) == 1

    entry = items[0]
    assert entry["id"] == analysis_id
    assert entry["analysis_id"] == analysis_id
    assert entry["file_name"] == "malware_sample.apk"
    assert entry["status"] == "completed"
    assert entry["sha256"] is not None
    assert entry["category"] == "banking"
    assert entry["created_at"] is not None
    assert entry["overall_score"] is not None
    assert entry["severity"] is not None
    assert entry["confidence"] is not None
    assert entry["analysis_quality"] is not None
    assert "package_name" in entry
    assert "static_score" in entry
    assert "runtime_adjustment" in entry


# 10. fetching historical analysis returns stored result without rerunning pipeline
def test_fetching_historical_analysis_does_not_rerun(client: TestClient, malicious_apk: bytes) -> None:
    upload_res = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("sample.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert upload_res.status_code == 201
    analysis_id = upload_res.json()["id"]

    # Patch analyze_uploaded to prove it is never called when retrieving historical analysis
    with patch("fraudshield.deceptiscope.pipeline.APKAnalysisPipeline.analyze_uploaded") as mock_run:
        get_res = client.get(f"/api/v1/apk-analyses/{analysis_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == analysis_id
        assert get_res.json()["status"] == "completed"
        mock_run.assert_not_called()


# 11. synthetic cleanup does not delete uploaded analysis
# 12. synthetic-only IOC is removed
# 13. IOC shared by uploaded + old synthetic records survives
def test_synthetic_cleanup_behavior(tmp_path: Path) -> None:
    db = Database(tmp_path / "test_cleanup.db")
    db.initialize()
    repo = AnalysisRepository(db)
    ind_repo = IndicatorRepository(db)

    # 1. Create uploaded analysis and associate IOC A and IOC Shared
    up_analysis = repo.create(
        file_name="real.apk",
        sha256="1" * 64,
        size_bytes=1000,
        category="banking",
        data_origin="uploaded",
    )
    repo.complete(
        up_analysis["id"],
        result={"risk": {"overall_score": 80, "severity": "HIGH", "confidence": 0.9}},
        narrative="Uploaded real analysis",
        overall_score=80,
        severity="HIGH",
        confidence=0.9,
        analysis_quality="static-only",
    )

    ind_shared = ind_repo.upsert(
        indicator_type="domain",
        value="shared-c2.example.com",
        severity="HIGH",
        confidence=0.9,
        source_analysis_id=up_analysis["id"],
    )
    ind_uploaded_only = ind_repo.upsert(
        indicator_type="domain",
        value="legit-c2.example.com",
        severity="HIGH",
        confidence=0.9,
        source_analysis_id=up_analysis["id"],
    )

    # 2. Insert synthetic analysis into DB directly (simulating pre-migration state)
    with db.transaction() as conn:
        conn.execute(
            """
            INSERT INTO analyses(id, status, data_origin, file_name, sha256, size_bytes, category, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("synth_1", "completed", "synthetic", "demo.apk", "2" * 64, 0, "banking", "2026-01-01T00:00:00Z"),
        )

    # Associate IOC Shared and IOC Synthetic-Only with synthetic analysis
    with db.transaction() as conn:
        conn.execute(
            """
            INSERT INTO indicator_sightings(id, indicator_id, source_analysis_id, seen_at)
            VALUES (?, ?, ?, ?)
            """,
            ("s_sight_1", ind_shared["id"], "synth_1", "2026-01-01T00:00:00Z"),
        )

    ind_synth_only = ind_repo.upsert(
        indicator_type="domain",
        value="synthetic-only-c2.example.com",
        severity="HIGH",
        confidence=0.9,
        source_analysis_id="synth_1",
    )

    # 3. Run cleanup
    cleanup_results = repo.cleanup_synthetic_records()
    assert cleanup_results["deleted_analyses"] == 1
    assert cleanup_results["deleted_sightings"] >= 1
    assert cleanup_results["deleted_indicators"] >= 1

    # Verify:
    # 11. Uploaded analysis still exists
    uploaded_check = repo.get(up_analysis["id"])
    assert uploaded_check["id"] == up_analysis["id"]
    assert uploaded_check["data_origin"] == "uploaded"

    # Synthetic analysis is deleted
    with pytest.raises(Exception):
        repo.get("synth_1")

    # 12. Synthetic-only IOC is removed
    with pytest.raises(Exception):
        ind_repo.get(ind_synth_only["id"])

    # 13. IOC shared by uploaded + synthetic survives
    shared_check = ind_repo.get(ind_shared["id"])
    assert shared_check["id"] == ind_shared["id"]

    # Uploaded-only IOC survives
    up_only_check = ind_repo.get(ind_uploaded_only["id"])
    assert up_only_check["id"] == ind_uploaded_only["id"]


# 14. fixed BOI-TEST production marker is absent from dynamic module
def test_fixed_boi_test_marker_absent() -> None:
    assert not hasattr(dynamic_module, "SYNTHETIC_OTP_MARKER")


# 15. per-run markers remain unique
def test_per_run_markers_remain_unique() -> None:
    mgr = SyntheticMarkerManager()
    markers = [mgr.create_otp_marker().value for _ in range(20)]
    assert len(set(markers)) == 20
    assert all(m.startswith("DS-TEST-OTP-") for m in markers)
