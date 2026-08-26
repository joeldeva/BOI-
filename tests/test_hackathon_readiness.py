from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from fraudshield.core.config import Settings
from fraudshield.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        environment="development",
        data_dir=tmp_path / "runtime",
        database_path=tmp_path / "runtime" / "test.db",
        upload_dir=tmp_path / "runtime" / "uploads",
        report_dir=tmp_path / "runtime" / "reports",
        demo_enabled=True,
        auth_mode="disabled",
        llm_provider="disabled",
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Test 1: Full 15-Section PDF Report Generation
# ---------------------------------------------------------------------------
def test_pdf_report_generation(client: TestClient) -> None:
    # Seed demo to create full analysis
    seed_res = client.post("/api/v1/demo/seed", json={"category": "banking"})
    assert seed_res.status_code == 201
    analysis_id = seed_res.json()["apk_analysis_id"]

    # Fetch report PDF
    pdf_res = client.get(f"/api/v1/apk-analyses/{analysis_id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000
    assert pdf_res.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Test 2: Demo Mode Complete Schema & Two-Stage Risk
# ---------------------------------------------------------------------------
def test_demo_mode_complete_schema(client: TestClient) -> None:
    seed_res = client.post("/api/v1/demo/seed", json={"category": "banking"})
    assert seed_res.status_code == 201
    analysis_id = seed_res.json()["apk_analysis_id"]

    get_res = client.get(f"/api/v1/apk-analyses/{analysis_id}")
    assert get_res.status_code == 200
    analysis = get_res.json()

    assert analysis["data_origin"] == "synthetic"
    result = analysis["result"]
    assert "risk" in result
    assert result["risk"]["static_score"] is not None
    assert result["risk"]["runtime_adjustment"] is not None
    assert result["risk"]["overall_score"] >= 60

    assert "brand_impersonation" in result
    assert result["brand_impersonation"]["target_bank_id"] == "bank_of_india"

    assert "firebase_infrastructure" in result
    assert result["firebase_infrastructure"]["project_id"] is not None

    assert "frauddna" in result
    assert "recovered_payloads" in result
    assert len(result["recovered_payloads"]) > 0


# ---------------------------------------------------------------------------
# Test 3: Safe Demo Reset
# ---------------------------------------------------------------------------
def test_safe_demo_reset(client: TestClient) -> None:
    # Seed demo
    seed_res = client.post("/api/v1/demo/seed", json={"category": "banking"})
    assert seed_res.status_code == 201

    # Reset demo
    reset_res = client.post("/api/v1/demo/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "demo_reset_completed"
    assert reset_res.json()["deleted_records"] >= 1

    # Verify list is empty of synthetic records
    list_res = client.get("/api/v1/apk-analyses")
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    assert all(item.get("data_origin") != "synthetic" for item in items)


# ---------------------------------------------------------------------------
# Test 4: Failure Resilience on Unreachable LLM / Engine
# ---------------------------------------------------------------------------
def test_failure_resilience_fallback(tmp_path: Path) -> None:
    settings = Settings(
        environment="development",
        data_dir=tmp_path / "runtime",
        database_path=tmp_path / "runtime" / "test.db",
        upload_dir=tmp_path / "runtime" / "uploads",
        report_dir=tmp_path / "runtime" / "reports",
        llm_provider="openai",
        llm_api_key="sk-invalid-key-for-test",
        llm_model="gpt-4o-mini",
        auth_mode="disabled",
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        # Even with invalid LLM key, analysis pipeline must complete deterministically
        seed_res = test_client.post("/api/v1/demo/seed", json={"category": "banking"})
        assert seed_res.status_code == 201
        analysis_id = seed_res.json()["apk_analysis_id"]

        get_res = test_client.get(f"/api/v1/apk-analyses/{analysis_id}")
        assert get_res.status_code == 200
        assert get_res.json()["status"] == "completed"
