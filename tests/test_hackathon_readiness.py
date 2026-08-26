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
        auth_mode="disabled",
        llm_provider="disabled",
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Test 1: Full 15-Section PDF Report Generation
# ---------------------------------------------------------------------------
def test_pdf_report_generation(client: TestClient, malicious_apk: bytes) -> None:
    upload_res = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("test.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert upload_res.status_code == 201
    analysis_id = upload_res.json()["id"]

    # Fetch report PDF
    pdf_res = client.get(f"/api/v1/apk-analyses/{analysis_id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000
    assert pdf_res.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Test 2: Upload Mode Complete Schema & Two-Stage Risk
# ---------------------------------------------------------------------------
def test_upload_mode_complete_schema(client: TestClient, malicious_apk: bytes) -> None:
    upload_res = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("test.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert upload_res.status_code == 201
    analysis_id = upload_res.json()["id"]

    get_res = client.get(f"/api/v1/apk-analyses/{analysis_id}")
    assert get_res.status_code == 200
    analysis = get_res.json()

    assert analysis["data_origin"] == "uploaded"
    result = analysis["result"]
    assert "risk" in result
    assert result["risk"]["static_score"] is not None
    assert result["risk"]["runtime_adjustment"] is not None
    assert result["risk"]["overall_score"] >= 60

    assert "brand_impersonation" in result
    assert "firebase_infrastructure" in result
    assert "frauddna" in result


# ---------------------------------------------------------------------------
# Test 3: Safe Synthetic DB Cleanup
# ---------------------------------------------------------------------------
def test_safe_synthetic_cleanup(client: TestClient, malicious_apk: bytes) -> None:
    upload_res = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("test.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert upload_res.status_code == 201
    uploaded_id = upload_res.json()["id"]

    # Verify list contains the uploaded record
    list_res = client.get("/api/v1/apk-analyses")
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    assert any(item["id"] == uploaded_id for item in items)
    assert all(item.get("data_origin") == "uploaded" for item in items)


# ---------------------------------------------------------------------------
# Test 4: Failure Resilience on Unreachable LLM / Engine
# ---------------------------------------------------------------------------
def test_failure_resilience_fallback(tmp_path: Path, malicious_apk: bytes) -> None:
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
        upload_res = test_client.post(
            "/api/v1/apk-analyses",
            files={"file": ("test.apk", malicious_apk, "application/vnd.android.package-archive")},
            data={"category": "banking", "dynamic": "false"},
        )
        assert upload_res.status_code == 201
        analysis_id = upload_res.json()["id"]

        get_res = test_client.get(f"/api/v1/apk-analyses/{analysis_id}")
        assert get_res.status_code == 200
        assert get_res.json()["status"] == "completed"
