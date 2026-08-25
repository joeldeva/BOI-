from __future__ import annotations


def test_health_and_capabilities(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.headers["x-content-type-options"] == "nosniff"
    readiness = client.get("/health/ready")
    assert readiness.status_code == 200
    assert readiness.json()["ready"] is True
    capabilities = client.get("/api/v1/system/capabilities").json()
    assert capabilities["apk_only_product"] is True
    assert capabilities["llm"]["controls_risk_score"] is False
    assert capabilities["ai_experiments"]["plan_limit"] == 3
    assert capabilities["ai_experiments"]["execution_mode"] == "planned-only"
    assert {item["experiment_type"] for item in capabilities["ai_experiments"]["catalog"]} >= {
        "SYNTHETIC_SMS",
        "LOGCAT_CAPTURE",
        "PACKAGE_STATE_CAPTURE",
    }
    assert capabilities["multi_engine"]["binary_upload_policy"] == "disabled-for-public-services"
    assert {item["id"] for item in capabilities["multi_engine"]["engines"]} >= {
        "androguard",
        "apkid",
        "yara",
        "apksigner",
        "quark",
        "mobsf",
        "virustotal",
        "malwarebazaar",
    }


def test_invalid_apk_returns_validation_error(client) -> None:
    response = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("fake.apk", b"not an apk", "application/vnd.android.package-archive")},
        data={"category": "banking"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_apk_magic"
    listing = client.get("/api/v1/apk-analyses", params={"status": "failed"}).json()
    assert listing["total"] == 1
    assert "result" not in listing["items"][0]


def test_apk_analysis_persistence_pdf_and_multi_engine_contract(client, malicious_apk: bytes) -> None:
    response = client.post(
        "/api/v1/apk-analyses",
        files={"file": ("evidence.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert response.status_code == 201, response.text
    analysis = response.json()
    result = analysis["result"]
    assert analysis["status"] == "completed"
    assert analysis["severity"] == "CRITICAL"
    assert result["schema_version"] == "3.0"
    assert result["malware_assessment"]["verdict"] in {"HIGH_RISK", "KNOWN_MALICIOUS"}
    assert result["malware_assessment"]["legitimacy"] == "not-established"
    assert result["malware_assessment"]["safe_to_install"] is False
    assert result["engine_analysis"]["policy"]["public_binary_uploads"] is False
    assert result["engine_analysis"]["policy"]["external_hash_lookups"] is False
    assert result["ai_investigation"]["status"] == "disabled"
    assert result["ai_investigation"]["evidence_count"] > 0
    assert result["ai_investigation"]["controls_risk_score"] is False
    assert result["runtime_evidence"] == []
    assert result["experiment_results"] == []
    assert result["narrative_metadata"]["llm_controls_score"] is False
    assert any(item["type"] == "apk_sha256" for item in result["emitted_indicators"])
    fetched = client.get(f"/api/v1/apk-analyses/{analysis['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["sha256"] == analysis["sha256"]
    report = client.get(f"/api/v1/apk-analyses/{analysis['id']}/report.pdf")
    assert report.status_code == 200
    assert report.content.startswith(b"%PDF")


def test_apk_demo_is_explicit_and_reproducible(client) -> None:
    first = client.post("/api/v1/demo/seed", json={"category": "banking"})
    second = client.post("/api/v1/demo/seed", json={"category": "banking"})
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    one = first.json()
    two = second.json()
    assert one["data_origin"] == "synthetic"
    assert one["apk_risk"] == two["apk_risk"]
    assert one["malware_assessment"]["safe_to_install"] is False
    analysis = client.get(f"/api/v1/apk-analyses/{one['apk_analysis_id']}")
    assert analysis.status_code == 200
    assert analysis.json()["data_origin"] == "synthetic"


def test_legacy_apk_only_contract_uses_persisted_results(client) -> None:
    seeded = client.post("/seed-demo")
    assert seeded.status_code == 200
    analysis_id = seeded.json()["apk_analysis_id"]
    report = client.get(f"/report/{analysis_id}.pdf")
    assert report.status_code == 200
    assert report.content.startswith(b"%PDF")
    assert client.get("/graph").status_code == 404
    assert client.get("/account/example").status_code == 404


def test_legacy_apk_endpoint_analyzes_the_uploaded_file(client, malicious_apk: bytes) -> None:
    response = client.post(
        "/analyze-apk",
        files={"file": ("legacy.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["metadata"]["data_origin"] == "uploaded"
    assert payload["metadata"]["overall_score"] >= 75
    assert payload["technical_details"]["extraction"]["file"]["name"] == "legacy.apk"


def test_removed_transaction_graph_routes_do_not_exist(client) -> None:
    for method, path in (
        ("post", "/api/v1/jobs/graph-analysis"),
        ("post", "/api/v1/transaction-datasets"),
        ("get", "/api/v1/graph-runs/graph_example"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code in {404, 405}


def test_early_content_length_guard(client) -> None:
    response = client.post(
        "/api/v1/apk-analyses",
        headers={"Content-Length": str(20 * 1024 * 1024)},
        content=b"x",
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_manual_indicator_validation(client) -> None:
    response = client.post(
        "/api/v1/indicators",
        json={
            "type": "ip",
            "value": "999.1.1.1",
            "severity": "HIGH",
            "confidence": 0.8,
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_ip"
