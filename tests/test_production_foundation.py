from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from fraudshield.core import security
from fraudshield.core.config import Settings
from fraudshield.main import create_app
from fraudshield.worker import DurableWorker


def test_complete_production_configuration_is_accepted(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    configuration = Settings(
        environment="production",
        data_dir=runtime,
        database_path=runtime / "unused.db",
        database_url=(
            "postgresql://fraudshield:secret@postgres/fraudshield?sslmode=verify-full"
        ),
        upload_dir=runtime / "uploads",
        report_dir=runtime / "reports",
        storage_backend="s3",
        s3_bucket="bank-fraudshield-evidence",
        s3_kms_key_id="alias/fraudshield-evidence",
        auth_mode="oidc",
        oidc_issuer="https://id.bank.example/realms/staff",
        oidc_audience="fraudshield-api",
        oidc_jwks_url="https://id.bank.example/realms/staff/protocol/openid-connect/certs",
        trusted_hosts=("fraudshield.bank.example",),
        cors_origins=("https://fraudshield.bank.example",),
        docs_enabled=False,
        legacy_api_enabled=False,
        inline_analysis_enabled=False,
        audit_hmac_key="a" * 32,
        metrics_enabled=True,
    )
    configuration.validate()


def test_operational_endpoints_allow_ip_host_but_application_routes_do_not(
    settings: Settings,
) -> None:
    restricted = settings.with_overrides(trusted_hosts=("fraudshield.bank.example",))
    with TestClient(create_app(restricted), base_url="http://10.0.0.7") as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200
        assert client.get("/api/v1/system/capabilities").status_code == 400


def test_oidc_role_permissions_are_enforced(settings: Settings, monkeypatch) -> None:
    def fake_decode(token: str, configured: Settings) -> dict:
        role = "viewer" if token == "viewer-token" else "auditor"
        return {
            "sub": f"{role}-user",
            "roles": [role],
            "iss": configured.oidc_issuer,
            "aud": configured.oidc_audience,
            "exp": 4_000_000_000,
            "iat": 1_700_000_000,
        }

    monkeypatch.setattr("fraudshield.core.security._decode_oidc_token", fake_decode)
    oidc = settings.with_overrides(
        auth_mode="oidc",
        oidc_issuer="https://id.example.test",
        oidc_audience="fraudshield-api",
        oidc_jwks_url="https://id.example.test/jwks.json",
    )
    with TestClient(create_app(oidc)) as client:
        viewer_headers = {"Authorization": "Bearer viewer-token"}
        assert client.get("/api/v1/system/capabilities", headers=viewer_headers).status_code == 200
        denied = client.post(
            "/api/v1/indicators",
            headers=viewer_headers,
            json={
                "type": "domain",
                "value": "blocked.example.test",
                "severity": "HIGH",
                "confidence": 0.9,
            },
        )
        assert denied.status_code == 403
        assert client.get("/api/v1/audit-events", headers=viewer_headers).status_code == 403
        auditor = client.get(
            "/api/v1/audit-events",
            headers={"Authorization": "Bearer auditor-token"},
        )
        assert auditor.status_code == 200
        assert auditor.json()["total"] >= 3


def test_oidc_decoder_verifies_signature_issuer_audience_and_time(settings: Settings) -> None:
    jwt = pytest.importorskip("jwt")
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    configured = settings.with_overrides(
        auth_mode="oidc",
        oidc_issuer="https://id.example.test",
        oidc_audience="fraudshield-api",
        oidc_jwks_url="https://id.example.test/jwks.json",
    )
    token = jwt.encode(
        {
            "sub": "analyst-123",
            "roles": ["analyst"],
            "iss": configured.oidc_issuer,
            "aud": configured.oidc_audience,
            "iat": 1_700_000_000,
            "exp": 4_000_000_000,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    class FakeJwkClient:
        def get_signing_key_from_jwt(self, encoded: str):
            assert encoded == token
            return SimpleNamespace(key=private_key.public_key())

    security._jwk_clients[configured.oidc_jwks_url] = FakeJwkClient()
    try:
        claims = security._decode_oidc_token(token, configured)
        assert claims["sub"] == "analyst-123"
        with pytest.raises(HTTPException) as rejected:
            security._decode_oidc_token(
                token,
                configured.with_overrides(oidc_audience="different-api"),
            )
        assert rejected.value.status_code == 401
    finally:
        security._jwk_clients.pop(configured.oidc_jwks_url, None)


def test_audit_chain_detects_database_tampering(settings: Settings) -> None:
    secured = settings.with_overrides(api_key="test-secret", audit_hmac_key="audit-key-" * 4)
    with TestClient(create_app(secured)) as client:
        headers = {"X-API-Key": "test-secret"}
        assert client.get("/api/v1/system/capabilities", headers=headers).status_code == 200
        verified = client.get("/api/v1/audit-events/verify", headers=headers)
        assert verified.status_code == 200
        assert verified.json()["valid"] is True
        services = client.app.state.container
        with services.db.transaction() as connection:
            connection.execute(
                "UPDATE audit_events SET path='/tampered' WHERE sequence_number=1"
            )
        tampered = client.get("/api/v1/audit-events/verify", headers=headers)
        assert tampered.status_code == 200
        assert tampered.json()["valid"] is False
        assert tampered.json()["first_invalid_sequence"] == 1


def test_audit_chain_remains_verifiable_after_key_rotation(settings: Settings) -> None:
    old_key = "old-audit-key-" * 3
    first = settings.with_overrides(
        api_key="test-secret",
        audit_hmac_key=old_key,
        audit_hmac_key_id="2026-q2",
    )
    headers = {"X-API-Key": "test-secret"}
    with TestClient(create_app(first)) as client:
        assert client.get("/api/v1/system/capabilities", headers=headers).status_code == 200
    rotated = settings.with_overrides(
        api_key="test-secret",
        audit_hmac_key="new-audit-key-" * 3,
        audit_hmac_key_id="2026-q3",
        audit_hmac_previous_keys=(f"2026-q2={old_key}",),
    )
    with TestClient(create_app(rotated)) as client:
        first_verification = client.get("/api/v1/audit-events/verify", headers=headers)
        assert first_verification.json()["valid"] is True
        second_verification = client.get("/api/v1/audit-events/verify", headers=headers)
        assert second_verification.json()["valid"] is True


def test_durable_apk_job_hides_storage_reference_and_completes(
    client: TestClient,
    malicious_apk: bytes,
) -> None:
    queued = client.post(
        "/api/v1/jobs/apk-analysis",
        headers={"Idempotency-Key": "apk-job-0000001"},
        files={"file": ("queued.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert "artifact_uri" not in job["payload"]
    worker = DurableWorker(client.app.state.container, worker_id="pytest-apk-worker")
    assert worker.process_next() is True
    completed = client.get(f"/api/v1/jobs/{job['id']}").json()
    assert completed["status"] == "completed"
    analysis = client.get(completed["result"]["resource"])
    assert analysis.status_code == 200
    assert analysis.json()["severity"] == "CRITICAL"
    duplicate = client.post(
        "/api/v1/jobs/apk-analysis",
        headers={"Idempotency-Key": "apk-job-0000001"},
        files={"file": ("queued.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert duplicate.status_code == 202
    assert duplicate.json()["id"] == job["id"]


def test_apk_idempotency_key_rejects_a_different_payload(
    client: TestClient,
    malicious_apk: bytes,
    benign_apk: bytes,
) -> None:
    headers = {"Idempotency-Key": "apk-job-conflict-0001"}
    accepted = client.post(
        "/api/v1/jobs/apk-analysis",
        headers=headers,
        files={"file": ("first.apk", malicious_apk, "application/vnd.android.package-archive")},
        data={"category": "banking", "dynamic": "false"},
    )
    assert accepted.status_code == 202
    conflict = client.post(
        "/api/v1/jobs/apk-analysis",
        headers=headers,
        files={"file": ("second.apk", benign_apk, "application/vnd.android.package-archive")},
        data={"category": "utility", "dynamic": "false"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "idempotency_conflict"
