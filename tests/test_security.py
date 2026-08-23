from __future__ import annotations

from fastapi.testclient import TestClient

from fraudshield.main import create_app
from fraudshield.core.config import Settings


def test_api_key_protects_mutating_routes(settings, malicious_apk: bytes) -> None:
    secured = settings.with_overrides(api_key="test-secret")
    with TestClient(create_app(secured)) as client:
        read_denied = client.get("/api/v1/system/capabilities")
        assert read_denied.status_code == 401
        read_allowed = client.get(
            "/api/v1/system/capabilities", headers={"X-API-Key": "test-secret"}
        )
        assert read_allowed.status_code == 200
        denied = client.post(
            "/api/v1/apk-analyses",
            files={"file": ("sample.apk", malicious_apk, "application/vnd.android.package-archive")},
            data={"category": "banking"},
        )
        assert denied.status_code == 401
        allowed = client.post(
            "/api/v1/apk-analyses",
            headers={"X-API-Key": "test-secret"},
            files={"file": ("sample.apk", malicious_apk, "application/vnd.android.package-archive")},
            data={"category": "banking"},
        )
        assert allowed.status_code == 201


def test_server_file_paths_are_not_accepted(client) -> None:
    response = client.post(
        "/api/v1/apk-analyses",
        data={"category": "banking", "apk_path": "/etc/passwd"},
    )
    assert response.status_code == 422


def test_production_configuration_requires_service_key(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    configuration = Settings(
        environment="production",
        data_dir=runtime,
        database_path=runtime / "db.sqlite",
        upload_dir=runtime / "uploads",
        report_dir=runtime / "reports",
        api_key="",
    )
    try:
        configuration.validate()
    except RuntimeError as exc:
        assert "API_KEY" in str(exc)
    else:
        raise AssertionError("production settings accepted an empty service key")

    short_key = configuration.with_overrides(api_key="too-short")
    try:
        short_key.validate()
    except RuntimeError as exc:
        assert "at least 32" in str(exc)
    else:
        raise AssertionError("production settings accepted a short service key")


def test_trusted_signer_inventory_rejects_invalid_hash(settings) -> None:
    configuration = settings.with_overrides(trusted_bank_cert_sha256=("not-a-sha256",))
    try:
        configuration.validate()
    except RuntimeError as exc:
        assert "TRUSTED_BANK_CERT_SHA256" in str(exc)
    else:
        raise AssertionError("trusted signer inventory accepted an invalid fingerprint")


def test_invalid_environment_cannot_bypass_production_controls(settings) -> None:
    configuration = settings.with_overrides(environment="prod")
    try:
        configuration.validate()
    except RuntimeError as exc:
        assert "FRAUDSHIELD_ENV" in str(exc)
    else:
        raise AssertionError("an unsupported environment name was accepted")
