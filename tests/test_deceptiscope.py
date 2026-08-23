from __future__ import annotations

import hashlib
import warnings
import zipfile
from pathlib import Path

import pytest

from fraudshield.core.errors import ValidationError
from fraudshield.core.errors import ConfigurationError
from fraudshield.deceptiscope.dynamic import DynamicLiteAnalyzer
from fraudshield.deceptiscope.engines import MultiEngineAnalyzer, malware_assessment
from fraudshield.deceptiscope.extractor import StaticAPKExtractor
from fraudshield.deceptiscope.fraud_delta import FraudDeltaCalculator
from fraudshield.deceptiscope.mitre import map_mitre_mobile
from fraudshield.deceptiscope.scoring import RiskScorer
from fraudshield.deceptiscope.validator import validate_apk_archive


def test_invalid_apk_is_rejected_not_replaced_with_fake_findings(settings, tmp_path: Path) -> None:
    target = tmp_path / "invalid.apk"
    target.write_bytes(b"PK\x03\x04not a complete archive")
    with pytest.raises(ValidationError) as caught:
        validate_apk_archive(target, settings)
    assert caught.value.code == "invalid_apk_zip"


def test_apk_archive_rejects_path_traversal(settings, tmp_path: Path) -> None:
    target = tmp_path / "unsafe.apk"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='org.example.safe'/>")
        archive.writestr("../escape.txt", "not allowed")
    with pytest.raises(ValidationError) as caught:
        validate_apk_archive(target, settings)
    assert caught.value.code == "unsafe_apk_path"


def test_apk_archive_rejects_duplicate_entries(settings, tmp_path: Path) -> None:
    target = tmp_path / "duplicate.apk"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='org.example.safe'/>")
        archive.writestr("classes.dex", b"dex\n035\x00first")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr("classes.dex", b"dex\n035\x00second")
    with pytest.raises(ValidationError) as caught:
        validate_apk_archive(target, settings)
    assert caught.value.code == "duplicate_apk_entry"


def test_dynamic_lite_is_disabled_by_default(settings, tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        DynamicLiteAnalyzer(settings).observe(tmp_path / "sample.apk", "org.example.sample")


def test_static_extraction_and_scoring_are_evidence_grounded(
    settings, malicious_apk: bytes, tmp_path: Path
) -> None:
    target = tmp_path / "sample.apk"
    target.write_bytes(malicious_apk)
    extracted = StaticAPKExtractor(target, settings, original_name="sample.apk").extract()
    assert extracted["file"]["sha256"] == hashlib.sha256(malicious_apk).hexdigest()
    assert extracted["app"]["package_name"] == "com.example.demobank"
    assert extracted["components"]["sms_receiver"] is True
    assert extracted["code_signals"]["dynamic_code_loading"]["detected"] is True
    assert extracted["analysis_quality"] in {"full", "partial"}
    assert extracted["network_indicators"]["domains"] == ["c2-demo.fraudshield.invalid"]
    assert "http://schemas.android.com/apk/res/android" not in extracted["network_indicators"]["urls"]
    if extracted["analysis_quality"] == "partial":
        assert extracted["certificate"]["sha256"] == ""
        assert extracted["certificate"]["signature_entries"]

    delta = FraudDeltaCalculator(settings.baseline_path).calculate(extracted, "banking")
    risk = RiskScorer().calculate(extracted, delta)
    assert risk["overall_score"] >= 75
    assert risk["severity"] == "CRITICAL"
    assert all(item["rule_id"].startswith("APK-") for item in risk["evidence"])
    assert risk["methodology_note"].startswith("Deterministic")


def test_benign_fixture_scores_lower(settings, benign_apk: bytes, tmp_path: Path) -> None:
    target = tmp_path / "notes.apk"
    target.write_bytes(benign_apk)
    extracted = StaticAPKExtractor(target, settings).extract()
    delta = FraudDeltaCalculator(settings.baseline_path).calculate(extracted, "utility")
    risk = RiskScorer().calculate(extracted, delta)
    assert risk["overall_score"] < 25
    assert risk["severity"] == "LOW"


def test_mitre_mapping_uses_verified_mobile_ids(settings, malicious_apk: bytes, tmp_path: Path) -> None:
    target = tmp_path / "sample.apk"
    target.write_bytes(malicious_apk)
    extracted = StaticAPKExtractor(target, settings).extract()
    mapped = {item["technique_id"] for item in map_mitre_mobile(extracted)}
    assert {"T1636.004", "T1417.002", "T1417.001", "T1516", "T1407", "T1418"} <= mapped
    assert "T1443" not in mapped


def test_multi_engine_orchestrator_is_private_and_failure_explicit(
    settings, malicious_apk: bytes, tmp_path: Path
) -> None:
    target = tmp_path / "sample.apk"
    target.write_bytes(malicious_apk)
    extracted = StaticAPKExtractor(target, settings).extract()
    result = MultiEngineAnalyzer(settings).analyze(
        target,
        sha256=hashlib.sha256(malicious_apk).hexdigest(),
        extraction=extracted,
    )
    assert result["policy"]["public_binary_uploads"] is False
    assert result["policy"]["external_hash_lookups"] is False
    assert result["reputation"]["verdict"] == "not-queried"
    engine_ids = [item["id"] for item in result["engines"]]
    assert len(engine_ids) == len(set(engine_ids))
    engines = {item["id"]: item for item in result["engines"]}
    assert engines["archive_native"]["status"] == "completed"
    assert engines["androguard"]["status"] in {"completed", "failed", "unavailable"}
    assert engines["virustotal"]["status"] == "disabled"
    assert engines["malwarebazaar"]["status"] == "disabled"
    assert all(item["status"] != "completed" for item in result["engines"] if item["id"] == "mobsf")


def test_normalized_engine_points_are_bounded_and_assessment_never_claims_safety(
    settings, benign_apk: bytes, tmp_path: Path
) -> None:
    target = tmp_path / "notes.apk"
    target.write_bytes(benign_apk)
    extracted = StaticAPKExtractor(target, settings).extract()
    delta = FraudDeltaCalculator(settings.baseline_path).calculate(extracted, "utility")
    engine_analysis = {
        "summary": {"unavailable_or_failed": 0},
        "normalized_findings": [
            {
                "id": f"test-{index}",
                "engine": "test-engine",
                "title": "Bounded test evidence",
                "confidence": 0.9,
                "risk_category": "evasion_resilience",
                "risk_points": 30,
                "score_eligible": True,
                "evidence": ["fixture"],
            }
            for index in range(5)
        ],
        "reputation": {"known_malicious": False},
    }
    risk = RiskScorer().calculate(extracted, delta, engine_analysis=engine_analysis)
    external = [item for item in risk["evidence"] if item["rule_id"].startswith("APK-EXT-")]
    assert sum(item["points"] for item in external) == 25
    assessment = malware_assessment(extracted, risk, engine_analysis)
    assert assessment["legitimacy"] == "not-established"
    assert assessment["safe_to_install"] is False
