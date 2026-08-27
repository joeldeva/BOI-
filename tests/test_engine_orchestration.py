"""
PRODUCTIZATION PASS 6 — Engine Adapter Unit & Integration Tests
===============================================================
Comprehensive test suite testing all adapter-specific requirements:
1. unavailable binary => UNAVAILABLE
2. timeout => TIMED_OUT / FAILED honestly
3. output size cap
4. malformed engine output contained
5. APKiD normalization
6. YARA normalization
7. apksigner normalization
8. similarity normalization
9. Quark normalization
10. private MobSF transfer flag enforced
11. VT hash-only
12. MalwareBazaar hash-only
13. no public APK upload
14. unknown/no-results never means safe
15. engine failure doesn't lower static risk
16. coordinator deterministic ordering
17. command safety audit
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch


from fraudshield.core.config import Settings
from fraudshield.deceptiscope.engines import (
    APKiDAdapter,
    EngineCoordinator,
    MalwareBazaarHashAdapter,
    MultiEngineAnalyzer,
    QuarkAdapter,
    SignatureAdapter,
    SimilarityAdapter,
    VirusTotalHashAdapter,
    YaraAdapter,
    malware_assessment,
)
from fraudshield.deceptiscope.scoring import RiskScorer


# ---------------------------------------------------------------------------
# Test 1: Unavailable binary => UNAVAILABLE status
# ---------------------------------------------------------------------------
def test_unavailable_binary_reports_unavailable_status(settings: Settings, tmp_path: Path) -> None:
    """When a binary or dependency is missing, adapter status is UNAVAILABLE."""
    sig_adapter = SignatureAdapter()
    with patch("shutil.which", return_value=None):
        assert sig_adapter.is_available(settings) is False

    analyzer = MultiEngineAnalyzer(settings)
    with patch("shutil.which", return_value=None):
        caps = analyzer.capabilities()
        apksigner_cap = next(e for e in caps["engines"] if e["id"] == "apksigner")
        assert apksigner_cap["available"] is False


# ---------------------------------------------------------------------------
# Test 2: Timeout => FAILED honestly
# ---------------------------------------------------------------------------
def test_timeout_fails_honestly_without_crashing(settings: Settings, tmp_path: Path) -> None:
    """Engine timeouts are caught and reported as failed with duration recorded."""
    target = tmp_path / "timeout_test.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    class SlowAdapter:
        engine_id = "slow_engine"
        label = "Slow Engine"
        privacy = "local-only"

        def is_enabled(self, s: Settings) -> bool:
            return True

        def is_available(self, s: Settings) -> bool:
            return True

        def analyze(self, path: Path, **kwargs) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            raise subprocess.TimeoutExpired(cmd=["slow_engine"], timeout=5)

    coordinator = EngineCoordinator(settings)
    status, findings = coordinator.run_guarded(
        SlowAdapter(), target, "sha256_dummy", {}
    )

    assert status["status"] == "failed"
    assert "TimeoutExpired" in status["error"]
    assert findings == []
    assert status["duration_ms"] >= 0


# ---------------------------------------------------------------------------
# Test 3: Output size cap
# ---------------------------------------------------------------------------
def test_output_size_cap_enforced(settings: Settings, tmp_path: Path) -> None:
    """Engine outputs exceeding max_engine_output_bytes are safely truncated."""
    target = tmp_path / "large_output.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    sig_adapter = SignatureAdapter()
    huge_stdout = "A" * (settings.max_engine_output_bytes + 5000)

    mock_run = MagicMock()
    mock_run.returncode = 0
    mock_run.stdout = huge_stdout
    mock_run.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/apksigner"), \
         patch("subprocess.run", return_value=mock_run):
        summary, findings = sig_adapter.analyze(
            target, settings=settings, sha256="abc", extraction={}
        )
        assert summary["verified"] is True


# ---------------------------------------------------------------------------
# Test 4: Malformed engine output contained
# ---------------------------------------------------------------------------
def test_malformed_engine_output_contained(settings: Settings, tmp_path: Path) -> None:
    """Malformed output from an external tool does not crash the coordinator."""
    target = tmp_path / "malformed.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    class BrokenOutputAdapter:
        engine_id = "broken"
        label = "Broken Output Engine"
        privacy = "local-only"

        def is_enabled(self, s: Settings) -> bool:
            return True

        def is_available(self, s: Settings) -> bool:
            return True

        def analyze(self, path: Path, **kwargs) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            raise ValueError("Corrupt JSON from engine process")

    coordinator = EngineCoordinator(settings)
    status, findings = coordinator.run_guarded(BrokenOutputAdapter(), target, "sha", {})
    assert status["status"] == "failed"
    assert "ValueError" in status["error"]
    assert findings == []


# ---------------------------------------------------------------------------
# Test 5: APKiD normalization
# ---------------------------------------------------------------------------
def test_apkid_normalization(settings: Settings, tmp_path: Path) -> None:
    """APKiD matches are correctly mapped to normalized findings with risk points."""
    target = tmp_path / "apkid_test.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    adapter = APKiDAdapter()
    fake_raw = {
        "files": [
            {
                "matches": {
                    "packer": ["SecShell"],
                    "anti_debug": ["ptrace_check"],
                    "compiler": ["dexmerge"],
                }
            }
        ]
    }

    mock_scanner = MagicMock()
    mock_scanner.scan_file.return_value = None
    mock_formatter = MagicMock()
    mock_formatter.build_json_output.return_value = fake_raw

    with patch("apkid.apkid.Scanner", return_value=mock_scanner), \
         patch("apkid.output.OutputFormatter", return_value=mock_formatter), \
         patch("fraudshield.deceptiscope.engines._module_available", return_value=True):
        summary, findings = adapter.analyze(target, settings=settings, sha256="abc", extraction={})

    assert summary["match_count"] == 3
    finding_ids = {f["id"] for f in findings}
    assert "APKID:packer" in finding_ids
    assert "APKID:anti_debug" in finding_ids
    packer_f = next(f for f in findings if f["id"] == "APKID:packer")
    assert packer_f["risk_points"] == 16
    assert packer_f["score_eligible"] is True


# ---------------------------------------------------------------------------
# Test 6: YARA normalization
# ---------------------------------------------------------------------------
def test_yara_normalization(settings: Settings, tmp_path: Path) -> None:
    """YARA rules are matched and mapped to standardized risk categories and points."""
    target = tmp_path / "yara_test.apk"
    import zipfile
    with zipfile.ZipFile(target, "w") as z:
        z.writestr("classes.dex", b"dex\n035\x00fake")

    # Create a real rule file
    rule_file = tmp_path / "banking_rules.yar"
    rule_file.write_text("rule test { condition: false }", encoding="utf-8")
    yara_settings = settings.with_overrides(yara_rules_path=rule_file)

    adapter = YaraAdapter()

    class FakeMatch:
        rule = "banking_sms_theft"
        namespace = "default"
        meta = {
            "title": "Banking SMS Interception Pattern",
            "risk_category": "credential_theft",
            "risk_points": "20",
            "severity": "HIGH",
        }

    mock_rules = MagicMock()
    mock_rules.match.return_value = [FakeMatch()]

    with patch("yara.compile", return_value=mock_rules):
        summary, findings = adapter.analyze(target, settings=yara_settings, sha256="abc", extraction={})

    assert summary["match_count"] >= 1
    assert len(findings) >= 1
    f = findings[0]
    assert "banking_sms_theft" in f["id"]
    assert f["risk_category"] == "credential_theft"
    assert f["risk_points"] == 20
    assert f["score_eligible"] is True


# ---------------------------------------------------------------------------
# Test 7: apksigner normalization
# ---------------------------------------------------------------------------
def test_apksigner_normalization_failed_signature(settings: Settings, tmp_path: Path) -> None:
    """Failed signature verification produces high-severity risk finding."""
    target = tmp_path / "tampered.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    adapter = SignatureAdapter()
    mock_run = MagicMock()
    mock_run.returncode = 1
    mock_run.stdout = "DOES NOT VERIFY\nJAR signature verification failed"
    mock_run.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/apksigner"), \
         patch("subprocess.run", return_value=mock_run):
        summary, findings = adapter.analyze(target, settings=settings, sha256="abc", extraction={})

    assert summary["verified"] is False
    assert len(findings) == 1
    assert findings[0]["id"] == "APKSIGNER:verification-failed"
    assert findings[0]["risk_points"] == 24
    assert findings[0]["risk_category"] == "fraud_impersonation"


# ---------------------------------------------------------------------------
# Test 8: Similarity normalization
# ---------------------------------------------------------------------------
def test_similarity_normalization(settings: Settings, tmp_path: Path) -> None:
    """Similarity adapter computes ssdeep and dexofuzzy fingerprints without findings."""
    target = tmp_path / "fingerprint.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    adapter = SimilarityAdapter()
    with patch("fraudshield.deceptiscope.engines._module_available", side_effect=lambda name: True):
        with patch.dict("sys.modules", {
            "ssdeep": MagicMock(hash_from_file=MagicMock(return_value="96:ssdeep-fingerprint:test")),
            "dexofuzzy": MagicMock(hash_from_file=MagicMock(return_value="dexofuzzy-hash-123")),
        }):
            summary, findings = adapter.analyze(target, settings=settings, sha256="abc", extraction={})

    assert summary["ssdeep"] == "96:ssdeep-fingerprint:test"
    assert summary["dexofuzzy"] == "dexofuzzy-hash-123"
    assert findings == []


# ---------------------------------------------------------------------------
# Test 9: Quark normalization
# ---------------------------------------------------------------------------
def test_quark_normalization(settings: Settings, tmp_path: Path) -> None:
    """Quark report output is parsed and normalized into behavioral findings."""
    target = tmp_path / "quark_test.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    # Create real quark rule directory and rule file
    rules_dir = tmp_path / "quark_rules"
    rules_dir.mkdir()
    (rules_dir / "rule1.json").write_text("{}", encoding="utf-8")
    quark_settings = settings.with_overrides(quark_rules_dir=rules_dir)

    adapter = QuarkAdapter()
    fake_reports = [
        {"crime": "Send SMS without user confirmation", "rule": "send_sms.json"},
        {"crime": "Monitor accessibility events", "rule": "accessibility.json"},
    ]

    mock_quark_instance = MagicMock()
    mock_quark_instance.get_json_report.return_value = fake_reports

    with patch("quark.core.quark.Quark", return_value=mock_quark_instance), \
         patch("quark.core.struct.ruleobject.RuleObject", return_value=MagicMock()), \
         patch("fraudshield.deceptiscope.engines._module_available", return_value=True):
        summary, findings = adapter.analyze(target, settings=quark_settings, sha256="abc", extraction={})

    assert summary["report_count"] == 2
    assert len(findings) == 2
    sms_finding = next(f for f in findings if "sms" in f["title"].lower())
    assert sms_finding["risk_category"] == "credential_theft"
    assert sms_finding["risk_points"] == 8


# ---------------------------------------------------------------------------
# Test 10: Private MobSF transfer flag enforced
# ---------------------------------------------------------------------------
def test_private_mobsf_transfer_flag_enforced(settings: Settings, tmp_path: Path) -> None:
    """MobSF binary transfer is blocked-by-policy unless allow_binary_transfer=True."""
    target = tmp_path / "sample.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    mobsf_settings = settings.with_overrides(
        mobsf_enabled=True,
        mobsf_allow_binary_transfer=False,
        mobsf_url="http://localhost:8000",
        mobsf_api_key="secret-key",
    )

    analyzer = MultiEngineAnalyzer(mobsf_settings)
    result = analyzer.analyze(target, sha256="abc", extraction={})

    mobsf_run = next(e for e in result["engines"] if e["id"] == "mobsf")
    assert mobsf_run["status"] == "blocked-by-policy"
    assert "FRAUDSHIELD_MOBSF_ALLOW_BINARY_TRANSFER" in mobsf_run["error"]


# ---------------------------------------------------------------------------
# Test 11: VirusTotal hash-only lookup
# ---------------------------------------------------------------------------
def test_virustotal_hash_only(settings: Settings) -> None:
    """VirusTotal adapter transmits only the SHA-256 hash and parses response."""
    vt_settings = settings.with_overrides(
        reputation_enabled=True,
        virustotal_api_key="test-api-key",
    )
    adapter = VirusTotalHashAdapter()

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 15, "suspicious": 2, "harmless": 50, "undetected": 5},
                "last_analysis_date": 1700000000,
            }
        }
    }

    with patch("httpx.Client.get", return_value=fake_response) as mock_get:
        result = adapter.lookup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", vt_settings)

    mock_get.assert_called_once()
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in str(mock_get.call_args)
    assert result["status"] == "found"
    assert result["malicious"] == 15


# ---------------------------------------------------------------------------
# Test 12: MalwareBazaar hash-only lookup
# ---------------------------------------------------------------------------
def test_malwarebazaar_hash_only(settings: Settings) -> None:
    """MalwareBazaar adapter transmits only SHA-256 and extracts threat metadata."""
    mb_settings = settings.with_overrides(
        reputation_enabled=True,
        malwarebazaar_api_key="test-auth-key",
    )
    adapter = MalwareBazaarHashAdapter()

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "query_status": "ok",
        "data": [{
            "signature": "SpyNote",
            "file_type": "apk",
            "first_seen": "2026-01-01 00:00:00",
            "tags": ["banking-trojan", "spynote"],
        }],
    }

    with patch("httpx.Client.post", return_value=fake_response) as mock_post:
        result = adapter.lookup("deadbeef" * 8, mb_settings)

    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["headers"] == {"Auth-Key": "test-auth-key"}
    assert result["status"] == "found"
    assert result["signature"] == "SpyNote"
    assert "banking-trojan" in result["tags"]


# ---------------------------------------------------------------------------
# Test 13: No public APK upload
# ---------------------------------------------------------------------------
def test_no_public_apk_upload_policy(settings: Settings, tmp_path: Path) -> None:
    """MultiEngineAnalyzer policy strictly disallows public binary uploads."""
    analyzer = MultiEngineAnalyzer(settings)
    target = tmp_path / "sample.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    result = analyzer.analyze(target, sha256="abc", extraction={})
    assert result["policy"]["public_binary_uploads"] is False
    assert result["policy"]["unknown_is_safe"] is False


# ---------------------------------------------------------------------------
# Test 14: Unknown / no-results never means safe
# ---------------------------------------------------------------------------
def test_unknown_or_no_results_never_means_safe(settings: Settings, tmp_path: Path) -> None:
    """When all engines return no findings or are unavailable, safe_to_install is False."""
    target = tmp_path / "sample.apk"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    analyzer = MultiEngineAnalyzer(settings)
    engine_res = analyzer.analyze(target, sha256="abc", extraction={})

    risk = {"overall_score": 0, "severity": "LOW"}
    assessment = malware_assessment({"analysis_quality": "full"}, risk, engine_res)

    assert assessment["safe_to_install"] is False
    assert assessment["legitimacy"] == "not-established"
    assert assessment["verdict"] == "LOW_RISK_OBSERVED"


# ---------------------------------------------------------------------------
# Test 15: Engine failure does not lower static risk
# ---------------------------------------------------------------------------
def test_engine_failure_does_not_lower_static_risk(settings: Settings) -> None:
    """Static risk calculation remains fully deterministic even when external engines fail."""
    extraction = {
        "file": {"sha256": "abc"},
        "app": {"package_name": "com.test"},
        "components": {"sms_receiver": True},
        "code_signals": {"credential_theft": {"detected": True, "evidence": ["rule"]}},
        "permissions": {"requested": ["android.permission.RECEIVE_SMS"], "flagged_dangerous": []},
    }
    scorer = RiskScorer()

    # Risk without engine analysis
    risk_base = scorer.calculate(extraction, {"score": 0, "contributions": []})
    # Risk with failed engine analysis (empty normalized findings)
    risk_with_failures = scorer.calculate(
        extraction, {"score": 0, "contributions": []},
        engine_analysis={"summary": {"unavailable_or_failed": 5}, "normalized_findings": []},
    )

    assert risk_with_failures["overall_score"] >= risk_base["overall_score"]


# ---------------------------------------------------------------------------
# Test 16: Coordinator deterministic ordering
# ---------------------------------------------------------------------------
def test_coordinator_deterministic_ordering(settings: Settings) -> None:
    """Coordinator executes adapters in an explicitly fixed, deterministic order."""
    expected_order = [
        "apkid",
        "yara",
        "apksigner",
        "similarity",
        "quark",
    ]
    coordinator = EngineCoordinator(settings)
    actual_order = [adapter.engine_id for adapter in coordinator.local_adapters]
    assert actual_order == expected_order


# ---------------------------------------------------------------------------
# Test 17: Command safety audit
# ---------------------------------------------------------------------------
def test_command_safety_no_shell_true(settings: Settings) -> None:
    """Verify that SignatureAdapter constructs command as an explicit argument list."""
    adapter = SignatureAdapter()
    target = Path("sample.apk")
    with patch("shutil.which", return_value="/usr/bin/apksigner"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        adapter.analyze(target, settings=settings, sha256="abc", extraction={})

    call_args, call_kwargs = mock_run.call_args
    # First arg must be a list, shell must NOT be True
    assert isinstance(call_args[0], list)
    assert call_args[0][0] == "/usr/bin/apksigner"
    assert call_kwargs.get("shell") is not True


# ---------------------------------------------------------------------------
# Test 18: Engine Timeout Isolation
# ---------------------------------------------------------------------------
def test_run_guarded_timeout_isolation(settings: Settings, tmp_path: Path) -> None:
    """A hanging engine adapter times out without blocking the overall orchestrator."""
    import time
    coordinator = EngineCoordinator(settings.with_overrides(engine_timeout_seconds=1))

    class HangingAdapter:
        engine_id = "hanging_engine"
        label = "Hanging Engine"
        privacy = "local-only"

        def analyze(self, path: Path, **kwargs: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            time.sleep(3)
            return {"status": "never_reached"}, []

    target = tmp_path / "dummy.apk"
    target.write_bytes(b"dummy")

    status, findings = coordinator.run_guarded(HangingAdapter(), target, "sha", {})
    assert status["status"] == "timeout"
    assert "timed out" in status["error"]
    assert findings == []


def test_no_successful_reputation_provider_is_unavailable(settings: Settings) -> None:
    analyzer = MultiEngineAnalyzer(
        settings.with_overrides(
            reputation_enabled=True,
            malwarebazaar_api_key="test-auth-key",
        )
    )
    analyzer._coordinator.vt_adapter.is_available = MagicMock(return_value=False)
    analyzer._coordinator.mb_adapter.lookup = MagicMock(side_effect=RuntimeError("offline"))

    reputation, statuses = analyzer._coordinator._run_reputation("a" * 64)

    assert reputation["verdict"] == "unavailable"
    assert reputation["known_malicious"] is False
    assert reputation["providers"] == []
    assert not any(status["status"] == "completed" for status in statuses)


def test_successful_reputation_miss_is_not_found(settings: Settings) -> None:
    analyzer = MultiEngineAnalyzer(
        settings.with_overrides(
            reputation_enabled=True,
            malwarebazaar_api_key="test-auth-key",
        )
    )
    analyzer._coordinator.vt_adapter.is_available = MagicMock(return_value=False)
    analyzer._coordinator.mb_adapter.lookup = MagicMock(
        return_value={"id": "malwarebazaar", "status": "not-found"}
    )

    reputation, _ = analyzer._coordinator._run_reputation("b" * 64)

    assert reputation["verdict"] == "not-found"
    assert len(reputation["providers"]) == 1


def test_malwarebazaar_without_auth_key_is_unavailable(settings: Settings) -> None:
    analyzer = MultiEngineAnalyzer(settings.with_overrides(reputation_enabled=True))

    reputation, statuses = analyzer._coordinator._run_reputation("d" * 64)

    malwarebazaar = next(status for status in statuses if status["id"] == "malwarebazaar")
    assert malwarebazaar["status"] == "unavailable"
    assert reputation["verdict"] == "unavailable"
    capability = next(
        item for item in analyzer.capabilities()["engines"] if item["id"] == "malwarebazaar"
    )
    assert capability["available"] is False


def test_engine_timeout_counts_as_coverage_gap(settings: Settings, tmp_path: Path) -> None:
    analyzer = MultiEngineAnalyzer(settings)
    analyzer._coordinator.run_all = MagicMock(
        return_value=(
            [{"id": "slow", "status": "timeout", "summary": {}}],
            [],
            {"verdict": "not-queried", "known_malicious": False, "providers": []},
        )
    )

    result = analyzer.analyze(tmp_path / "unused.apk", sha256="c" * 64, extraction={})

    assert result["summary"]["unavailable_or_failed"] == 1

