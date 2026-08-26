from __future__ import annotations

import base64
import re
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from fraudshield.core.config import Settings
from fraudshield.deceptiscope.dynamic import (
    DynamicLiteAnalyzer,
    ExperimentStatus,
    ExperimentType,
    _RuntimeEvidenceBuilder,
)
from fraudshield.deceptiscope.lineage import (
    DataLineageCorrelator,
    SyntheticMarkerManager,
)
from fraudshield.deceptiscope.scoring import RiskScorer
from fraudshield.deceptiscope.verifier import HypothesisVerifier


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "fraudshield" / "deceptiscope" / "runtime" / "scripts"


# ---------------------------------------------------------------------------
# Test A: Frida Hook Safety - No Recursive Invocations
# ---------------------------------------------------------------------------
def test_frida_hook_safety_no_recursive_invocations() -> None:
    """
    Statically audits every trusted Frida observer script to ensure NO hook
    implementation calls 'this.methodName(...)' or 'this.$init(...)' recursively.
    Every hook must explicitly invoke the saved original overload reference.
    """
    forbidden_patterns = [
        re.compile(r"this\.\$init\s*\("),
        re.compile(r"this\.loadDex\s*\("),
        re.compile(r"this\.newCall\s*\("),
        re.compile(r"this\.connect\s*\("),
        re.compile(r"this\.openConnection\s*\("),
        re.compile(r"this\.sendTextMessage\s*\("),
        re.compile(r"this\.sendMultipartTextMessage\s*\("),
        re.compile(r"this\.getText\s*\("),
        re.compile(r"this\.performAction\s*\("),
        re.compile(r"this\.performGlobalAction\s*\("),
        re.compile(r"this\.onNotificationPosted\s*\("),
        re.compile(r"this\.getReference\s*\("),
        re.compile(r"this\.collection\s*\("),
        re.compile(r"this\.addJavascriptInterface\s*\("),
        re.compile(r"this\.loadUrl\s*\("),
    ]

    script_files = list(SCRIPTS_DIR.glob("*.js"))
    assert len(script_files) >= 5, f"Expected observer scripts in {SCRIPTS_DIR}"

    for script_file in script_files:
        code = script_file.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            matches = pat.findall(code)
            assert not matches, (
                f"Unsafe recursive method invocation {matches} detected in observer script: {script_file.name}. "
                "Hooks must call original overload reference explicitly via .call(this, ...)."
            )


# ---------------------------------------------------------------------------
# Test 1: Unique Real Marker
# ---------------------------------------------------------------------------
def test_unique_real_marker() -> None:
    """Verifies that each marker creation in uploaded analysis produces a unique marker."""
    manager = SyntheticMarkerManager()
    marker1 = manager.create_otp_marker()
    marker2 = manager.create_otp_marker()

    assert marker1.value != marker2.value
    assert marker1.value.startswith("DS-TEST-OTP-")
    assert marker2.value.startswith("DS-TEST-OTP-")
    assert marker1.value != "BOI-TEST-749231"
    assert marker2.value != "BOI-TEST-749231"


# ---------------------------------------------------------------------------
# Test 2: Frida Observers Start BEFORE Controlled Experiment Action
# ---------------------------------------------------------------------------
def test_frida_before_experiment() -> None:
    """Verifies that Frida observation session is entered BEFORE the experiment action executes."""
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    execution_order: list[str] = []

    # Mock observation_session context manager
    class MockSession:
        def __init__(self) -> None:
            self.events = []

        def __enter__(self) -> MockSession:
            execution_order.append("observers_start")
            return self

        def __exit__(self, *args) -> None:
            execution_order.append("observers_stop")

    analyzer.frida_host.observation_session = MagicMock(return_value=MockSession())
    analyzer.frida_host.status = MagicMock(return_value={"frida_installed": True})
    analyzer._collect = MagicMock(side_effect=lambda *args: (
        execution_order.append("experiment_action") or (ExperimentStatus.COMPLETED, "OK", None)
    ))

    state = {"package_name": "com.test.app", "launched": True, "active_marker": "DS-TEST-OTP-999"}
    builder = _RuntimeEvidenceBuilder("com.test.app", time.monotonic())

    analyzer._execute_experiment(
        experiment_id="DYN001",
        experiment_type=ExperimentType.SYNTHETIC_SMS,
        state=state,
        builder=builder,
    )

    assert execution_order == ["observers_start", "experiment_action", "observers_stop"], (
        f"Incorrect lifecycle order: {execution_order}"
    )


# ---------------------------------------------------------------------------
# Test 3: Instrumented URL Marker Is NOT Payload Proof
# ---------------------------------------------------------------------------
def test_instrumented_url_marker_is_not_payload_proof() -> None:
    """Verifies that even with INSTRUMENTED trust, a URL-only marker does NOT create PAYLOAD_CORRELATED."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-554433")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "Synthetic SMS delivered containing DS-TEST-OTP-554433",
            "api": "android.telephony.SmsMessage.createFromPdu",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {"has_synthetic_marker": True},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "Observed connection to https://c2.evil.com/gate?otp=DS-TEST-OTP-554433",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {
                "url": "https://c2.evil.com/gate?otp=DS-TEST-OTP-554433",
                "destination": "https://c2.evil.com/gate?otp=DS-TEST-OTP-554433",
            },
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")

    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


# ---------------------------------------------------------------------------
# Test 4: Description Marker Is NOT Payload Proof
# ---------------------------------------------------------------------------
def test_description_marker_is_not_payload_proof() -> None:
    """Verifies that marker appearing only in evidence description does not create PAYLOAD_CORRELATED."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-443322")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "Delivered DS-TEST-OTP-443322",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "Target sent data containing DS-TEST-OTP-443322 to C2",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {"url": "https://evil.c2/post"},
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")

    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


# ---------------------------------------------------------------------------
# Test 5: Destination Marker Is NOT Payload Proof
# ---------------------------------------------------------------------------
def test_destination_marker_is_not_payload_proof() -> None:
    """Verifies that marker appearing in destination field does not create PAYLOAD_CORRELATED."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-332211")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "Delivered DS-TEST-OTP-332211",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "Socket connect",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {"destination": "DS-TEST-OTP-332211.evil.com:443"},
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")

    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


# ---------------------------------------------------------------------------
# Test 6: has_synthetic_marker True With WRONG Marker
# ---------------------------------------------------------------------------
def test_has_synthetic_marker_true_with_wrong_marker() -> None:
    """Verifies that boolean has_synthetic_marker=true cannot correlate when marker value is different."""
    manager = SyntheticMarkerManager()
    active_marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-111111")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "network_destination",
            "description": "POST request",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {
                "destination": "https://c2.evil.com/steal",
                "body_preview_redacted": "otp=DS-TEST-OTP-222222",
                "has_synthetic_marker": True,
            },
        }
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [active_marker], target_package="com.target.malware")
    assert len(lineages) == 0


# ---------------------------------------------------------------------------
# Test 7: has_synthetic_marker True With NO Body
# ---------------------------------------------------------------------------
def test_has_synthetic_marker_true_with_no_body() -> None:
    """Verifies that has_synthetic_marker=true without captured body data never produces PAYLOAD_CORRELATED."""
    manager = SyntheticMarkerManager()
    active_marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-887766")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "SMS Delivered DS-TEST-OTP-887766",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {"has_synthetic_marker": True},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "POST request observed",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {
                "has_synthetic_marker": True,
            },
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [active_marker], target_package="com.target.malware")
    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


# ---------------------------------------------------------------------------
# Test 8: Exact Body Match Produces PAYLOAD_CORRELATED
# ---------------------------------------------------------------------------
def test_exact_body_match_produces_payload_correlated() -> None:
    """Verifies that active marker inside captured pre-TLS outbound body produces PAYLOAD_CORRELATED."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-778899")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "Synthetic SMS delivered containing DS-TEST-OTP-778899",
            "api": "android.telephony.SmsMessage.createFromPdu",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "Pre-TLS OkHttp POST request",
            "api": "okhttp3.OkHttpClient.newCall",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {
                "destination": "https://c2.evil.com/api/steal",
                "method": "POST",
                "body_preview_redacted": '{"account":"123","otp":"DS-TEST-OTP-778899"}',
            },
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")

    assert len(lineages) == 1
    pl = lineages[0]
    assert pl.is_complete_exfiltration is True
    assert pl.trust_level == "PAYLOAD_CORRELATED"
    assert "Complete Outbound Body Exfiltration Proven" in pl.summary


# ---------------------------------------------------------------------------
# Test 9: Base64 Body Match
# ---------------------------------------------------------------------------
def test_base64_body_match() -> None:
    """Verifies that base64 encoded active marker in outbound body produces deterministic correlation."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-123456")
    b64_val = base64.b64encode(b"DS-TEST-OTP-123456").decode("ascii")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "SMS Delivered",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {"body": "DS-TEST-OTP-123456"},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "POST payload",
            "trust_level": "INSTRUMENTED",
            "process": "com.target.malware",
            "metadata": {
                "body_preview_redacted": f'{{"data":"{b64_val}"}}',
            },
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")

    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is True
    assert lineages[0].trust_level == "PAYLOAD_CORRELATED"
    egress_step = [s for s in lineages[0].steps if s.phase == "EGRESS"][0]
    assert egress_step.transform_type == "base64"


# ---------------------------------------------------------------------------
# Test 10: Logcat Confidence CANNOT Upgrade Trust
# ---------------------------------------------------------------------------
def test_logcat_confidence_cannot_upgrade_trust() -> None:
    """Verifies that high confidence (1.0) on LOG_OBSERVED evidence cannot confirm OTP hypothesis."""
    verifier = HypothesisVerifier()

    findings = {
        "extraction": {
            "permissions": {"requested": ["android.permission.READ_SMS"]},
            "components": {"sms_receiver": True},
            "signals": {"sms_api": {"detected": True, "evidence": ["sendTextMessage"]}},
        },
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_sms_delivered",
                "trust_level": "LOG_OBSERVED",
                "confidence": 1.0,  # High confidence on logcat must NOT upgrade provenance
            },
            {
                "evidence_id": "R002",
                "evidence_type": "sms_access",
                "trust_level": "LOG_OBSERVED",
                "confidence": 1.0,
            },
        ],
        "experiment_results": [
            {"experiment_id": "DYN001", "experiment_type": "SYNTHETIC_SMS", "status": "COMPLETED"}
        ],
    }

    hypothesis = {
        "hypothesis_id": "H001",
        "category": "OTP_INTERCEPTION",
        "status": "CONFIRMED",
    }

    verification = verifier.verify(hypothesis, findings, [])
    # Must NOT be CONFIRMED because trust_level is LOG_OBSERVED
    assert verification.verified_status != "CONFIRMED"
    assert verification.confirmation_allowed is False
    assert verification.verified_status == "SUPPORTED"


# ---------------------------------------------------------------------------
# Test 11: Instrumented SMS Access Confirms When Required Conditions Exist
# ---------------------------------------------------------------------------
def test_instrumented_sms_access_confirms() -> None:
    """Verifies that controlled delivery + INSTRUMENTED sms_access + static support achieves CONFIRMED."""
    verifier = HypothesisVerifier()

    findings = {
        "extraction": {
            "permissions": {"requested": ["android.permission.READ_SMS"]},
            "components": {"sms_receiver": True},
            "signals": {"sms_api": {"detected": True, "evidence": ["sendTextMessage"]}},
        },
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_sms_delivered",
                "trust_level": "SYSTEM_OBSERVED",
                "confidence": 1.0,
            },
            {
                "evidence_id": "R002",
                "evidence_type": "sms_access",
                "trust_level": "INSTRUMENTED",
                "confidence": 0.95,
            },
        ],
        "experiment_results": [
            {"experiment_id": "DYN001", "experiment_type": "SYNTHETIC_SMS", "status": "COMPLETED"}
        ],
    }

    hypothesis = {
        "hypothesis_id": "H001",
        "category": "OTP_INTERCEPTION",
        "status": "CONFIRMED",
    }

    verification = verifier.verify(hypothesis, findings, [])
    assert verification.verified_status == "CONFIRMED"
    assert verification.confirmation_allowed is True


# ---------------------------------------------------------------------------
# Test 12: Emulator DEX Path Retrieval
# ---------------------------------------------------------------------------
def test_emulator_dex_path_retrieval() -> None:
    """Verifies that DEX recovery uses retrieve_file_from_emulator instead of host Path.exists()."""
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    valid_dex_bytes = b"dex\n035\x00" + b"\x00" * 100

    # Mock retrieve_file_from_emulator
    analyzer.retrieve_file_from_emulator = MagicMock(return_value=(True, valid_dex_bytes, None))

    ok, data, err = analyzer.retrieve_file_from_emulator(
        "com.target.malware",
        "/data/data/com.target.malware/files/payload.dex",
    )
    assert ok is True
    assert data == valid_dex_bytes
    assert err is None


# ---------------------------------------------------------------------------
# Test 13: DEX Path Traversal Rejected
# ---------------------------------------------------------------------------
def test_dex_path_traversal_rejected() -> None:
    """Verifies that path traversal sequences are rejected."""
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    ok, data, err = analyzer.retrieve_file_from_emulator(
        "com.target.malware",
        "/data/data/com.target.malware/files/../../something.dex",
    )
    assert ok is False
    assert data is None
    assert "traversal" in str(err).lower()


# ---------------------------------------------------------------------------
# Test 14: DEX Path Wrong Package Rejected
# ---------------------------------------------------------------------------
def test_dex_path_wrong_package_rejected() -> None:
    """Verifies that paths outside the target package directory are rejected."""
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    ok, data, err = analyzer.retrieve_file_from_emulator(
        "com.target.malware",
        "/data/data/com.other.app/files/x.dex",
    )
    assert ok is False
    assert data is None
    assert "outside approved sandbox" in str(err).lower()


# ---------------------------------------------------------------------------
# Test 15: DEX Oversize Rejected
# ---------------------------------------------------------------------------
def test_dex_oversize_rejected() -> None:
    """Verifies that retrieving a file larger than max_bytes limit fails safely."""
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"X" * 1000)
        ok, data, err = analyzer.retrieve_file_from_emulator(
            "com.target.malware",
            "/data/data/com.target.malware/files/huge.dex",
            max_bytes=500,
        )
        assert ok is False
        assert data is None
        assert "exceeds maximum allowable limit" in str(err).lower()


# ---------------------------------------------------------------------------
# Test 16: DEX Temp File Cleanup
# ---------------------------------------------------------------------------
def test_dex_temp_file_cleanup() -> None:
    """Verifies that temporary host DEX files created during analysis are properly deleted."""
    dex_bytes = b"dex\n035\x00" + b"\x00" * 100
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as tf:
            tf.write(dex_bytes)
            temp_path = Path(tf.name)
        assert temp_path.exists()
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()

    assert not temp_path.exists()


# ---------------------------------------------------------------------------
# Test 17: Runtime Failure Preserves Static Score
# ---------------------------------------------------------------------------
def test_runtime_failure_preserves_static_risk_honestly() -> None:
    """Verifies that runtime failure/timeout NEVER lowers risk score and retains deterministic static base."""
    scorer = RiskScorer()
    verifier = HypothesisVerifier()

    extracted = {
        "permissions": {"requested": ["android.permission.READ_SMS", "android.permission.INTERNET"]},
        "components": {"sms_receiver": True},
        "signals": {"sms_api": {"detected": True, "evidence": ["sendTextMessage"]}},
        "obfuscation": {},
        "certificate": {},
        "file": {},
    }
    fraud_delta = {"contributions": []}

    static_risk = scorer.calculate(extracted, fraud_delta)
    assert static_risk["static_score"] > 0

    failed_experiment_results = [
        {"experiment_id": "DYN001", "experiment_type": "SYNTHETIC_SMS", "status": "FAILED", "error": "ADB timeout"}
    ]

    findings = {
        "extraction": extracted,
        "runtime_evidence": [],
        "experiment_results": failed_experiment_results,
    }
    hypothesis = {
        "hypothesis_id": "H001",
        "category": "OTP_INTERCEPTION",
        "status": "CONFIRMED",
    }
    verification = verifier.verify(hypothesis, findings, [])
    assert verification.verified_status == "INCONCLUSIVE"
    assert verification.confirmation_allowed is False

    final_risk = scorer.calculate(
        extracted,
        fraud_delta,
        runtime_evidence=[],
        experiment_results=failed_experiment_results,
        verifications=[verification.model_dump(mode="json")],
    )
    assert final_risk["runtime_adjustment"] == 0
    assert final_risk["overall_score"] == static_risk["static_score"]
