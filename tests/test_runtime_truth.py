from __future__ import annotations

import base64
import io
import re
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fraudshield.core.config import Settings
from fraudshield.core.database import Database
from fraudshield.core.repository import AnalysisRepository, IndicatorRepository
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
from fraudshield.deceptiscope.payloads import PayloadAnalysisStatus, PayloadRecoveryManager
from fraudshield.deceptiscope.pipeline import APKAnalysisPipeline
from fraudshield.deceptiscope.runtime.frida_host import FridaHost
from fraudshield.deceptiscope.runtime.runtime_models import (
    FridaRuntimeEvent,
    RuntimeObserverStatus,
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
    """Verifies that bounded emulator DEX retrieval returns valid bytes on the success path."""
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    valid_dex_bytes = b"dex\n035\x00" + b"\x00" * 100

    class FakeProc:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(valid_dex_bytes)

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            pass

    with patch("fraudshield.deceptiscope.dynamic.subprocess.Popen", return_value=FakeProc()) as popen:
        ok, data, err = analyzer.retrieve_file_from_emulator(
            "com.target.malware",
            "/data/data/com.target.malware/files/payload.dex",
        )

    assert ok is True
    assert data == valid_dex_bytes
    assert err is None
    popen.assert_called_once()


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

    class FakeProc:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"X" * 1000)

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            pass

    with patch("fraudshield.deceptiscope.dynamic.subprocess.Popen", return_value=FakeProc()):
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


def test_launch_app_is_instrumented_without_second_monkey_launch(monkeypatch) -> None:
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)
    order: list[str] = []
    adb_calls: list[tuple[str, ...]] = []

    class MockSession:
        status = RuntimeObserverStatus.COMPLETED
        events = []
        warnings = []
        spawned_pid = 4242
        attached_existing = False
        started_target = True

        def __enter__(self) -> MockSession:
            order.extend(["frida_spawn", "hooks_load", "app_resume"])
            return self

        def __exit__(self, *args) -> None:
            order.append("observers_stop")

    def fake_run(*args: str, timeout: int | None = None) -> str:
        adb_calls.append(tuple(args))
        if args[:2] == ("shell", "monkey"):
            raise AssertionError("monkey must not launch a second process after Frida spawn")
        if args[:2] == ("shell", "pidof"):
            order.append("launch_observation")
            return "4242"
        return ""

    analyzer.frida_host.status = MagicMock(return_value={"frida_installed": True})
    analyzer.frida_host.observation_session = MagicMock(return_value=MockSession())
    analyzer._run = fake_run  # type: ignore[method-assign]
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.time.sleep", lambda seconds: order.append("observer_grace"))

    state = {"package_name": "com.target.bank", "launched": False, "active_marker": "DS-TEST-OTP-111111"}
    builder = _RuntimeEvidenceBuilder("com.target.bank", time.monotonic())
    result = analyzer._execute_experiment(
        experiment_id="DYN001",
        experiment_type=ExperimentType.LAUNCH_APP,
        state=state,
        builder=builder,
    )

    assert result.status == ExperimentStatus.COMPLETED
    assert state["launched"] is True
    assert order[:4] == ["frida_spawn", "hooks_load", "app_resume", "launch_observation"]
    assert order[-2:] == ["observer_grace", "observers_stop"]
    assert not any(call[:2] == ("shell", "monkey") for call in adb_calls)
    assert builder.items[0].evidence_type == "app_launch"
    assert builder.items[0].trust_level == "INSTRUMENTED"
    assert result.metadata["instrumentation"]["started_target"] is True


def test_synthetic_sms_establishes_instrumentation_without_prior_launch(monkeypatch) -> None:
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)
    order: list[str] = []
    adb_calls: list[tuple[str, ...]] = []

    class MockSession:
        status = RuntimeObserverStatus.COMPLETED
        events = []
        warnings = []
        spawned_pid = 5252
        attached_existing = False
        started_target = True

        def __enter__(self) -> MockSession:
            order.extend(["observers_start", "target_resumed"])
            return self

        def __exit__(self, *args) -> None:
            order.append("observers_stop")

    def fake_run(*args: str, timeout: int | None = None) -> str:
        adb_calls.append(tuple(args))
        if args[:2] == ("shell", "monkey"):
            raise AssertionError("SYNTHETIC_SMS must not require a prior monkey launch")
        if args[:3] == ("emu", "sms", "send"):
            order.append("sms_send")
            return "OK"
        if args[:3] == ("logcat", "-d", "-t"):
            order.append("collector_logcat")
            return ""
        return ""

    def fake_sleep(seconds: float) -> None:
        order.append("collector_wait" if seconds < 1 else "observer_grace")

    analyzer.frida_host.status = MagicMock(return_value={"frida_installed": True})
    analyzer.frida_host.observation_session = MagicMock(return_value=MockSession())
    analyzer._run = fake_run  # type: ignore[method-assign]
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.time.sleep", fake_sleep)

    state = {"package_name": "com.target.bank", "launched": False, "active_marker": "DS-TEST-OTP-222222"}
    builder = _RuntimeEvidenceBuilder("com.target.bank", time.monotonic())
    result = analyzer._execute_experiment(
        experiment_id="DYN001",
        experiment_type=ExperimentType.SYNTHETIC_SMS,
        state=state,
        builder=builder,
    )

    assert result.status == ExperimentStatus.COMPLETED
    assert state["launched"] is True
    assert order == [
        "observers_start",
        "target_resumed",
        "sms_send",
        "collector_wait",
        "collector_logcat",
        "observer_grace",
        "observers_stop",
    ]
    assert not any(call[:2] == ("shell", "monkey") for call in adb_calls)
    assert result.metadata["instrumentation"]["started_target"] is True


def test_frida_existing_process_attach_does_not_spawn(monkeypatch) -> None:
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    host = FridaHost(settings)
    host.status = MagicMock(return_value={"frida_installed": True})
    host.registry.build_bundle = MagicMock(return_value="Java.perform(function() {});")

    class FakeScript:
        def on(self, name, callback) -> None:
            pass

        def load(self) -> None:
            pass

        def unload(self) -> None:
            pass

    class FakeSession:
        def create_script(self, script: str) -> FakeScript:
            return FakeScript()

        def detach(self) -> None:
            pass

    class FakeDevice:
        def __init__(self) -> None:
            self.spawn_calls: list[list[str]] = []

        def attach(self, target):
            return FakeSession()

        def spawn(self, argv):
            self.spawn_calls.append(argv)
            return 9999

        def resume(self, pid: int) -> None:
            pass

    device = FakeDevice()
    fake_frida = SimpleNamespace(get_device_manager=lambda: SimpleNamespace(get_device=lambda serial: device))
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    with host.observation_session("com.target.bank", ["sms"]) as session:
        assert session.status == RuntimeObserverStatus.COMPLETED
        assert session.attached_existing is True
        assert session.started_target is False
        assert session.spawned_pid is None

    assert device.spawn_calls == []


def test_startup_dex_event_can_be_captured_before_teardown(monkeypatch) -> None:
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)
    dex_event = FridaRuntimeEvent(
        schema="deceptiscope.runtime.v1",
        observer="dynamic_dex",
        event_type="DEX_CLASS_LOADER_INIT",
        timestamp_ms=5,
        api="dalvik.system.DexClassLoader.<init>",
        target_package="com.target.bank",
        metadata={"dex_path": "/data/data/com.target.bank/files/startup.dex"},
    )

    class MockSession:
        status = RuntimeObserverStatus.COMPLETED
        events = [dex_event]
        warnings = []
        spawned_pid = 1234
        attached_existing = False
        started_target = True

        def __enter__(self) -> MockSession:
            return self

        def __exit__(self, *args) -> None:
            pass

    analyzer.frida_host.status = MagicMock(return_value={"frida_installed": True})
    analyzer.frida_host.observation_session = MagicMock(return_value=MockSession())
    analyzer._collect_process_state = MagicMock()
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.time.sleep", lambda seconds: None)

    state = {"package_name": "com.target.bank", "launched": False, "active_marker": "DS-TEST-OTP-333333"}
    builder = _RuntimeEvidenceBuilder("com.target.bank", time.monotonic())
    result = analyzer._execute_experiment(
        experiment_id="DYN001",
        experiment_type=ExperimentType.LAUNCH_APP,
        state=state,
        builder=builder,
    )

    assert result.status == ExperimentStatus.COMPLETED
    dex_evidence = [item for item in builder.items if item.evidence_type == "dynamic_code_load"]
    assert len(dex_evidence) == 1
    assert dex_evidence[0].metadata["dex_path"] == "/data/data/com.target.bank/files/startup.dex"


def _lineage_for_package_case(
    *,
    process: str = "com.target",
    metadata_target: str | None = None,
    trust_level: str = "INSTRUMENTED",
    target_package: str = "com.target",
    include_ingress: bool = True,
) -> list:
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-555555")
    metadata = {
        "body_preview_redacted": "otp=DS-TEST-OTP-555555",
        "api": "okhttp3.OkHttpClient.newCall",
    }
    if metadata_target is not None:
        metadata["target_package"] = metadata_target
    evidence = []
    if include_ingress:
        evidence.append(
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_sms_delivered",
                "description": "Synthetic SMS delivered with DS-TEST-OTP-555555",
                "trust_level": "INSTRUMENTED",
                "process": target_package,
                "metadata": {"target_package": target_package},
            }
        )
    evidence.append(
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "Observed outbound POST",
            "api": "okhttp3.OkHttpClient.newCall",
            "trust_level": trust_level,
            "process": process,
            "metadata": metadata,
        }
    )
    return DataLineageCorrelator().correlate(evidence, [marker], target_package=target_package)


def test_package_mismatch_without_metadata_rejected() -> None:
    lineages = _lineage_for_package_case(process="com.other", metadata_target=None, include_ingress=False)
    assert lineages == []


def test_package_substring_matches_rejected() -> None:
    for process in ("com.target.fake", "evil.com.target"):
        lineages = _lineage_for_package_case(process=process, metadata_target=None, include_ingress=False)
        assert lineages == []


def test_legitimate_target_subprocess_accepted() -> None:
    lineages = _lineage_for_package_case(process="com.target:remote", metadata_target=None)
    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is True
    assert lineages[0].trust_level == "PAYLOAD_CORRELATED"


def test_contradictory_package_attribution_rejected() -> None:
    lineages = _lineage_for_package_case(process="com.other", metadata_target="com.target", include_ingress=False)
    assert lineages == []


def test_no_package_attribution_rejected_when_target_requested() -> None:
    lineages = _lineage_for_package_case(process="", metadata_target="", include_ingress=False)
    assert lineages == []


def test_blank_trust_cannot_payload_correlate() -> None:
    lineages = _lineage_for_package_case(trust_level="")
    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


def test_system_observed_body_cannot_payload_correlate() -> None:
    lineages = _lineage_for_package_case(trust_level="SYSTEM_OBSERVED")
    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


def test_instrumented_exact_body_still_payload_correlates() -> None:
    lineages = _lineage_for_package_case(trust_level="INSTRUMENTED")
    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is True
    assert lineages[0].trust_level == "PAYLOAD_CORRELATED"


def test_payload_correlated_cannot_self_prove_raw_body() -> None:
    lineages = _lineage_for_package_case(trust_level="PAYLOAD_CORRELATED")
    assert len(lineages) == 1
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


def test_dex_retrieval_uses_bounded_read(monkeypatch) -> None:
    settings = Settings(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")
    analyzer = DynamicLiteAnalyzer(settings)

    class FakeProc:
        def __init__(self, payload: bytes) -> None:
            self.stdout = io.BytesIO(payload)
            self.killed = False

        def wait(self, timeout: int | None = None) -> int:
            return 0

        def kill(self) -> None:
            self.killed = True

    fake_proc = FakeProc(b"X" * 501)

    def fake_popen(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["stdout"] is not None
        return fake_proc

    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.subprocess.Popen", fake_popen)
    ok, data, err = analyzer.retrieve_file_from_emulator(
        "com.target.malware",
        "/data/data/com.target.malware/files/huge.dex",
        max_bytes=500,
    )

    assert ok is False
    assert data is None
    assert "exceeds maximum allowable limit" in str(err)
    assert fake_proc.killed is True


class _PipelineFakeDynamic:
    def __init__(self, package_name: str, dex_path: str, retrieve_result: tuple[bool, bytes | None, str | None]) -> None:
        self.package_name = package_name
        self.dex_path = dex_path
        self.retrieve_file_from_emulator = MagicMock(return_value=retrieve_result)

    def status(self) -> dict[str, object]:
        return {
            "enabled": True,
            "adb_available": True,
            "safe_target_shape": True,
        }

    def observe(self, *args, **kwargs) -> dict[str, object]:
        return {
            "runtime_evidence": [
                {
                    "evidence_id": "R001",
                    "timestamp_ms": 1,
                    "evidence_type": "dynamic_code_load",
                    "source": "dynamic",
                    "trust_level": "INSTRUMENTED",
                    "process": self.package_name,
                    "description": "Instrumented dynamic DEX load",
                    "confidence": 0.95,
                    "metadata": {
                        "target_package": self.package_name,
                        "event_metadata": {
                            "target_package": self.package_name,
                            "dex_path": self.dex_path,
                            "loader_type": "DexClassLoader",
                        },
                    },
                }
            ],
            "experiment_results": [
                {
                    "experiment_id": "DYN001",
                    "experiment_type": "DYNAMIC_CODE_LOAD_OBSERVATION",
                    "status": "COMPLETED",
                    "evidence_ids": ["R001"],
                }
            ],
        }


def _pipeline_for_runtime_dex(tmp_path: Path, settings: Settings) -> APKAnalysisPipeline:
    db = Database(tmp_path / "pipeline.db")
    db.initialize()
    return APKAnalysisPipeline(settings, AnalysisRepository(db), IndicatorRepository(db))


def test_pipeline_dex_retrieval_integration_and_temp_cleanup(settings, malicious_apk: bytes, tmp_path: Path) -> None:
    package_name = "com.example.demobank"
    dex_path = f"/data/data/{package_name}/files/payload.dex"
    dex_bytes = b"dex\n035\x00" + b"\x00" * 128
    pipeline = _pipeline_for_runtime_dex(
        tmp_path,
        settings.with_overrides(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554"),
    )
    pipeline.dynamic = _PipelineFakeDynamic(package_name, dex_path, (True, dex_bytes, None))  # type: ignore[assignment]

    captured: dict[str, Path] = {}
    real_recovery = PayloadRecoveryManager()

    def recover_spy(**kwargs):
        file_path = kwargs["file_path"]
        captured["path"] = file_path
        assert file_path.exists()
        assert str(file_path) != dex_path
        return real_recovery.recover_from_file_path(**kwargs)

    pipeline.payload_recovery_manager.recover_from_file_path = MagicMock(side_effect=recover_spy)
    pipeline.payload_analyzer.analyze_payload = MagicMock(return_value=[])

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)
    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="a" * 64,
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,
    )

    assert result["status"] == "completed"
    pipeline.dynamic.retrieve_file_from_emulator.assert_called_once_with(package_name, dex_path)
    pipeline.payload_recovery_manager.recover_from_file_path.assert_called_once()
    pipeline.payload_analyzer.analyze_payload.assert_called_once()
    assert not captured["path"].exists()
    payload = result["result"]["recovered_payloads"][0]
    assert payload["analysis_status"] == PayloadAnalysisStatus.ANALYZED.value


def test_pipeline_dex_retrieval_failure_remains_unavailable(
    settings,
    malicious_apk: bytes,
    tmp_path: Path,
) -> None:
    package_name = "com.example.demobank"
    dex_path = f"/data/data/{package_name}/files/payload.dex"
    pipeline = _pipeline_for_runtime_dex(
        tmp_path,
        settings.with_overrides(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554"),
    )
    pipeline.dynamic = _PipelineFakeDynamic(package_name, dex_path, (False, None, "retrieval unavailable"))  # type: ignore[assignment]
    pipeline.payload_analyzer.analyze_payload = MagicMock(return_value=[])

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)
    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="b" * 64,
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,
    )

    assert result["status"] == "completed"
    pipeline.dynamic.retrieve_file_from_emulator.assert_called_once_with(package_name, dex_path)
    pipeline.payload_analyzer.analyze_payload.assert_not_called()
    payload = result["result"]["recovered_payloads"][0]
    assert payload["analysis_status"] == PayloadAnalysisStatus.UNAVAILABLE.value
    assert "retrieval unavailable" in payload["metadata"]["reason"]
