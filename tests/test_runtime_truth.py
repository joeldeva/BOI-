from __future__ import annotations

import re
import time
from pathlib import Path

from fraudshield.core.config import Settings
from fraudshield.deceptiscope.dynamic import (
    DynamicLiteAnalyzer,
    EvidenceTrustLevel,
    _RuntimeEvidenceBuilder,
)
from fraudshield.deceptiscope.lineage import (
    DataLineageCorrelator,
    SyntheticMarkerManager,
)
from fraudshield.deceptiscope.payloads import (
    PayloadAnalysisStatus,
    PayloadAnalyzer,
    PayloadType,
    RecoveredPayload,
)
from fraudshield.deceptiscope.reverse import MethodLevelAnalyzer
from fraudshield.deceptiscope.runtime import (
    FridaHost,
    FridaRuntimeEvent,
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
# Test B: Structured Frida Event Canonical Mapping
# ---------------------------------------------------------------------------
def test_structured_frida_event_canonical_mapping() -> None:
    """Verifies that all structured Frida events map to canonical evidence types with INSTRUMENTED trust."""
    host = FridaHost(Settings(dynamic_analysis_enabled=True))
    builder = _RuntimeEvidenceBuilder("com.victim.bank", time.monotonic())

    events = [
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="sms",
            event_type="SMS_PDU_PARSED",
            timestamp_ms=1000,
            api="android.telephony.SmsMessage.createFromPdu",
            target_package="com.victim.bank",
            metadata={"sender": "+12345"},
        ),
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="network",
            event_type="HTTP_REQUEST_OBSERVED",
            timestamp_ms=1010,
            api="okhttp3.OkHttpClient.newCall",
            target_package="com.victim.bank",
            metadata={"url": "https://evil.c2/post", "body_size": 128},
        ),
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="accessibility",
            event_type="ACCESSIBILITY_TEXT_READ",
            timestamp_ms=1020,
            api="AccessibilityNodeInfo.getText",
            target_package="com.victim.bank",
            metadata={"view_id": "com.victim.bank:id/pin"},
        ),
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="dynamic_dex",
            event_type="DEX_CLASS_LOADER_INIT",
            timestamp_ms=1030,
            api="DexClassLoader.<init>",
            target_package="com.victim.bank",
            metadata={"dex_path": "/data/data/com.victim.bank/files/payload.dex"},
        ),
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="webview",
            event_type="WEBVIEW_INTERFACE_ADDED",
            timestamp_ms=1040,
            api="WebView.addJavascriptInterface",
            target_package="com.victim.bank",
            metadata={"interface_name": "AndroidBridge"},
        ),
    ]

    evidence = host.normalize_to_evidence(events, builder)
    assert len(evidence) == 5

    assert evidence[0].evidence_type == "sms_access"
    assert evidence[0].trust_level == EvidenceTrustLevel.INSTRUMENTED

    assert evidence[1].evidence_type == "network_destination"
    assert evidence[1].trust_level == EvidenceTrustLevel.INSTRUMENTED

    assert evidence[2].evidence_type == "accessibility_behavior"
    assert evidence[2].trust_level == EvidenceTrustLevel.INSTRUMENTED

    assert evidence[3].evidence_type == "dynamic_code_load"
    assert evidence[3].trust_level == EvidenceTrustLevel.INSTRUMENTED

    assert evidence[4].evidence_type == "webview_activity"
    assert evidence[4].trust_level == EvidenceTrustLevel.INSTRUMENTED

    for ev in evidence:
        assert re.match(r"^R\d{3}$", ev.evidence_id)


# ---------------------------------------------------------------------------
# Test C: Logcat Marker Isolation (Unrelated process ignored)
# ---------------------------------------------------------------------------
def test_logcat_unrelated_process_marker_isolation() -> None:
    """Verifies that marker text appearing in an unrelated process line is NOT attributed to target package."""
    unrelated_logcat = (
        "08-26 10:00:01.000 999 999 I com.other.unrelated: Received test OTP DS-TEST-OTP-998877\n"
        "08-26 10:00:02.000 999 999 I com.other.unrelated: Sending to https://other-server.example\n"
    )

    relevant = DynamicLiteAnalyzer._relevant_lines(unrelated_logcat, "com.target.malware")
    assert len(relevant) == 0, "Unrelated process logs containing marker must be completely ignored"


# ---------------------------------------------------------------------------
# Test D: Logcat Cannot Produce PAYLOAD_CORRELATED
# ---------------------------------------------------------------------------
def test_logcat_cannot_produce_payload_correlated() -> None:
    """Verifies that even if target process logcat contains marker + URL, trust level is strictly LOG_OBSERVED."""
    analyzer = DynamicLiteAnalyzer(Settings())
    builder = _RuntimeEvidenceBuilder("com.target.malware", time.monotonic())

    logcat = (
        "08-26 10:00:01.000 123 123 I com.target.malware: POST https://c2.evil.com/exfil?otp=DS-TEST-OTP-123456\n"
    )
    state = {"package_name": "com.target.malware", "active_marker": "DS-TEST-OTP-123456"}
    analyzer._extract_network_destinations(logcat, state, builder)

    assert len(builder.items) >= 1
    assert all(ev.trust_level == EvidenceTrustLevel.LOG_OBSERVED for ev in builder.items)
    assert all(ev.metadata.get("payload_correlated") is False for ev in builder.items)


# ---------------------------------------------------------------------------
# Test E: URL Marker Is Not Payload Proof
# ---------------------------------------------------------------------------
def test_url_marker_alone_not_payload_proof() -> None:
    """Verifies that observing a URL with marker text does not create verified complete exfiltration."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-554433")

    # Ingress exists, but egress is plain LOG_OBSERVED URL without captured body payload
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
            "trust_level": "LOG_OBSERVED",
            "process": "com.target.malware",
            "metadata": {"destination": "https://c2.evil.com/gate?otp=DS-TEST-OTP-554433"},
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")

    assert len(lineages) == 1
    # Plain logcat URL is NOT complete exfiltration
    assert lineages[0].is_complete_exfiltration is False
    assert lineages[0].trust_level != "PAYLOAD_CORRELATED"


# ---------------------------------------------------------------------------
# Test F: Exact Request Body Outbound Correlation
# ---------------------------------------------------------------------------
def test_exact_request_body_correlation_produces_payload_correlated() -> None:
    """Verifies that pre-TLS outbound body capture from trusted instrumentation produces complete exfiltration."""
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
            "metadata": {"has_synthetic_marker": True},
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
                "has_synthetic_marker": True,
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
# Test G: Wrong Marker Does Not Correlate
# ---------------------------------------------------------------------------
def test_wrong_marker_does_not_correlate() -> None:
    """Verifies that observation of a different marker than the active run marker produces NO exfiltration."""
    manager = SyntheticMarkerManager()
    active_marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-111111")

    # Network body contains a completely different marker
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
            },
        }
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [active_marker], target_package="com.target.malware")
    assert len(lineages) == 0


# ---------------------------------------------------------------------------
# Test H: Wrong Target Package Does Not Correlate
# ---------------------------------------------------------------------------
def test_wrong_target_package_does_not_correlate() -> None:
    """Verifies that evidence from another application process is strictly filtered out."""
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-333333")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "network_destination",
            "description": "POST request",
            "trust_level": "INSTRUMENTED",
            "process": "com.unrelated.package",
            "metadata": {
                "target_package": "com.unrelated.package",
                "body_preview_redacted": "otp=DS-TEST-OTP-333333",
            },
        }
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker], target_package="com.target.malware")
    assert len(lineages) == 0


# ---------------------------------------------------------------------------
# Test I: Runtime Scoring Requires Verified Trust
# ---------------------------------------------------------------------------
def test_runtime_scoring_requires_verified_trust() -> None:
    """Verifies that RiskScorer awards exfiltration points ONLY when trust_level is PAYLOAD_CORRELATED."""
    scorer = RiskScorer()

    extracted = {
        "permissions": {"requested": ["android.permission.READ_SMS", "android.permission.INTERNET"]},
        "components": {},
        "signals": {},
        "obfuscation": {},
        "certificate": {},
        "file": {},
        "coverage": {"dynamic": True},
    }
    fraud_delta = {"contributions": []}

    # Case 1: Unverified logcat evidence (LOG_OBSERVED) -> NO exfiltration escalation
    unverified_ev = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_marker_correlation",
            "trust_level": "LOG_OBSERVED",
            "confidence": 0.6,
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "trust_level": "LOG_OBSERVED",
            "confidence": 0.6,
        },
    ]
    res_unverified = scorer.calculate(
        extracted,
        fraud_delta,
        runtime_evidence=unverified_ev,
    )
    assert not any(rule["rule_id"] == "RUNTIME-EXFIL-001" for rule in res_unverified["runtime_rules"])

    # Case 2: Verified PAYLOAD_CORRELATED evidence -> Exfiltration escalation awarded
    verified_ev = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_marker_correlation",
            "trust_level": "PAYLOAD_CORRELATED",
            "confidence": 1.0,
            "metadata": {"payload_correlated": True},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "trust_level": "INSTRUMENTED",
            "confidence": 0.95,
        },
    ]
    res_verified = scorer.calculate(
        extracted,
        fraud_delta,
        runtime_evidence=verified_ev,
    )
    assert any(rule["rule_id"] == "RUNTIME-EXFIL-001" for rule in res_verified["runtime_rules"])


# ---------------------------------------------------------------------------
# Test J: Recovered Payload Evidence ID Format
# ---------------------------------------------------------------------------
def test_recovered_payload_evidence_id_valid_regex() -> None:
    """Verifies that PayloadAnalyzer creates valid E### EvidenceItems that satisfy EvidenceItem regex ^E\\d{3}$."""
    payload = RecoveredPayload(
        payload_id="PAYLOAD-001",
        parent_sample_sha256="c" * 64,
        sha256="d" * 64,
        payload_type=PayloadType.DEX,
        size_bytes=1024,
        analysis_status=PayloadAnalysisStatus.ANALYZED,
    )

    # Mock MethodLevelAnalyzer match
    class MockMethodAnalyzer(MethodLevelAnalyzer):
        def analyze(self, apk_path, app_package=None):
            return {
                "status": "completed",
                "matches": [
                    {
                        "signature_id": "SIG-01",
                        "title": "C2 Connect",
                        "category": "NETWORKING",
                        "class_name": "com.payload.C2",
                        "method_name": "send",
                        "call_site": "OkHttpClient->newCall",
                        "code_ownership": "APPLICATION_CODE",
                    }
                ],
            }

    analyzer = PayloadAnalyzer(MockMethodAnalyzer())
    dex_bytes = b"dex\n035\x00" + b"\x00" * 100

    items = analyzer.analyze_payload(payload, dex_bytes)
    assert len(items) == 1
    assert re.match(r"^E\d{3}$", items[0].evidence_id)
    assert items[0].phase == "PAYLOAD"
    assert items[0].source_artifact == "PAYLOAD-001"


# ---------------------------------------------------------------------------
# Test K: Dynamic Failure Keeps Analysis Honest
# ---------------------------------------------------------------------------
def test_dynamic_failure_preserves_static_risk_honestly() -> None:
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

    # Simulate dynamic failure
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
        "status": "CONFIRMED",  # AI claimed confirmation
    }
    verification = verifier.verify(hypothesis, findings, [])
    # AI self-confirmation is rejected; status downgraded to INCONCLUSIVE
    assert verification.verified_status == "INCONCLUSIVE"
    assert verification.confirmation_allowed is False

    # Calculate final risk: runtime_adjustment MUST be 0
    final_risk = scorer.calculate(
        extracted,
        fraud_delta,
        runtime_evidence=[],
        experiment_results=failed_experiment_results,
        verifications=[verification.model_dump(mode="json")],
    )
    assert final_risk["runtime_adjustment"] == 0
    assert final_risk["overall_score"] == static_risk["static_score"]
