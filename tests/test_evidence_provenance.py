from __future__ import annotations

from typing import Any

from fraudshield.deceptiscope.dynamic import EvidenceTrustLevel
from fraudshield.deceptiscope.scoring import RiskScorer
from fraudshield.deceptiscope.verifier import HypothesisVerifier


def _sample_findings(
    *,
    permissions: list[str] | None = None,
    sms_receiver: bool = False,
    runtime_evidence: list[dict[str, Any]] | None = None,
    experiment_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "extraction": {
            "permissions": {"requested": permissions or ["android.permission.INTERNET"]},
            "components": {"sms_receiver": sms_receiver, "accessibility_service": False},
            "code_signals": {"sms_api": {"detected": False}, "input_injection": {"detected": False}},
            "network_indicators": {"domains": ["c2.example.invalid"], "ips": [], "urls": []},
            "coverage": {"dynamic": True},
        },
        "runtime_evidence": runtime_evidence or [],
        "experiment_results": experiment_results or [],
    }


# Test 1: Random log string cannot produce CONFIRMED
def test_random_log_string_cannot_produce_confirmed() -> None:
    verifier = HypothesisVerifier()
    hypothesis = {
        "hypothesis_id": "H-001",
        "category": "OTP_INTERCEPTION",
        "status": "PROPOSED",
        "confidence": 0.85,
    }
    # Log string only has LOG_OBSERVED trust and no instrumented delivery
    findings = _sample_findings(
        permissions=["android.permission.READ_SMS"],
        sms_receiver=True,
        runtime_evidence=[
            {
                "evidence_id": "R001",
                "evidence_type": "sms_access",
                "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
                "confidence": 0.75,
                "description": "Log matched generic SmsManager string",
            }
        ],
    )
    result = verifier.verify(hypothesis, findings, [])
    assert result.verified_status != "CONFIRMED"
    assert result.verified_status == "SUPPORTED"
    assert result.confirmation_allowed is False
    assert "generic log matching" in result.deterministic_explanation


# Test 2: AI confidence cannot produce CONFIRMED
def test_ai_confidence_cannot_produce_confirmed() -> None:
    verifier = HypothesisVerifier()
    hypothesis = {
        "hypothesis_id": "H-002",
        "category": "DATA_EXFILTRATION",
        "status": "CONFIRMED",  # AI claims confirmed
        "confidence": 1.0,       # AI max confidence
    }
    findings = _sample_findings(
        permissions=["android.permission.INTERNET"],
        runtime_evidence=[],  # No runtime evidence
    )
    result = verifier.verify(hypothesis, findings, [])
    assert result.verified_status != "CONFIRMED"
    assert result.verified_status in {"SUPPORTED", "PROPOSED"}
    assert result.confirmation_allowed is False


# Test 3: Temporal network correlation alone does not prove payload exfiltration
def test_temporal_network_correlation_alone_does_not_prove_exfiltration() -> None:
    verifier = HypothesisVerifier()
    hypothesis = {
        "hypothesis_id": "H-003",
        "category": "DATA_EXFILTRATION",
        "status": "PROPOSED",
        "confidence": 0.70,
    }
    # Marker was seen at t=1000, unrelated network socket opened at t=2000 without payload proof
    findings = _sample_findings(
        permissions=["android.permission.INTERNET"],
        runtime_evidence=[
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_marker_correlation",
                "timestamp_ms": 1000,
                "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
                "confidence": 0.80,
                "description": "Marker BOI-TEST-749231 seen in logcat",
            },
            {
                "evidence_id": "R002",
                "evidence_type": "network_destination",
                "timestamp_ms": 2000,
                "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
                "confidence": 0.55,
                "description": "Egress connection to c2.example.invalid",
                "metadata": {"destination": "c2.example.invalid", "payload_correlated": False},
            },
        ],
    )
    result = verifier.verify(hypothesis, findings, [])
    assert result.verified_status != "CONFIRMED"
    assert result.verified_status == "SUPPORTED"
    assert result.confirmation_allowed is False
    assert "temporal correlation only" in result.deterministic_explanation


# Test 4: Strong evidence can produce CONFIRMED
def test_strong_evidence_produces_confirmed() -> None:
    verifier = HypothesisVerifier()
    # 4A: Strong OTP Interception
    otp_hypothesis = {
        "hypothesis_id": "H-001",
        "category": "OTP_INTERCEPTION",
        "status": "PROPOSED",
        "confidence": 0.80,
    }
    otp_findings = _sample_findings(
        permissions=["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        sms_receiver=True,
        runtime_evidence=[
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_sms_delivered",
                "trust_level": EvidenceTrustLevel.INSTRUMENTED,
                "confidence": 1.0,
                "description": "Synthetic SMS delivered via controlled emulator injection",
            },
            {
                "evidence_id": "R002",
                "evidence_type": "sms_access",
                "trust_level": EvidenceTrustLevel.INSTRUMENTED,
                "confidence": 0.95,
                "description": "Receiver handled synthetic SMS broadcast",
            },
            {
                "evidence_id": "R003",
                "evidence_type": "synthetic_marker_correlation",
                "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
                "confidence": 1.0,
                "description": "Marker BOI-TEST-749231 accessed",
            },
        ],
    )
    otp_result = verifier.verify(otp_hypothesis, otp_findings, [])
    assert otp_result.verified_status == "CONFIRMED"
    assert otp_result.confirmation_allowed is True
    assert otp_result.evidence_strength == 1.0

    # 4B: Strong Exfiltration with PAYLOAD_CORRELATED
    exfil_hypothesis = {
        "hypothesis_id": "H-002",
        "category": "DATA_EXFILTRATION",
        "status": "PROPOSED",
        "confidence": 0.80,
    }
    exfil_findings = _sample_findings(
        permissions=["android.permission.INTERNET"],
        runtime_evidence=[
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_marker_correlation",
                "timestamp_ms": 1000,
                "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
                "confidence": 0.95,
                "description": "Marker BOI-TEST-749231 accessed",
            },
            {
                "evidence_id": "R002",
                "evidence_type": "network_destination",
                "timestamp_ms": 1500,
                "trust_level": EvidenceTrustLevel.PAYLOAD_CORRELATED,
                "confidence": 0.95,
                "description": "Outbound HTTP POST sending BOI-TEST-749231 to https://c2.example.invalid/collect",
                "metadata": {"destination": "https://c2.example.invalid/collect", "payload_correlated": True},
            },
        ],
    )
    exfil_result = verifier.verify(exfil_hypothesis, exfil_findings, [])
    assert exfil_result.verified_status == "CONFIRMED"
    assert exfil_result.confirmation_allowed is True
    assert exfil_result.evidence_strength == 0.95


# Test 5: Trust downgrade changes verifier output predictably
def test_trust_downgrade_changes_verifier_output_predictably() -> None:
    verifier = HypothesisVerifier()
    hypothesis = {
        "hypothesis_id": "H-003",
        "category": "ACCESSIBILITY_ABUSE",
        "status": "CONFIRMED",
        "confidence": 0.90,
    }
    # Dumpsys active binding absent, only log keyword matched
    findings = {
        "extraction": {
            "permissions": {"requested": ["android.permission.INTERNET"]},
            "components": {"accessibility_service": True},
            "code_signals": {"input_injection": {"detected": True}},
            "network_indicators": {"domains": [], "ips": [], "urls": []},
            "coverage": {"dynamic": True},
        },
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "evidence_type": "accessibility_behavior",
                "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
                "confidence": 0.70,
                "description": "Matched accessibility keyword in logcat",
            }
        ],
        "experiment_results": [],
    }
    result = verifier.verify(hypothesis, findings, [])
    assert result.verified_status == "SUPPORTED"
    assert result.confirmation_allowed is False
    assert "active service binding was not confirmed" in result.deterministic_explanation


# Test 6: Runtime scorer respects trust threshold
def test_runtime_scorer_respects_trust_threshold() -> None:
    scorer = RiskScorer()
    extracted = {
        "analysis_quality": "full",
        "file": {"sha256": "abc", "name": "test.apk", "embedded_payloads": []},
        "permissions": {"requested": ["android.permission.INTERNET"], "flagged_dangerous": []},
        "components": {"sms_receiver": False, "accessibility_service": False, "boot_receiver": False, "activities": [], "services": [], "receivers": [], "providers": []},
        "code_signals": {"sms_api": {"detected": False}, "installed_app_enumeration": {"detected": False}, "input_injection": {"detected": False}, "dynamic_code_loading": {"detected": False}, "reflection": {"detected": False}, "command_execution": {"detected": False}},
        "certificate": {"bank_impersonation_flag": False},
        "obfuscation": {"likely_name_obfuscation": False},
        "coverage": {"archive": True, "manifest": True, "dex": True, "certificate": True, "dynamic": True},
    }
    delta = {"score": 0.0, "category": "banking"}

    # Case A: Network evidence without payload correlation
    unverified_exfil_evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_marker_correlation",
            "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
            "confidence": 0.8,
            "description": "Marker in log",
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
            "confidence": 0.7,
            "description": "Network ping to c2.invalid",
            "metadata": {"payload_correlated": False},
        },
    ]
    risk_unverified = scorer.calculate(extracted, delta, runtime_evidence=unverified_exfil_evidence)
    # RUNTIME-EXFIL-001 should NOT fire without payload correlation
    assert not any(r["rule_id"] == "RUNTIME-EXFIL-001" for r in risk_unverified["runtime_rules"])

    # Case B: Verified PAYLOAD_CORRELATED evidence
    verified_exfil_evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_marker_correlation",
            "trust_level": EvidenceTrustLevel.LOG_OBSERVED,
            "confidence": 0.95,
            "description": "Marker in log",
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "trust_level": EvidenceTrustLevel.PAYLOAD_CORRELATED,
            "confidence": 0.95,
            "description": "Marker in outbound flow",
            "metadata": {"payload_correlated": True},
        },
    ]
    risk_verified = scorer.calculate(extracted, delta, runtime_evidence=verified_exfil_evidence)
    assert any(r["rule_id"] == "RUNTIME-EXFIL-001" for r in risk_verified["runtime_rules"])
    assert risk_verified["runtime_adjustment"] > risk_unverified["runtime_adjustment"]


# Test 7: Evidence IDs and provenance remain attached
def test_evidence_ids_and_provenance_remain_attached() -> None:
    verifier = HypothesisVerifier()
    hypothesis = {
        "hypothesis_id": "H-001",
        "category": "OTP_INTERCEPTION",
        "status": "PROPOSED",
        "confidence": 0.80,
    }
    findings = _sample_findings(
        permissions=["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        sms_receiver=True,
        runtime_evidence=[
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_sms_delivered",
                "trust_level": EvidenceTrustLevel.INSTRUMENTED,
                "confidence": 1.0,
                "description": "Delivered",
            },
            {
                "evidence_id": "R002",
                "evidence_type": "sms_access",
                "trust_level": EvidenceTrustLevel.INSTRUMENTED,
                "confidence": 0.95,
                "description": "Handled",
            },
        ],
        experiment_results=[
            {
                "experiment_id": "EXP001",
                "experiment_type": "SYNTHETIC_SMS",
                "status": "COMPLETED",
                "evidence_ids": ["R001", "R002"],
            }
        ],
    )
    result = verifier.verify(hypothesis, findings, [])
    assert result.runtime_evidence_ids == ["R001", "R002"]
    assert result.experiment_result_ids == ["EXP001"]
