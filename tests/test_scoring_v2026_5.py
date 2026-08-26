from __future__ import annotations

from typing import Any

from fraudshield.deceptiscope.scoring import RiskScorer


def _sample_extraction(
    *,
    permissions: list[str] | None = None,
    sms_receiver: bool = False,
    accessibility: bool = False,
    dynamic_code_loading: bool = False,
    dynamic_coverage: bool = False,
) -> dict[str, Any]:
    return {
        "analysis_quality": "full",
        "file": {"sha256": "abcdef1234567890", "name": "sample.apk", "embedded_payloads": []},
        "permissions": {
            "requested": permissions or ["android.permission.INTERNET"],
            "flagged_dangerous": [],
        },
        "components": {
            "sms_receiver": sms_receiver,
            "accessibility_service": accessibility,
            "boot_receiver": False,
            "activities": ["MainActivity"],
            "services": [],
            "receivers": ["SmsReceiver"] if sms_receiver else [],
            "providers": [],
        },
        "code_signals": {
            "sms_api": {"detected": False, "evidence": []},
            "installed_app_enumeration": {"detected": False, "evidence": []},
            "input_injection": {"detected": False, "evidence": []},
            "dynamic_code_loading": {"detected": dynamic_code_loading, "evidence": []},
            "reflection": {"detected": False, "evidence": []},
            "command_execution": {"detected": False, "evidence": []},
        },
        "certificate": {"bank_impersonation_flag": False},
        "obfuscation": {"likely_name_obfuscation": False},
        "coverage": {
            "archive": True,
            "manifest": True,
            "dex": True,
            "certificate": True,
            "dynamic": dynamic_coverage,
        },
    }


# Test A: static_score = X, runtime strongly verifies OTP theft -> final score > static_score
def test_two_stage_risk_scoring_escalates_on_verified_otp_theft() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(
        permissions=["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
        sms_receiver=True,
        dynamic_coverage=True,
    )
    delta = {"score": 0.7, "category": "banking"}

    # Base static score
    static_risk = scorer.calculate(extracted, delta)
    static_score = static_risk["static_score"]
    assert static_risk["runtime_adjustment"] == 0
    assert static_risk["overall_score"] == static_score

    # Runtime evidence with OTP interception + external network connection
    runtime_evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "confidence": 1.0,
            "description": "Synthetic OTP marker BOI-TEST-749231 delivered to SMS receiver",
        },
        {
            "evidence_id": "R002",
            "evidence_type": "sms_access",
            "confidence": 0.95,
            "description": "Package read incoming SMS broadcast with synthetic OTP marker",
        },
        {
            "evidence_id": "R003",
            "evidence_type": "synthetic_marker_correlation",
            "confidence": 0.95,
            "description": "Synthetic marker BOI-TEST-749231 observed in outbound flow",
        },
        {
            "evidence_id": "R004",
            "evidence_type": "network_destination",
            "confidence": 0.90,
            "description": "Outbound TCP connection to 198.51.100.24:8443",
        },
    ]

    final_risk = scorer.calculate(extracted, delta, runtime_evidence=runtime_evidence)
    assert final_risk["model_version"] == "apk-risk-2026.5"
    assert final_risk["static_score"] == static_score
    assert final_risk["runtime_adjustment"] > 0
    assert final_risk["overall_score"] == static_score + final_risk["runtime_adjustment"]
    assert final_risk["overall_score"] > static_score
    assert len(final_risk["runtime_rules"]) >= 2
    assert final_risk["runtime_confirmation"] > 0.5


# Test B: AI claims OTP theft but runtime verifier does not confirm it -> runtime_adjustment = 0
def test_ai_claims_otp_theft_without_runtime_confirmation() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(
        permissions=["android.permission.READ_SMS"],
        sms_receiver=False,
        dynamic_coverage=True,
    )
    delta = {"score": 0.2, "category": "banking"}

    # Runtime evidence contains ONLY benign startup, no SMS delivery or access
    runtime_evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "app_launch",
            "confidence": 1.0,
            "description": "MainActivity launched successfully",
        }
    ]

    risk = scorer.calculate(extracted, delta, runtime_evidence=runtime_evidence)
    assert risk["runtime_adjustment"] == 0
    assert risk["overall_score"] == risk["static_score"]
    assert risk["runtime_rules"] == []
    assert risk["runtime_confirmation"] == 0.0


# Test C: Requested-but-not-run experiment -> runtime_adjustment = 0
def test_requested_not_run_experiment_produces_zero_runtime_adjustment() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(permissions=["android.permission.READ_SMS"], dynamic_coverage=False)
    delta = {"score": 0.0, "category": "banking"}

    # No runtime evidence was generated because experiment was NOT_RUN / SKIPPED
    risk = scorer.calculate(extracted, delta, runtime_evidence=[])
    assert risk["runtime_adjustment"] == 0
    assert risk["overall_score"] == risk["static_score"]
    assert risk["runtime_rules"] == []


# Test D: Failed experiment -> runtime_adjustment = 0
def test_failed_experiment_produces_zero_runtime_adjustment() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(permissions=["android.permission.READ_SMS"], dynamic_coverage=True)
    delta = {"score": 0.0, "category": "banking"}

    # Sandbox failed or timed out, no valid behavioral evidence
    experiment_results = [
        {
            "experiment_id": "EXP001",
            "status": "FAILED",
            "error": "TimeoutException: emulator did not respond",
            "evidence_ids": [],
        }
    ]

    risk = scorer.calculate(
        extracted,
        delta,
        runtime_evidence=[],
        experiment_results=experiment_results,
    )
    assert risk["runtime_adjustment"] == 0
    assert risk["overall_score"] == risk["static_score"]


# Test E: Contradicted hypothesis -> no runtime escalation
def test_contradicted_hypothesis_has_no_runtime_escalation() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(permissions=["android.permission.INTERNET"], dynamic_coverage=True)
    delta = {"score": 0.0, "category": "banking"}

    verifications = [
        {
            "hypothesis_id": "H-001",
            "verified_status": "CONTRADICTED",
            "deterministic_explanation": "SMS receiver was not invoked; background traffic absent.",
        }
    ]

    risk = scorer.calculate(
        extracted,
        delta,
        runtime_evidence=[],
        verifications=verifications,
    )
    assert risk["runtime_adjustment"] == 0
    assert risk["overall_score"] == risk["static_score"]


# Test F: Strong trusted runtime evidence affects score even if AI confidence is low
def test_strong_runtime_evidence_affects_score_independently_of_ai() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(
        permissions=["android.permission.INTERNET"],
        dynamic_coverage=True,
    )
    delta = {"score": 0.0, "category": "banking"}

    runtime_evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "dynamic_code_load",
            "confidence": 0.95,
            "description": "DexClassLoader loaded payload.dex dynamically",
        }
    ]

    # Even with empty or zero AI confidence, deterministic rule fires
    risk = scorer.calculate(extracted, delta, runtime_evidence=runtime_evidence)
    assert risk["runtime_adjustment"] == 15
    assert any(rule["rule_id"] == "RUNTIME-DCL-001" for rule in risk["runtime_rules"])
    assert risk["overall_score"] == risk["static_score"] + 15


# Test G: AI confidence=1.0 alone cannot change score
def test_ai_confidence_alone_cannot_alter_score() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(permissions=["android.permission.INTERNET"], dynamic_coverage=False)
    delta = {"score": 0.0, "category": "banking"}

    risk_baseline = scorer.calculate(extracted, delta)

    # Calling scoring with different context without runtime evidence changes nothing
    risk_with_fake_ai = scorer.calculate(
        extracted,
        delta,
        runtime_evidence=[],
        verifications=[{"ai_confidence": 1.0, "status": "CONFIRMED"}],
    )
    assert risk_with_fake_ai["overall_score"] == risk_baseline["overall_score"]
    assert risk_with_fake_ai["runtime_adjustment"] == 0


# Test H: Score never exceeds 100
def test_score_never_exceeds_100() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        sms_receiver=True,
        accessibility=True,
        dynamic_code_loading=True,
        dynamic_coverage=True,
    )
    # High delta
    delta = {"score": 1.0, "category": "banking"}

    # Inject every single runtime rule evidence
    runtime_evidence = [
        {"evidence_id": "R001", "evidence_type": "synthetic_sms_delivered", "confidence": 1.0, "description": "Delivered"},
        {"evidence_id": "R002", "evidence_type": "sms_access", "confidence": 1.0, "description": "Accessed"},
        {"evidence_id": "R003", "evidence_type": "synthetic_marker_correlation", "confidence": 1.0, "description": "Marker"},
        {"evidence_id": "R004", "evidence_type": "network_destination", "confidence": 0.9, "description": "Network"},
        {"evidence_id": "R005", "evidence_type": "accessibility_behavior", "confidence": 0.95, "description": "Accessibility"},
        {"evidence_id": "R006", "evidence_type": "dynamic_code_load", "confidence": 0.95, "description": "DCL"},
        {"evidence_id": "R007", "evidence_type": "webview_activity", "confidence": 0.9, "description": "WebView"},
    ]

    risk = scorer.calculate(extracted, delta, runtime_evidence=runtime_evidence)
    assert risk["overall_score"] <= 100
    assert risk["runtime_adjustment"] <= scorer.global_runtime_cap


# Test I: Runtime category and global caps work
def test_runtime_category_and_global_caps_enforced() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(dynamic_coverage=True)
    delta = {"score": 0.0, "category": "banking"}

    # Provide evidence that would trigger multiple rules in credential_theft and payment_manipulation
    runtime_evidence = [
        {"evidence_id": "R001", "evidence_type": "synthetic_sms_delivered", "confidence": 1.0, "description": "Delivered"},
        {"evidence_id": "R002", "evidence_type": "sms_access", "confidence": 1.0, "description": "Accessed"},
        {"evidence_id": "R003", "evidence_type": "synthetic_marker_correlation", "confidence": 1.0, "description": "Marker"},
        {"evidence_id": "R004", "evidence_type": "network_destination", "confidence": 0.9, "description": "Network"},
        {"evidence_id": "R005", "evidence_type": "accessibility_behavior", "confidence": 0.95, "description": "Accessibility"},
        {"evidence_id": "R006", "evidence_type": "dynamic_code_load", "confidence": 0.95, "description": "DCL"},
        {"evidence_id": "R007", "evidence_type": "webview_activity", "confidence": 0.9, "description": "WebView"},
    ]

    risk = scorer.calculate(extracted, delta, runtime_evidence=runtime_evidence)
    # Global cap is 35
    assert risk["runtime_adjustment"] == scorer.global_runtime_cap
    assert risk["runtime_adjustment"] == 35

    # Check that individual category additions respected category caps
    cred_rules = [r for r in risk["runtime_rules"] if r["category"] == "credential_theft"]
    cred_points = sum(r["points"] for r in cred_rules)
    assert cred_points <= scorer.category_runtime_caps["credential_theft"]


# Test J: Existing static scoring regression tests still pass
def test_static_scoring_regression_baseline() -> None:
    scorer = RiskScorer()
    extracted = _sample_extraction(permissions=["android.permission.INTERNET"], dynamic_coverage=False)
    delta = {"score": 0.0, "category": "utility"}

    risk = scorer.calculate(extracted, delta)
    assert risk["model_version"] == "apk-risk-2026.5"
    assert risk["overall_score"] < 25
    assert risk["severity"] == "LOW"
    assert "static_score" in risk
    assert "runtime_adjustment" in risk
    assert "static_rules" in risk
    assert "runtime_rules" in risk
    assert "evidence" in risk
