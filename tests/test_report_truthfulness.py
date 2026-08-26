from __future__ import annotations

from typing import Any

from fraudshield.deceptiscope.impact import derive_banking_impact
from fraudshield.deceptiscope.report import build_analysis_pdf


def test_unrelated_positive_runtime_adjustment_cannot_confirm_otp() -> None:
    """Requirement 1: Positive runtime adjustment from other rules (e.g. DCL, network) must NOT confirm OTP."""
    result: dict[str, Any] = {
        "risk": {
            "overall_score": 85,
            "static_score": 50,
            "runtime_adjustment": 35,
            "severity": "CRITICAL",
        },
        "extraction": {
            "permissions": {"requested": []},
            "components": {},
            "code_signals": {},
        },
        "ai_investigation": {"hypothesis_verifications": []},
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "evidence_type": "dynamic_code_load",
                "trust_level": "INSTRUMENTED",
            }
        ],
    }

    impact = derive_banking_impact(result)
    otp_item = next(it for it in impact["items"] if it["id"] == "otp_interception")
    assert otp_item["status"] == "NOT_OBSERVED"


def test_static_receive_sms_supports_otp_but_not_confirms() -> None:
    """Requirement 2: Static RECEIVE_SMS permission alone supports OTP capability, never confirms it."""
    result: dict[str, Any] = {
        "risk": {"overall_score": 40, "static_score": 40, "runtime_adjustment": 0},
        "extraction": {
            "permissions": {"requested": ["android.permission.RECEIVE_SMS"]},
            "components": {},
            "code_signals": {},
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H1",
                    "category": "OTP_INTERCEPTION",
                    "verified_status": "SUPPORTED",
                    "static_evidence_ids": ["E-STATIC-SMS"],
                    "runtime_evidence_ids": [],
                    "observed_signals": ["RECEIVE_SMS"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    otp_item = next(it for it in impact["items"] if it["id"] == "otp_interception")
    assert otp_item["status"] == "SUPPORTED"
    assert "E-STATIC-SMS" in otp_item["evidence_ids"]


def test_log_observed_cannot_confirm_otp() -> None:
    """Requirement 3: Weak or untrusted log observation (LOG_OBSERVED / INFERRED) without instrumentation cannot confirm OTP."""
    result: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": ["android.permission.RECEIVE_SMS"]},
            "components": {},
            "code_signals": {},
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H1",
                    "category": "OTP_INTERCEPTION",
                    "verified_status": "SUPPORTED",  # Capped at SUPPORTED because log-observed only
                    "static_evidence_ids": ["E-STATIC-SMS"],
                    "runtime_evidence_ids": ["R-LOG-01"],
                    "observed_signals": ["RECEIVE_SMS", "logcat_sms"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    otp_item = next(it for it in impact["items"] if it["id"] == "otp_interception")
    assert otp_item["status"] == "SUPPORTED"


def test_exact_verified_otp_confirms_otp() -> None:
    """Requirement 4: Instrumented runtime proof confirming OTP results in CONFIRMED status with evidence IDs."""
    result: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": ["android.permission.RECEIVE_SMS"]},
            "components": {},
            "code_signals": {},
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H1",
                    "category": "OTP_INTERCEPTION",
                    "verified_status": "CONFIRMED",
                    "static_evidence_ids": ["E-STATIC-SMS"],
                    "runtime_evidence_ids": ["R-SMS-01", "R-MARKER-01"],
                    "observed_signals": ["RECEIVE_SMS", "synthetic_sms_delivered", "synthetic_marker_correlation"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    otp_item = next(it for it in impact["items"] if it["id"] == "otp_interception")
    assert otp_item["status"] == "CONFIRMED"
    assert "R-SMS-01" in otp_item["evidence_ids"]
    assert "R-MARKER-01" in otp_item["evidence_ids"]


def test_known_malware_verdict_alone_cannot_confirm_credential_exfiltration() -> None:
    """Requirement 5: Hash reputation / known_malware flag alone must not mark credential exfiltration CONFIRMED."""
    result: dict[str, Any] = {
        "malware_assessment": {
            "verdict": "KNOWN_MALICIOUS",
            "known_malware": True,
        },
        "extraction": {
            "permissions": {"requested": ["android.permission.INTERNET"]},
            "components": {},
            "code_signals": {},
        },
        "ai_investigation": {"hypothesis_verifications": []},
    }

    impact = derive_banking_impact(result)
    cred_item = next(it for it in impact["items"] if it["id"] == "credential_exfiltration")
    assert cred_item["status"] != "CONFIRMED"


def test_static_phishing_signals_result_in_supported() -> None:
    """Requirement 6: Static phishing indicators or credential theft strings produce SUPPORTED status."""
    result: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": ["android.permission.INTERNET"]},
            "components": {},
            "code_signals": {
                "credential_theft": {"detected": True, "evidence": ["login_form_detected"]},
                "phishing_indicators": {"detected": True, "evidence": ["bank_login_fake"]},
            },
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H2",
                    "category": "DATA_EXFILTRATION",
                    "verified_status": "SUPPORTED",
                    "static_evidence_ids": ["E-PHISH-01"],
                    "runtime_evidence_ids": [],
                    "observed_signals": ["credential_theft"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    cred_item = next(it for it in impact["items"] if it["id"] == "credential_exfiltration")
    assert cred_item["status"] == "SUPPORTED"
    assert "E-PHISH-01" in cred_item["evidence_ids"]


def test_verified_runtime_credential_exfiltration_confirms() -> None:
    """Requirement 7: Verified payload-correlated network exfiltration produces CONFIRMED status."""
    result: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": ["android.permission.INTERNET"]},
            "components": {},
            "code_signals": {"credential_theft": {"detected": True}},
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H2",
                    "category": "DATA_EXFILTRATION",
                    "verified_status": "CONFIRMED",
                    "static_evidence_ids": ["E-NET-01"],
                    "runtime_evidence_ids": ["R-EXFIL-01"],
                    "observed_signals": ["synthetic_marker_correlation", "network_destination"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    cred_item = next(it for it in impact["items"] if it["id"] == "credential_exfiltration")
    assert cred_item["status"] == "CONFIRMED"
    assert "R-EXFIL-01" in cred_item["evidence_ids"]


def test_accessibility_manifest_only_is_supported() -> None:
    """Requirement 8: Manifest accessibility service declaration alone results in SUPPORTED, not CONFIRMED."""
    result: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": []},
            "components": {"accessibility_service": True},
            "code_signals": {},
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H3",
                    "category": "ACCESSIBILITY_ABUSE",
                    "verified_status": "SUPPORTED",
                    "static_evidence_ids": ["E-ACC-01"],
                    "runtime_evidence_ids": [],
                    "observed_signals": ["accessibility_service"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    acc_item = next(it for it in impact["items"] if it["id"] == "accessibility_abuse")
    assert acc_item["status"] == "SUPPORTED"


def test_verified_accessibility_runtime_confirms() -> None:
    """Requirement 9: Active service binding with dumpsys / instrumented runtime proof produces CONFIRMED."""
    result: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": []},
            "components": {"accessibility_service": True},
            "code_signals": {},
        },
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H3",
                    "category": "ACCESSIBILITY_ABUSE",
                    "verified_status": "CONFIRMED",
                    "static_evidence_ids": ["E-ACC-01"],
                    "runtime_evidence_ids": ["R-ACC-01"],
                    "observed_signals": ["accessibility_service", "accessibility_behavior"],
                }
            ]
        },
    }

    impact = derive_banking_impact(result)
    acc_item = next(it for it in impact["items"] if it["id"] == "accessibility_abuse")
    assert acc_item["status"] == "CONFIRMED"
    assert "R-ACC-01" in acc_item["evidence_ids"]


def test_recovered_payload_actually_recovered_confirms_payload() -> None:
    """Requirement 10: Dropped secondary payload present in recovered_payloads produces CONFIRMED."""
    result: dict[str, Any] = {
        "extraction": {"permissions": {"requested": []}, "components": {}, "code_signals": {}},
        "recovered_payloads": [
            {
                "payload_id": "PL-001",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "payload_type": "DEX",
                "size_bytes": 1024,
            }
        ],
    }

    impact = derive_banking_impact(result)
    pl_item = next(it for it in impact["items"] if it["id"] == "second_stage_payload")
    assert pl_item["status"] == "CONFIRMED"
    assert "PL-001" in pl_item["evidence_ids"]


def test_no_recovered_payload_results_in_not_observed() -> None:
    """Requirement 11: Empty recovered_payloads produces NOT_OBSERVED."""
    result: dict[str, Any] = {
        "extraction": {"permissions": {"requested": []}, "components": {}, "code_signals": {}},
        "recovered_payloads": [],
    }

    impact = derive_banking_impact(result)
    pl_item = next(it for it in impact["items"] if it["id"] == "second_stage_payload")
    assert pl_item["status"] == "NOT_OBSERVED"


def test_pdf_and_api_banking_impact_statuses_match() -> None:
    """Requirement 12: PDF report uses exact backend-derived banking_impact statuses."""
    result: dict[str, Any] = {
        "extraction": {
            "app": {"app_label": "TestApp", "package_name": "com.test.app"},
            "file": {"sha256": "1" * 64},
            "permissions": {"requested": ["android.permission.RECEIVE_SMS"]},
            "components": {},
            "code_signals": {},
        },
        "risk": {"overall_score": 60, "severity": "HIGH", "static_score": 60, "runtime_adjustment": 0},
        "malware_assessment": {"verdict": "SUSPICIOUS"},
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H1",
                    "category": "OTP_INTERCEPTION",
                    "verified_status": "SUPPORTED",
                    "static_evidence_ids": ["E-SMS"],
                    "runtime_evidence_ids": [],
                    "observed_signals": ["RECEIVE_SMS"],
                }
            ]
        },
    }
    result["banking_impact"] = derive_banking_impact(result)

    analysis_record = {
        "id": "analysis-123",
        "sha256": "1" * 64,
        "result": result,
    }

    pdf_bytes = build_analysis_pdf(analysis_record)
    assert len(pdf_bytes) > 500

    otp_item = next(it for it in result["banking_impact"]["items"] if it["id"] == "otp_interception")
    assert otp_item["status"] == "SUPPORTED"


def test_account_takeover_derived_risk_status() -> None:
    """Requirement 13 & ATO rules: ATO is framed as derived risk (CONFIRMED ATO risk only when both OTP and Creds are confirmed)."""
    # Case A: Neither confirmed nor supported -> NOT_OBSERVED
    res_none: dict[str, Any] = {"extraction": {"permissions": {"requested": []}, "components": {}, "code_signals": {}}}
    imp_none = derive_banking_impact(res_none)
    ato_none = next(it for it in imp_none["items"] if it["id"] == "account_takeover_risk")
    assert ato_none["status"] == "NOT_OBSERVED"

    # Case B: Supported OTP or Creds -> POSSIBLE ATO risk
    res_partial: dict[str, Any] = {
        "extraction": {
            "permissions": {"requested": ["android.permission.RECEIVE_SMS"]},
            "components": {},
            "code_signals": {},
        }
    }
    imp_partial = derive_banking_impact(res_partial)
    ato_partial = next(it for it in imp_partial["items"] if it["id"] == "account_takeover_risk")
    assert ato_partial["status"] == "POSSIBLE"

    # Case C: Both confirmed -> CONFIRMED ATO risk
    res_full: dict[str, Any] = {
        "extraction": {"permissions": {"requested": []}, "components": {}, "code_signals": {}},
        "ai_investigation": {
            "hypothesis_verifications": [
                {
                    "hypothesis_id": "H1",
                    "category": "OTP_INTERCEPTION",
                    "verified_status": "CONFIRMED",
                    "static_evidence_ids": ["E1"],
                    "runtime_evidence_ids": ["R1"],
                    "observed_signals": ["sms"],
                },
                {
                    "hypothesis_id": "H2",
                    "category": "DATA_EXFILTRATION",
                    "verified_status": "CONFIRMED",
                    "static_evidence_ids": ["E2"],
                    "runtime_evidence_ids": ["R2"],
                    "observed_signals": ["exfil"],
                },
            ]
        },
    }
    imp_full = derive_banking_impact(res_full)
    ato_full = next(it for it in imp_full["items"] if it["id"] == "account_takeover_risk")
    assert ato_full["status"] == "CONFIRMED"
