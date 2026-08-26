from __future__ import annotations

import base64

from fraudshield.deceptiscope.lineage import (
    DataLineageCorrelator,
    SyntheticMarkerManager,
)
from fraudshield.deceptiscope.scoring import DeterministicScorer
from fraudshield.deceptiscope.verifier import HypothesisVerifier


# ---------------------------------------------------------------------------
# Test 1: Raw Marker Correlation
# ---------------------------------------------------------------------------
def test_raw_marker_correlation() -> None:
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-882211")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "Synthetic SMS delivered containing DS-TEST-OTP-882211",
            "api": "android.telephony.SmsMessage.createFromPdu",
            "metadata": {"has_synthetic_marker": True, "preview": "Your DS-TEST-OTP-882211 is..."},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "instrumented_network",
            "description": "Outbound HTTP request to https://evil-c2.net/exfil",
            "api": "okhttp3.OkHttpClient.newCall",
            "metadata": {
                "url": "https://evil-c2.net/exfil",
                "body_preview_redacted": "otp=DS-TEST-OTP-882211",
                "has_synthetic_marker": True,
            },
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker])

    assert len(lineages) == 1
    pl = lineages[0]
    assert pl.lineage_id == "P001"
    assert pl.marker_id == marker.marker_id
    assert pl.evidence_chain == ["R001", "R002"]
    assert pl.is_complete_exfiltration is True
    assert pl.steps[0].phase == "INGRESS"
    assert pl.steps[1].phase == "EGRESS"
    assert pl.trust_level == "PAYLOAD_CORRELATED"


# ---------------------------------------------------------------------------
# Test 2: Base64 Transformed Marker Correlation
# ---------------------------------------------------------------------------
def test_base64_marker_correlation() -> None:
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-334455")
    b64_val = base64.b64encode(b"DS-TEST-OTP-334455").decode("ascii")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "sms_access",
            "description": "SMS PDU parsed with DS-TEST-OTP-334455",
            "api": "android.telephony.SmsMessage.createFromPdu",
            "metadata": {},
        },
        {
            "evidence_id": "R002",
            "evidence_type": "instrumented_network",
            "description": "Outbound POST request with encoded payload",
            "api": "okhttp3.OkHttpClient.newCall",
            "metadata": {"payload": f'{{"token": "{b64_val}"}}'},
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker])

    assert len(lineages) == 1
    pl = lineages[0]
    assert pl.evidence_chain == ["R001", "R002"]
    assert pl.steps[1].transform_type == "base64"
    assert pl.is_complete_exfiltration is True


# ---------------------------------------------------------------------------
# Test 3: Unrelated Network Call Does Not Correlate
# ---------------------------------------------------------------------------
def test_unrelated_network_call_no_correlation() -> None:
    manager = SyntheticMarkerManager()
    marker = manager.create_otp_marker(custom_value="DS-TEST-OTP-112233")

    evidence = [
        {
            "evidence_id": "R001",
            "evidence_type": "synthetic_sms_delivered",
            "description": "Delivered DS-TEST-OTP-112233",
            "api": "createFromPdu",
        },
        {
            "evidence_id": "R002",
            "evidence_type": "network_destination",
            "description": "Unrelated telemetry to https://analytics.google.com/event",
            "api": "HttpURLConnection.connect",
            "metadata": {"destination": "https://analytics.google.com/event"},
        },
    ]

    correlator = DataLineageCorrelator()
    lineages = correlator.correlate(evidence, [marker])

    assert len(lineages) == 1
    pl = lineages[0]
    # Only R001 matched, R002 has no marker
    assert pl.evidence_chain == ["R001"]
    assert pl.is_complete_exfiltration is False


# ---------------------------------------------------------------------------
# Test 4: Temporal Proximity Alone Does Not Correlate (Capped at SUPPORTED)
# ---------------------------------------------------------------------------
def test_temporal_proximity_alone_does_not_confirm_exfiltration() -> None:
    verifier = HypothesisVerifier()

    findings = {
        "permissions": {"requested": ["android.permission.INTERNET", "android.permission.RECEIVE_SMS"]},
        "components": {"sms_receiver": True},
        "urls": ["https://evil-c2.net"],
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "timestamp_ms": 1000,
                "evidence_type": "synthetic_marker_correlation",
                "trust_level": "LOG_OBSERVED",
                "description": "Logcat match for synthetic marker",
                "metadata": {},
            },
            {
                "evidence_id": "R002",
                "timestamp_ms": 1500,  # 500ms later
                "evidence_type": "network_destination",
                "trust_level": "SYSTEM_OBSERVED",
                "description": "Network connection observed",
                "metadata": {"destination": "https://evil-c2.net/heartbeat"},  # No marker in payload
            },
        ],
        "dynamic_experiment_results": [
            {"experiment_id": "EXP001", "experiment_type": "NETWORK_OBSERVATION", "status": "COMPLETED"},
        ],
    }

    hypo = {
        "hypothesis_id": "H001",
        "category": "DATA_EXFILTRATION",
        "status": "CONFIRMED",  # AI claims confirmed
        "confidence": 0.99,
    }

    result = verifier.verify(hypo, findings, normalized_evidence=[])
    # Temporal correlation alone must NOT be CONFIRMED! Capped at SUPPORTED.
    assert result.verified_status == "SUPPORTED"
    assert result.confirmation_allowed is False
    assert "temporal correlation only" in result.deterministic_explanation


# ---------------------------------------------------------------------------
# Test 5: Failed SMS Experiment Cannot Confirm OTP Theft
# ---------------------------------------------------------------------------
def test_failed_sms_experiment_cannot_confirm_otp() -> None:
    verifier = HypothesisVerifier()

    findings = {
        "permissions": {"requested": ["android.permission.RECEIVE_SMS"]},
        "components": {"sms_receiver": True},
        "runtime_evidence": [],
        "dynamic_experiment_results": [
            {
                "experiment_id": "EXP001",
                "experiment_type": "SYNTHETIC_SMS",
                "status": "FAILED",
                "error": "Emulator dropped connection",
            },
        ],
    }

    hypo = {
        "hypothesis_id": "H002",
        "category": "OTP_INTERCEPTION",
        "status": "CONFIRMED",
        "confidence": 0.95,
    }

    result = verifier.verify(hypo, findings, normalized_evidence=[])
    assert result.verified_status == "INCONCLUSIVE"
    assert result.confirmation_allowed is False


# ---------------------------------------------------------------------------
# Test 6: Marker Consumed But Not Transmitted -> Interception Confirms, Exfil Does Not
# ---------------------------------------------------------------------------
def test_marker_consumed_not_transmitted() -> None:
    verifier = HypothesisVerifier()

    findings = {
        "permissions": {"requested": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]},
        "components": {"sms_receiver": True},
        "urls": ["https://some-api.com"],
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "evidence_type": "synthetic_sms_delivered",
                "trust_level": "INSTRUMENTED",
                "description": "Synthetic SMS delivered with BOI-TEST-749231",
                "confidence": 1.0,
                "metadata": {},
            },
            {
                "evidence_id": "R002",
                "evidence_type": "sms_access",
                "trust_level": "INSTRUMENTED",
                "description": "Instrumented SmsMessage.createFromPdu consumed BOI-TEST-749231",
                "confidence": 0.95,
                "metadata": {},
            },
        ],
        "dynamic_experiment_results": [
            {"experiment_id": "EXP001", "experiment_type": "SYNTHETIC_SMS", "status": "COMPLETED"},
            {"experiment_id": "EXP002", "experiment_type": "NETWORK_OBSERVATION", "status": "COMPLETED"},
        ],
    }

    # 1. OTP Interception
    otp_hypo = {"hypothesis_id": "H001", "category": "OTP_INTERCEPTION", "confidence": 0.9}
    otp_res = verifier.verify(otp_hypo, findings, normalized_evidence=[])
    assert otp_res.verified_status == "CONFIRMED"

    # 2. Data Exfiltration
    exfil_hypo = {"hypothesis_id": "H002", "category": "DATA_EXFILTRATION", "confidence": 0.9}
    exfil_res = verifier.verify(exfil_hypo, findings, normalized_evidence=[])
    assert exfil_res.verified_status != "CONFIRMED"
    assert exfil_res.confirmation_allowed is False


# ---------------------------------------------------------------------------
# Test 7: Outbound Marker Correlation -> Exfiltration Confirmed
# ---------------------------------------------------------------------------
def test_outbound_marker_correlation_confirms_exfiltration() -> None:
    verifier = HypothesisVerifier()

    findings = {
        "permissions": {"requested": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]},
        "components": {"sms_receiver": True},
        "urls": ["https://c2.fraud.net/upload"],
        "runtime_evidence": [
            {
                "evidence_id": "R001",
                "timestamp_ms": 1000,
                "evidence_type": "synthetic_marker_correlation",
                "trust_level": "INSTRUMENTED",
                "description": "Marker BOI-TEST-749231 read from SMS PDU",
                "metadata": {},
            },
            {
                "evidence_id": "R002",
                "timestamp_ms": 1500,
                "evidence_type": "network_destination",
                "trust_level": "PAYLOAD_CORRELATED",
                "description": "HTTP POST with BOI-TEST-749231 in request body",
                "metadata": {"payload": "otp=BOI-TEST-749231&victim=123", "payload_correlated": True},
            },
        ],
        "dynamic_experiment_results": [
            {"experiment_id": "EXP001", "experiment_type": "NETWORK_OBSERVATION", "status": "COMPLETED"},
        ],
    }

    exfil_hypo = {"hypothesis_id": "H001", "category": "DATA_EXFILTRATION", "confidence": 0.5}
    exfil_res = verifier.verify(exfil_hypo, findings, normalized_evidence=[])
    assert exfil_res.verified_status == "CONFIRMED"
    assert exfil_res.confirmation_allowed is True


# ---------------------------------------------------------------------------
# Test 8: AI Statement Alone Has Zero Effect
# ---------------------------------------------------------------------------
def test_ai_statement_alone_has_zero_effect() -> None:
    verifier = HypothesisVerifier()

    # Empty static + empty runtime
    empty_findings = {
        "permissions": {"requested": []},
        "components": {},
        "runtime_evidence": [],
        "dynamic_experiment_results": [],
    }

    hypo = {
        "hypothesis_id": "H001",
        "category": "OTP_INTERCEPTION",
        "status": "CONFIRMED",
        "confidence": 1.0,  # AI is 100% confident
        "reasoning": "I the AI think this is a banking trojan without proof",
    }

    res = verifier.verify(hypo, empty_findings, normalized_evidence=[])
    assert res.verified_status in ("PROPOSED", "UNCONFIRMED", "INCONCLUSIVE")
    assert res.confirmation_allowed is False


# ---------------------------------------------------------------------------
# Test 9: Runtime Scoring Uses Trusted Correlated Evidence Only
# ---------------------------------------------------------------------------
def test_runtime_scoring_uses_trusted_correlated_evidence() -> None:
    scorer = DeterministicScorer()

    extraction = {
        "permissions": {"requested": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]},
        "components": {"sms_receiver": True},
        "urls": ["https://evil-c2.net"],
    }
    fraud_delta = {"delta_score": 15, "signals": []}

    # Case A: Generic unverified log match
    res_generic = scorer.calculate(
        extracted=extraction,
        fraud_delta=fraud_delta,
        engine_analysis={"engines": {}},
        runtime_evidence=[
            {"evidence_id": "R001", "evidence_type": "logcat_match", "trust_level": "LOG_OBSERVED", "metadata": {}}
        ],
        verifications=[{"hypothesis_id": "H001", "verified_status": "SUPPORTED"}],
    )

    # Case B: Instrumented payload correlation with verified rules
    res_correlated = scorer.calculate(
        extracted=extraction,
        fraud_delta=fraud_delta,
        engine_analysis={"engines": {}},
        runtime_evidence=[
            {"evidence_id": "R001", "evidence_type": "synthetic_sms_delivered", "trust_level": "INSTRUMENTED", "metadata": {}},
            {"evidence_id": "R002", "evidence_type": "sms_access", "trust_level": "INSTRUMENTED", "description": "SmsMessage read marker", "metadata": {}},
            {"evidence_id": "R003", "evidence_type": "network_destination", "trust_level": "PAYLOAD_CORRELATED", "confidence": 1.0, "description": "HTTP POST with marker", "metadata": {"payload_correlated": True}},
        ],
        verifications=[{"hypothesis_id": "H001", "verified_status": "CONFIRMED"}],
    )

    assert res_correlated["overall_score"] > res_generic["overall_score"]
    assert res_correlated["runtime_adjustment"] > res_generic["runtime_adjustment"]
    assert res_correlated["model_version"] == "apk-risk-2026.5"
