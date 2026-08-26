from __future__ import annotations

import time

import pytest

from fraudshield.core.config import Settings
from fraudshield.deceptiscope.dynamic import (
    EvidenceTrustLevel,
    _RuntimeEvidenceBuilder,
)
from fraudshield.deceptiscope.experiments import (
    ExperimentPlanner,
    ExperimentType,
)
from fraudshield.deceptiscope.runtime import (
    FridaHost,
    FridaRuntimeEvent,
    ObserverRegistry,
    RuntimeObserverStatus,
)


# ---------------------------------------------------------------------------
# Test 1: Valid Frida event normalization into RuntimeEvidence
# ---------------------------------------------------------------------------
def test_valid_frida_event_normalization() -> None:
    settings = Settings(dynamic_analysis_enabled=True)
    host = FridaHost(settings)
    builder = _RuntimeEvidenceBuilder("com.fakebank.trojan", time.monotonic())

    raw_msg = {
        "type": "send",
        "payload": {
            "schema": "deceptiscope.runtime.v1",
            "observer": "sms",
            "event_type": "SMS_PDU_PARSED",
            "timestamp_ms": 1700000000000,
            "api": "android.telephony.SmsMessage.createFromPdu([B)",
            "target_package": "com.fakebank.trojan",
            "metadata": {
                "sender": "+1234567890",
                "has_synthetic_marker": True,
                "preview": "Your BOI-TEST-749231 code",
            },
        },
    }

    event = host.process_raw_message(raw_msg)
    assert event is not None
    assert event.observer == "sms"
    assert event.event_type == "SMS_PDU_PARSED"

    evidence = host.normalize_to_evidence([event], builder)
    assert len(evidence) == 1
    assert evidence[0].evidence_id == "R001"
    assert evidence[0].trust_level == EvidenceTrustLevel.PAYLOAD_CORRELATED
    assert evidence[0].confidence == 0.95
    assert "correlated synthetic test marker" in evidence[0].description


# ---------------------------------------------------------------------------
# Test 2: Malformed event rejection
# ---------------------------------------------------------------------------
def test_malformed_event_rejection() -> None:
    settings = Settings(dynamic_analysis_enabled=True)
    host = FridaHost(settings)

    # Missing schema
    bad1 = {"type": "send", "payload": {"observer": "sms", "event_type": "SMS_PDU_PARSED"}}
    assert host.process_raw_message(bad1) is None

    # Wrong schema version
    bad2 = {
        "type": "send",
        "payload": {
            "schema": "deceptiscope.runtime.v2_unknown",
            "observer": "sms",
            "event_type": "SMS_PDU_PARSED",
            "timestamp_ms": 12345,
            "api": "test",
            "target_package": "com.test",
        },
    }
    assert host.process_raw_message(bad2) is None

    # Non-send message type (e.g. raw console error)
    bad3 = {"type": "error", "description": "some internal error"}
    assert host.process_raw_message(bad3) is None


# ---------------------------------------------------------------------------
# Test 3: Unknown observer event rejection
# ---------------------------------------------------------------------------
def test_unknown_observer_event_rejection() -> None:
    settings = Settings(dynamic_analysis_enabled=True)
    host = FridaHost(settings)

    unknown_obs = {
        "type": "send",
        "payload": {
            "schema": "deceptiscope.runtime.v1",
            "observer": "arbitrary_exploit_module",
            "event_type": "ROOT_EXPLOIT_TRIGGERED",
            "timestamp_ms": 12345,
            "api": "exploit()",
            "target_package": "com.target",
        },
    }
    assert host.process_raw_message(unknown_obs) is None


# ---------------------------------------------------------------------------
# Test 4: AI cannot inject scripts (system only runs trusted local JS files)
# ---------------------------------------------------------------------------
def test_ai_cannot_inject_scripts() -> None:
    registry = ObserverRegistry()
    with pytest.raises(ValueError, match="Unknown observer"):
        registry.load_observer_script("evil_injected_script.js")


# ---------------------------------------------------------------------------
# Test 5: AI cannot inject arbitrary commands
# ---------------------------------------------------------------------------
def test_ai_cannot_inject_commands() -> None:
    planner = ExperimentPlanner(Settings())
    injected_plan = [
        {
            "experiment_id": "EXP001",
            "hypothesis_id": "H001",
            "experiment_type": "SYNTHETIC_SMS",
            "objective": "Test SMS",
            "expected_signal": "Signal",
            "priority": 5,
            "command": "rm -rf /",  # Forbidden key
        }
    ]
    items, errors = planner.plan_from_payload(
        {"experiment_requests": injected_plan},
        hypotheses=[{"hypothesis_id": "H001"}],
    )
    assert len(items) == 0
    assert any("forbidden execution fields: command" in err for err in errors)


# ---------------------------------------------------------------------------
# Test 6: Experiment enum maps to trusted observer pack
# ---------------------------------------------------------------------------
def test_experiment_enum_maps_to_observer_pack() -> None:
    registry = ObserverRegistry()

    sms_obs = registry.get_observers_for_experiments([ExperimentType.SYNTHETIC_SMS])
    assert "sms" in sms_obs
    assert "network" in sms_obs

    acc_obs = registry.get_observers_for_experiments([ExperimentType.ACCESSIBILITY_OBSERVATION])
    assert acc_obs == ["accessibility"]

    dcl_obs = registry.get_observers_for_experiments([ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION])
    assert dcl_obs == ["dynamic_dex"]


# ---------------------------------------------------------------------------
# Test 7: Frida unavailable does not crash analysis
# ---------------------------------------------------------------------------
def test_frida_unavailable_graceful_handling() -> None:
    settings = Settings(dynamic_analysis_enabled=False)
    host = FridaHost(settings)
    status, events, warnings = host.run_observers("com.test.app", ["sms"])
    assert status in (RuntimeObserverStatus.UNAVAILABLE, RuntimeObserverStatus.FAILED)
    assert len(events) == 0
    assert len(warnings) > 0


# ---------------------------------------------------------------------------
# Test 8: Observer bundle builds cleanly without script leakage
# ---------------------------------------------------------------------------
def test_observer_bundle_construction() -> None:
    registry = ObserverRegistry()
    bundle = registry.build_bundle(["sms", "accessibility", "network"])
    assert "SmsMessage.createFromPdu" in bundle
    assert "AccessibilityNodeInfo.getText" in bundle
    assert "OkHttpClient.newCall" in bundle
    assert "deceptiscope.runtime.v1" in bundle


# ---------------------------------------------------------------------------
# Test 9: Runtime evidence IDs are unique and sequential
# ---------------------------------------------------------------------------
def test_runtime_evidence_ids_unique() -> None:
    settings = Settings(dynamic_analysis_enabled=True)
    host = FridaHost(settings)
    builder = _RuntimeEvidenceBuilder("com.target.pkg", time.monotonic())

    events = [
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="sms",
            event_type="SMS_PDU_PARSED",
            timestamp_ms=1000,
            api="createFromPdu",
            target_package="com.target.pkg",
            metadata={"sender": "123"},
        ),
        FridaRuntimeEvent(
            schema="deceptiscope.runtime.v1",
            observer="network",
            event_type="HTTP_REQUEST_OBSERVED",
            timestamp_ms=1050,
            api="OkHttpClient.newCall",
            target_package="com.target.pkg",
            metadata={"url": "http://example.com"},
        ),
    ]

    evidence = host.normalize_to_evidence(events, builder)
    assert len(evidence) == 2
    assert evidence[0].evidence_id == "R001"
    assert evidence[1].evidence_id == "R002"
    assert evidence[0].trust_level == EvidenceTrustLevel.INSTRUMENTED
    assert evidence[1].trust_level == EvidenceTrustLevel.INSTRUMENTED


# ---------------------------------------------------------------------------
# Test 10: Target package attribution is strictly preserved
# ---------------------------------------------------------------------------
def test_target_package_attribution_preserved() -> None:
    settings = Settings(dynamic_analysis_enabled=True)
    host = FridaHost(settings)
    builder = _RuntimeEvidenceBuilder("com.bank.victim", time.monotonic())

    event = FridaRuntimeEvent(
        schema="deceptiscope.runtime.v1",
        observer="accessibility",
        event_type="ACCESSIBILITY_TEXT_READ",
        timestamp_ms=2000,
        api="getText",
        target_package="com.bank.victim",
        metadata={"view_id": "com.bank.victim:id/otp_input"},
    )
    evidence = host.normalize_to_evidence([event], builder)
    assert len(evidence) == 1
    assert evidence[0].process == "com.bank.victim"
    assert evidence[0].metadata["event_metadata"]["view_id"] == "com.bank.victim:id/otp_input"
