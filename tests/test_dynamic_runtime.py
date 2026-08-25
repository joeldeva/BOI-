from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fraudshield.core.errors import ConfigurationError
from fraudshield.deceptiscope.dynamic import DynamicLiteAnalyzer, SYNTHETIC_OTP_MARKER
from fraudshield.deceptiscope.experiments import ExperimentType


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

    def _run(self, *args: str, timeout: int | None = None) -> str:
        key = tuple(args)
        self.calls.append(key)
        if key in self.fail:
            raise self.fail[key]
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


def test_runtime_evidence_normalization_ids_timestamps_and_marker_correlation(
    dynamic_settings,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    logcat = (
        f"08-25 10:00:01.000 1234 1234 I {PACKAGE}: SmsManager read {SYNTHETIC_OTP_MARKER}\n"
        f"08-25 10:00:02.000 1234 1234 I {PACKAGE}: DexClassLoader loaded payload.dex\n"
        f"08-25 10:00:03.000 1234 1234 I {PACKAGE}: WebView addJavascriptInterface https://c2.example.invalid/gate\n"
        f"08-25 10:00:04.000 1234 1234 I {PACKAGE}: AccessibilityService dispatchGesture\n"
    )
    analyzer = FakeDynamicAnalyzer(dynamic_settings, logcat=logcat)
    result = analyzer.observe(
        apk,
        PACKAGE,
        [
            ExperimentType.LAUNCH_APP,
            ExperimentType.SYNTHETIC_SMS,
            ExperimentType.LOGCAT_CAPTURE,
            ExperimentType.NETWORK_OBSERVATION,
            ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION,
            ExperimentType.WEBVIEW_OBSERVATION,
            ExperimentType.ACCESSIBILITY_OBSERVATION,
        ],
    )

    evidence = result["runtime_evidence"]
    evidence_types = {item["evidence_type"] for item in evidence}
    assert [item["evidence_id"] for item in evidence] == [f"R{index:03d}" for index in range(1, len(evidence) + 1)]
    assert all(isinstance(item["timestamp_ms"], int) and item["timestamp_ms"] >= 0 for item in evidence)
    assert {
        "app_launch",
        "process_creation",
        "synthetic_sms_delivered",
        "sms_access",
        "synthetic_marker_correlation",
        "dynamic_code_load",
        "webview_activity",
        "network_destination",
        "accessibility_behavior",
    } <= evidence_types
    marker = next(item for item in evidence if item["evidence_type"] == "synthetic_marker_correlation")
    assert marker["confidence"] == 1.0
    assert marker["metadata"]["marker"] == SYNTHETIC_OTP_MARKER
    assert any(item["status"] == "COMPLETED" for item in result["experiment_results"])


def test_dynamic_timeout_returns_timed_out_and_cleans_up(dynamic_settings, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    timeout = subprocess.TimeoutExpired(cmd="adb logcat", timeout=20)
    analyzer = FakeDynamicAnalyzer(
        dynamic_settings,
        fail={("logcat", "-d", "-t", "500"): timeout},
    )
    result = analyzer.observe(apk, PACKAGE, [ExperimentType.LOGCAT_CAPTURE])
    assert result["experiment_results"][0]["status"] == "TIMED_OUT"
    assert ("uninstall", PACKAGE) in analyzer.calls


def test_dynamic_emulator_qemu_enforcement(dynamic_settings, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    analyzer = FakeDynamicAnalyzer(dynamic_settings, qemu="0")
    with pytest.raises(ConfigurationError):
        analyzer.observe(apk, PACKAGE, [ExperimentType.LAUNCH_APP])
    assert not any(call[0] == "install" for call in analyzer.calls)


def test_dynamic_cleanup_after_launch_failure(dynamic_settings, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    analyzer = FakeDynamicAnalyzer(
        dynamic_settings,
        fail={("shell", "monkey", "-p", PACKAGE, "-c", "android.intent.category.LAUNCHER", "1"): RuntimeError("boom")},
    )
    result = analyzer.observe(apk, PACKAGE, [ExperimentType.LAUNCH_APP])
    assert result["experiment_results"][0]["status"] == "FAILED"
    assert ("uninstall", PACKAGE) in analyzer.calls


def test_unsupported_collector_returns_unavailable(dynamic_settings, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    analyzer = FakeDynamicAnalyzer(
        dynamic_settings,
        fail={("shell", "run-as", PACKAGE, "find", ".", "-maxdepth", "4", "-type", "f"): RuntimeError("run-as failed")},
    )
    result = analyzer.observe(apk, PACKAGE, [ExperimentType.FILESYSTEM_DIFF])
    assert result["experiment_results"][0]["status"] == "UNAVAILABLE"
    assert "run-as" in result["experiment_results"][0]["unavailable_reason"]


def test_network_observation_policy_can_disable_destination_collection(
    dynamic_settings,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.shutil.which", lambda value: "adb")
    policy_settings = dynamic_settings.with_overrides(dynamic_network_policy="disabled")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    analyzer = FakeDynamicAnalyzer(
        policy_settings,
        logcat=f"08-25 10:00:03.000 1234 1234 I {PACKAGE}: https://c2.example.invalid/gate",
    )
    result = analyzer.observe(apk, PACKAGE, [ExperimentType.NETWORK_OBSERVATION])
    assert result["network_policy"]["mode"] == "disabled"
    assert result["experiment_results"][0]["status"] == "UNAVAILABLE"
    assert not any(item["evidence_type"] == "network_destination" for item in result["runtime_evidence"])


def test_dynamic_run_uses_process_isolation(dynamic_settings, monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_run(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return SimpleNamespace(returncode=0, stdout="1", stderr="")

    monkeypatch.setattr("fraudshield.deceptiscope.dynamic.subprocess.run", fake_run)
    output = DynamicLiteAnalyzer(dynamic_settings)._run("shell", "getprop", "ro.kernel.qemu", timeout=10)
    assert output == "1"
    assert calls[0]["shell"] is False
    assert calls[0]["command"][:3] == ["adb", "-s", "emulator-5554"]
