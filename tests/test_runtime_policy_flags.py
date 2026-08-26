from __future__ import annotations

from pathlib import Path
import pytest

from fraudshield.core.config import Settings
from fraudshield.deceptiscope.dynamic import DynamicLiteAnalyzer
from fraudshield.deceptiscope.experiments import ExperimentType
from fraudshield.deceptiscope.runtime import (
    FridaHost,
    ObserverRegistry,
    RuntimeObserverStatus,
)


# ---------------------------------------------------------------------------
# Test 1 & 2: Observer flags control selection (enabled -> selected, disabled -> omitted)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("flag_name", "observer_name", "experiment_type"),
    [
        ("sms_observer_enabled", "sms", ExperimentType.SYNTHETIC_SMS),
        ("accessibility_observer_enabled", "accessibility", ExperimentType.ACCESSIBILITY_OBSERVATION),
        ("network_observer_enabled", "network", ExperimentType.NETWORK_OBSERVATION),
        ("dex_observer_enabled", "dynamic_dex", ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION),
        ("webview_observer_enabled", "webview", ExperimentType.WEBVIEW_OBSERVATION),
    ],
)
def test_individual_observer_flag_enforcement(
    flag_name: str,
    observer_name: str,
    experiment_type: ExperimentType,
) -> None:
    # 1. Enabled flag -> observer selected
    settings_enabled = Settings(**{flag_name: True})
    registry_enabled = ObserverRegistry(settings=settings_enabled)
    assert registry_enabled.is_observer_enabled(observer_name) is True
    observers = registry_enabled.get_observers_for_experiments([experiment_type])
    assert observer_name in observers

    # 2. Disabled flag -> observer omitted from selection
    settings_disabled = Settings(**{flag_name: False})
    registry_disabled = ObserverRegistry(settings=settings_disabled)
    assert registry_disabled.is_observer_enabled(observer_name) is False
    observers_disabled = registry_disabled.get_observers_for_experiments([experiment_type])
    assert observer_name not in observers_disabled

    # Also omitted from combined multi-observer experiments such as LAUNCH_APP
    launch_observers = registry_disabled.get_observers_for_experiments([ExperimentType.LAUNCH_APP])
    assert observer_name not in launch_observers


# ---------------------------------------------------------------------------
# Test 2b: Directly loading a disabled observer raises ValueError
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("flag_name", "observer_name"),
    [
        ("sms_observer_enabled", "sms"),
        ("accessibility_observer_enabled", "accessibility"),
        ("network_observer_enabled", "network"),
        ("dex_observer_enabled", "dynamic_dex"),
        ("webview_observer_enabled", "webview"),
    ],
)
def test_disabled_observer_direct_load_rejected(flag_name: str, observer_name: str) -> None:
    settings_disabled = Settings(**{flag_name: False})
    registry = ObserverRegistry(settings=settings_disabled)
    with pytest.raises(ValueError, match="disabled by configuration"):
        registry.load_observer_script(observer_name)


# ---------------------------------------------------------------------------
# Test 3: Frida runtime disabled flag prevents session from starting
# ---------------------------------------------------------------------------
def test_frida_runtime_disabled_prevents_session() -> None:
    settings = Settings(
        dynamic_analysis_enabled=True,
        frida_runtime_enabled=False,
    )
    host = FridaHost(settings)
    assert host.status()["configured_enabled"] is False

    with host.observation_session("com.target.app", ["sms", "network"]) as session:
        assert session.status == RuntimeObserverStatus.UNAVAILABLE
        assert any("disabled by configuration" in w for w in session.warnings)
        assert len(session.events) == 0


# ---------------------------------------------------------------------------
# Test 4: Missing host dependency returns UNAVAILABLE gracefully
# ---------------------------------------------------------------------------
def test_missing_dependency_returns_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        dynamic_analysis_enabled=True,
        frida_runtime_enabled=True,
    )
    host = FridaHost(settings)

    # Simulate import failure
    monkeypatch.setattr(
        host,
        "status",
        lambda: {
            "configured_enabled": True,
            "host_dependency_available": False,
            "frida_installed": False,
            "runtime_ready": False,
        },
    )

    with host.observation_session("com.target.app", ["sms"]) as session:
        assert session.status == RuntimeObserverStatus.UNAVAILABLE
        assert any("not installed" in w for w in session.warnings)


# ---------------------------------------------------------------------------
# Test 5: Unapproved or arbitrary observer names rejected
# ---------------------------------------------------------------------------
def test_unapproved_or_arbitrary_observers_rejected() -> None:
    registry = ObserverRegistry()

    with pytest.raises(ValueError, match="Unknown or unapproved"):
        registry.load_observer_script("arbitrary_exploit")

    with pytest.raises(ValueError, match="Unknown or unapproved"):
        registry.load_observer_script("../../../etc/passwd")


# ---------------------------------------------------------------------------
# Test 6: Missing trusted script causes honest failure
# ---------------------------------------------------------------------------
def test_missing_trusted_script_honest_failure(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty_scripts"
    empty_dir.mkdir()
    registry = ObserverRegistry(scripts_dir=empty_dir)

    with pytest.raises(FileNotFoundError, match="Trusted script missing"):
        registry.load_observer_script("sms")


# ---------------------------------------------------------------------------
# Test 7: System capabilities truthfully match runtime configuration
# ---------------------------------------------------------------------------
def test_dynamic_status_truthfully_reflects_capabilities() -> None:
    # Scenario A: Default / Disabled
    settings_default = Settings(dynamic_analysis_enabled=False)
    analyzer_default = DynamicLiteAnalyzer(settings_default)
    st_default = analyzer_default.status()

    assert st_default["enabled"] is False
    assert st_default["configured_enabled"] is False
    assert st_default["runtime_ready"] is False
    assert "observers_enabled" in st_default
    assert st_default["observers_enabled"]["sms"] is True
    assert st_default["observers_enabled"]["webview"] is True

    # Scenario B: Partial configuration with selective observer toggling
    settings_custom = Settings(
        dynamic_analysis_enabled=True,
        adb_emulator_serial="emulator-5554",
        sms_observer_enabled=False,
        dex_observer_enabled=False,
        webview_observer_enabled=True,
    )
    analyzer_custom = DynamicLiteAnalyzer(settings_custom)
    st_custom = analyzer_custom.status()

    assert st_custom["configured_enabled"] is True
    assert st_custom["emulator_configured"] is True
    assert st_custom["safe_target_shape"] is True
    assert st_custom["emulator_serial"] == "emulator-5554"
    assert st_custom["observers_enabled"]["sms"] is False
    assert st_custom["observers_enabled"]["dynamic_dex"] is False
    assert st_custom["observers_enabled"]["webview"] is True
    assert st_custom["observers_enabled"]["network"] is True


# ---------------------------------------------------------------------------
# Test 8: No fixed OTP / synthetic markers exposed in system status
# ---------------------------------------------------------------------------
def test_no_fixed_otp_marker_in_system_status() -> None:
    settings = Settings(dynamic_analysis_enabled=True)
    analyzer = DynamicLiteAnalyzer(settings)
    st = analyzer.status()

    # Must NOT expose any fixed synthetic marker keys or static marker values
    assert "synthetic_markers" not in st
    for key, value in st.items():
        assert "otp" not in key.lower()
        if isinstance(value, str):
            assert "otp" not in value.lower()
