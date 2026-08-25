from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from fraudshield.core.config import Settings
from fraudshield.core.errors import ConfigurationError, ValidationError
from fraudshield.deceptiscope.experiments import ExperimentStatus, ExperimentType


SYNTHETIC_OTP_MARKER = "BOI-TEST-749231"
DESTINATION_RE = re.compile(
    r"\b(?:https?://[^\s\"'<>]+|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,24})\b",
    re.IGNORECASE,
)
ANDROID_NOISE_DOMAINS = {"schemas.android.com"}
LOG_SECURITY_PATTERNS = {
    "sms_access": re.compile(r"\b(SmsManager|SMS_RECEIVED|Telephony|content://sms|READ_SMS|RECEIVE_SMS)\b", re.I),
    "accessibility_behavior": re.compile(r"\b(AccessibilityService|dispatchGesture|TYPE_VIEW_TEXT|accessibility)\b", re.I),
    "dynamic_code_load": re.compile(r"\b(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadDex|BaseDexClassLoader|\.dex)\b", re.I),
    "webview_activity": re.compile(r"\b(WebView|addJavascriptInterface|evaluateJavascript|shouldOverrideUrlLoading)\b", re.I),
}
DEFAULT_EXPERIMENTS = (
    ExperimentType.LAUNCH_APP,
    ExperimentType.OBSERVE_STARTUP,
    ExperimentType.PACKAGE_STATE_CAPTURE,
    ExperimentType.SYNTHETIC_SMS,
    ExperimentType.LOGCAT_CAPTURE,
    ExperimentType.NETWORK_OBSERVATION,
    ExperimentType.ACCESSIBILITY_OBSERVATION,
    ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION,
    ExperimentType.WEBVIEW_OBSERVATION,
    ExperimentType.FILESYSTEM_DIFF,
    ExperimentType.UI_SCREENSHOT,
)


class RuntimeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(pattern=r"^R\d{3}$")
    timestamp_ms: int = Field(ge=0)
    evidence_type: str = Field(min_length=1, max_length=80)
    source: str = "dynamic"
    process: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DynamicExperimentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    experiment_id: str = Field(pattern=r"^DYN\d{3}$")
    experiment_type: ExperimentType
    status: ExperimentStatus
    started_at_ms: int = Field(ge=0)
    completed_at_ms: int = Field(ge=0)
    evidence_ids: list[str] = Field(default_factory=list)
    summary: str = Field(default="", max_length=500)
    unavailable_reason: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class _RuntimeEvidenceBuilder:
    def __init__(self, package_name: str, started_at: float) -> None:
        self.package_name = package_name
        self.started_at = started_at
        self.items: list[RuntimeEvidence] = []
        self._seen: set[tuple[str, str, str]] = set()

    def elapsed_ms(self) -> int:
        return max(0, int((time.monotonic() - self.started_at) * 1000))

    def add(
        self,
        evidence_type: str,
        description: str,
        *,
        confidence: float,
        metadata: dict[str, Any] | None = None,
        process: str | None = None,
        timestamp_ms: int | None = None,
    ) -> RuntimeEvidence | None:
        clipped_description = _clip(description, 500)
        compact_metadata = _compact_metadata(metadata or {})
        key = (evidence_type, clipped_description, str(compact_metadata))
        if key in self._seen:
            return None
        self._seen.add(key)
        item = RuntimeEvidence(
            evidence_id=f"R{len(self.items) + 1:03d}",
            timestamp_ms=self.elapsed_ms() if timestamp_ms is None else max(0, timestamp_ms),
            evidence_type=evidence_type,
            source="dynamic",
            process=process or self.package_name,
            description=clipped_description,
            confidence=max(0.0, min(1.0, confidence)),
            metadata=compact_metadata,
        )
        self.items.append(item)
        return item


class DynamicLiteAnalyzer:
    """Opt-in ADB observations, hard-guarded to an Android emulator.

    This component is disabled by default and uses only backend-defined ADB operations.
    It never accepts LLM-provided commands, scripts, URLs, host paths, or ADB arguments.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def status(self) -> dict[str, Any]:
        serial = self.settings.adb_emulator_serial
        adb_available = bool(shutil.which(self.settings.adb_path))
        return {
            "enabled": self.settings.dynamic_analysis_enabled,
            "adb_available": adb_available,
            "emulator_serial_configured": bool(serial),
            "safe_target_shape": serial.startswith("emulator-") if serial else False,
            "synthetic_markers": {"otp": SYNTHETIC_OTP_MARKER},
            "network_policy": {
                "mode": self.settings.dynamic_network_policy,
                "llm_supplied_targets": False,
                "backend_injected_credentials": False,
            },
        }

    def observe(
        self,
        apk_path: Path,
        package_name: str,
        experiment_types: list[ExperimentType | str] | None = None,
    ) -> dict[str, Any]:
        self._preflight(package_name)
        selected = self._selected_experiments(experiment_types)
        started_at = time.monotonic()
        builder = _RuntimeEvidenceBuilder(package_name, started_at)
        observations: dict[str, Any] = {
            "schema_version": "1.0",
            "mode": "dynamic-lite",
            "emulator_serial": self.settings.adb_emulator_serial,
            "installed": False,
            "launched": False,
            "package_dump": "",
            "logcat_excerpt": [],
            "runtime_evidence": [],
            "experiment_results": [],
            "synthetic_markers": {"otp": SYNTHETIC_OTP_MARKER},
            "network_policy": {
                "mode": self.settings.dynamic_network_policy,
                "llm_supplied_targets": False,
                "backend_injected_credentials": False,
            },
            "warnings": [],
        }
        state: dict[str, Any] = {
            "package_name": package_name,
            "latest_logcat": "",
            "package_dump": "",
            "launched": False,
            "file_snapshot_before": None,
            "file_snapshot_after": None,
        }
        try:
            self._try_clear_logcat(observations)
            self._run("install", "-r", "-t", str(apk_path))
            observations["installed"] = True
            for index, experiment_type in enumerate(selected, start=1):
                result = self._execute_experiment(
                    experiment_id=f"DYN{index:03d}",
                    experiment_type=experiment_type,
                    state=state,
                    builder=builder,
                )
                observations["experiment_results"].append(result.model_dump(mode="json"))
                observations["launched"] = bool(state.get("launched"))
                if state.get("package_dump"):
                    observations["package_dump"] = str(state["package_dump"])[:20_000]
            if not state.get("latest_logcat"):
                state["latest_logcat"] = self._capture_logcat_optional(observations)
            observations["logcat_excerpt"] = self._package_logcat_excerpt(
                str(state.get("latest_logcat", "")),
                package_name,
            )
            observations["runtime_evidence"] = [item.model_dump(mode="json") for item in builder.items]
            return observations
        finally:
            if observations["installed"]:
                try:
                    self._run("uninstall", package_name, timeout=30)
                except Exception:
                    observations["warnings"].append("Automatic emulator uninstall did not complete")

    def _preflight(self, package_name: str) -> None:
        if not self.settings.dynamic_analysis_enabled:
            raise ConfigurationError("Dynamic analysis is disabled")
        serial = self.settings.adb_emulator_serial
        if not serial.startswith("emulator-"):
            raise ConfigurationError("Dynamic analysis requires an explicit emulator-* serial")
        if not shutil.which(self.settings.adb_path):
            raise ConfigurationError("ADB executable is unavailable")
        if not package_name or package_name == "unknown":
            raise ValidationError("unknown_package", "A parsed package name is required for dynamic analysis")
        qemu = self._run("shell", "getprop", "ro.kernel.qemu", timeout=10).strip()
        if qemu != "1":
            raise ConfigurationError("ADB target did not identify itself as an emulator")

    def _selected_experiments(
        self,
        experiment_types: list[ExperimentType | str] | None,
    ) -> list[ExperimentType]:
        if not experiment_types:
            return list(DEFAULT_EXPERIMENTS)
        selected: list[ExperimentType] = []
        for item in experiment_types:
            experiment_type = item if isinstance(item, ExperimentType) else ExperimentType(str(item))
            if experiment_type not in selected:
                selected.append(experiment_type)
        return selected

    def _execute_experiment(
        self,
        *,
        experiment_id: str,
        experiment_type: ExperimentType,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> DynamicExperimentResult:
        started = builder.elapsed_ms()
        before_count = len(builder.items)
        try:
            status, summary, unavailable_reason = self._collect(experiment_type, state, builder)
            error = None
        except subprocess.TimeoutExpired as exc:
            status = ExperimentStatus.TIMED_OUT
            summary = "Dynamic collector timed out"
            unavailable_reason = None
            error = _clip(str(exc), 500)
        except Exception as exc:
            status = ExperimentStatus.FAILED
            summary = "Dynamic collector failed"
            unavailable_reason = None
            error = _clip(str(exc), 500)
        new_ids = [item.evidence_id for item in builder.items[before_count:]]
        return DynamicExperimentResult(
            experiment_id=experiment_id,
            experiment_type=experiment_type,
            status=status,
            started_at_ms=started,
            completed_at_ms=builder.elapsed_ms(),
            evidence_ids=new_ids,
            summary=summary,
            unavailable_reason=unavailable_reason,
            error=error,
            metadata={"synthetic_otp_marker": SYNTHETIC_OTP_MARKER}
            if experiment_type == ExperimentType.SYNTHETIC_SMS
            else {},
        )

    def _collect(
        self,
        experiment_type: ExperimentType,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        if experiment_type == ExperimentType.LAUNCH_APP:
            return self._collect_launch(state, builder)
        if experiment_type == ExperimentType.OBSERVE_STARTUP:
            return self._collect_startup(state, builder)
        if experiment_type == ExperimentType.PACKAGE_STATE_CAPTURE:
            return self._collect_package_state(state, builder)
        if experiment_type == ExperimentType.SYNTHETIC_SMS:
            return self._collect_synthetic_sms(state, builder)
        if experiment_type == ExperimentType.LOGCAT_CAPTURE:
            return self._collect_logcat(state, builder)
        if experiment_type == ExperimentType.NETWORK_OBSERVATION:
            return self._collect_network(state, builder)
        if experiment_type == ExperimentType.ACCESSIBILITY_OBSERVATION:
            return self._collect_accessibility(state, builder)
        if experiment_type == ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION:
            return self._collect_runtime_token(state, builder, "dynamic_code_load")
        if experiment_type == ExperimentType.WEBVIEW_OBSERVATION:
            return self._collect_runtime_token(state, builder, "webview_activity")
        if experiment_type == ExperimentType.FILESYSTEM_DIFF:
            return self._collect_filesystem_diff(state, builder)
        if experiment_type == ExperimentType.UI_SCREENSHOT:
            return self._collect_ui_screenshot(state, builder)
        raise ValueError(f"unsupported experiment type: {experiment_type}")

    def _collect_launch(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        package_name = str(state["package_name"])
        launch = self._run("shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1")
        launched = "Events injected: 1" in launch
        state["launched"] = launched
        if launched:
            builder.add(
                "app_launch",
                "Application launch intent was injected in the emulator",
                confidence=1.0,
                metadata={"launcher_output": _clip(launch, 500)},
            )
            self._collect_process_state(state, builder)
            return ExperimentStatus.COMPLETED, "Application launch was observed", None
        return ExperimentStatus.FAILED, "Application launch did not report an injected event", None

    def _collect_startup(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        if not state.get("launched"):
            self._collect_launch(state, builder)
        package_name = str(state["package_name"])
        activity_dump = self._run("shell", "dumpsys", "activity", "activities", timeout=15)
        matched = False
        for line in activity_dump.splitlines():
            if package_name in line and any(token in line for token in ("ResumedActivity", "mResumed", "Hist #", "Run #")):
                matched = True
                builder.add(
                    "activity_change",
                    "Activity manager output referenced the analyzed application",
                    confidence=0.85,
                    metadata={"line": _clip(line, 500)},
                )
        self._collect_process_state(state, builder)
        if matched:
            return ExperimentStatus.COMPLETED, "Startup activity evidence was normalized", None
        return ExperimentStatus.UNAVAILABLE, "Startup collector found no reliable activity signal", "No activity manager signal referenced the package"

    def _collect_package_state(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        package_name = str(state["package_name"])
        dump = self._run("shell", "dumpsys", "package", package_name, timeout=20)
        state["package_dump"] = dump[:20_000]
        builder.add(
            "package_state",
            "Package manager state was captured for the analyzed application",
            confidence=0.9,
            metadata={"excerpt": _clip(dump, 1000)},
        )
        if "android.permission" in dump:
            permissions = sorted(set(re.findall(r"android\.permission\.[A-Z0-9_]+", dump)))
            if permissions:
                builder.add(
                    "permission_state",
                    "Runtime package state includes Android permission entries",
                    confidence=0.85,
                    metadata={"permissions": permissions[:30]},
                )
        return ExperimentStatus.COMPLETED, "Package state was captured", None

    def _collect_synthetic_sms(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        self._run("emu", "sms", "send", "+15551230000", SYNTHETIC_OTP_MARKER, timeout=20)
        builder.add(
            "synthetic_sms_delivered",
            "Synthetic OTP SMS marker was delivered to the emulator",
            confidence=1.0,
            metadata={"marker": SYNTHETIC_OTP_MARKER, "test_data": True},
        )
        time.sleep(0.2)
        logcat = self._capture_logcat()
        state["latest_logcat"] = logcat
        self._extract_logcat_evidence(logcat, state, builder)
        if self._marker_seen_in_app_logcat(logcat, str(state["package_name"])):
            builder.add(
                "synthetic_marker_correlation",
                "Synthetic OTP marker appeared later in an application-associated runtime data path",
                confidence=1.0,
                metadata={"marker": SYNTHETIC_OTP_MARKER, "correlation_source": "package-filtered logcat"},
            )
        return ExperimentStatus.COMPLETED, "Synthetic SMS was delivered and correlated where observable", None

    def _collect_logcat(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        logcat = self._capture_logcat()
        state["latest_logcat"] = logcat
        self._extract_logcat_evidence(logcat, state, builder)
        return ExperimentStatus.COMPLETED, "Bounded logcat was captured and normalized", None

    def _collect_network(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        if self.settings.dynamic_network_policy == "disabled":
            return (
                ExperimentStatus.UNAVAILABLE,
                "Network destination observation is disabled by policy",
                "FRAUDSHIELD_DYNAMIC_NETWORK_POLICY=disabled",
            )
        before = len(builder.items)
        logcat = str(state.get("latest_logcat") or self._capture_logcat())
        state["latest_logcat"] = logcat
        self._extract_network_destinations(logcat, state, builder)
        if len(builder.items) > before:
            return ExperimentStatus.COMPLETED, "Network destination evidence was observed", None
        return (
            ExperimentStatus.UNAVAILABLE,
            "No safe network destination source produced observations",
            "Lightweight analyzer does not perform host packet capture or active network interception",
        )

    def _collect_accessibility(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        before = len(builder.items)
        logcat = str(state.get("latest_logcat") or self._capture_logcat())
        state["latest_logcat"] = logcat
        self._extract_token_evidence(logcat, state, builder, "accessibility_behavior")
        accessibility_dump = self._run_optional("shell", "dumpsys", "accessibility", timeout=15)
        package_name = str(state["package_name"])
        if accessibility_dump and package_name in accessibility_dump:
            builder.add(
                "accessibility_behavior",
                "Accessibility service state referenced the analyzed application",
                confidence=0.85,
                metadata={"excerpt": _clip(accessibility_dump, 1000)},
            )
        if len(builder.items) > before:
            return ExperimentStatus.COMPLETED, "Accessibility-related behavior was observed", None
        return ExperimentStatus.UNAVAILABLE, "No accessibility runtime signal was observed", "No reliable accessibility source referenced the package"

    def _collect_runtime_token(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
        evidence_type: str,
    ) -> tuple[ExperimentStatus, str, str | None]:
        before = len(builder.items)
        logcat = str(state.get("latest_logcat") or self._capture_logcat())
        state["latest_logcat"] = logcat
        self._extract_token_evidence(logcat, state, builder, evidence_type)
        if len(builder.items) > before:
            return ExperimentStatus.COMPLETED, f"{evidence_type} runtime evidence was observed", None
        return ExperimentStatus.UNAVAILABLE, f"No {evidence_type} runtime signal was observed", "No package-associated logcat signal matched this collector"

    def _collect_filesystem_diff(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        package_name = str(state["package_name"])
        before = state.get("file_snapshot_before")
        if before is None:
            before = self._snapshot_app_files(package_name)
            state["file_snapshot_before"] = before
        if before is None:
            return (
                ExperimentStatus.UNAVAILABLE,
                "App-private filesystem diff is unavailable",
                "run-as could not access app-private files; the APK may not be debuggable",
            )
        if not state.get("launched"):
            self._collect_launch(state, builder)
        after = self._snapshot_app_files(package_name)
        state["file_snapshot_after"] = after
        if after is None:
            return (
                ExperimentStatus.UNAVAILABLE,
                "App-private filesystem diff is unavailable after launch",
                "run-as could not access app-private files after launch",
            )
        created = sorted(after - before)
        removed = sorted(before - after)
        if created or removed:
            builder.add(
                "filesystem_change",
                "App-private filesystem changed during dynamic observation",
                confidence=0.8,
                metadata={"created": created[:30], "removed": removed[:30]},
            )
        return ExperimentStatus.COMPLETED, "Filesystem diff completed", None

    def _collect_ui_screenshot(
        self,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> tuple[ExperimentStatus, str, str | None]:
        if not state.get("launched"):
            self._collect_launch(state, builder)
        emulator_path = "/sdcard/fraudshield-deceptiscope-screen.png"
        try:
            self._run("shell", "screencap", "-p", emulator_path, timeout=15)
            listing = self._run_optional("shell", "ls", "-l", emulator_path, timeout=10)
            builder.add(
                "ui_screenshot",
                "Emulator screenshot was captured through trusted backend instrumentation",
                confidence=0.75,
                metadata={"emulator_temp_file": emulator_path, "listing": _clip(listing or "", 300)},
            )
            return ExperimentStatus.COMPLETED, "UI screenshot was captured in the emulator", None
        finally:
            self._run_optional("shell", "rm", "-f", emulator_path, timeout=10)

    def _collect_process_state(self, state: dict[str, Any], builder: _RuntimeEvidenceBuilder) -> None:
        package_name = str(state["package_name"])
        pid_output = self._run_optional("shell", "pidof", package_name, timeout=10)
        pids = [item for item in (pid_output or "").split() if item.isdigit()]
        if pids:
            builder.add(
                "process_creation",
                "Application process was present in the emulator process table",
                confidence=0.9,
                metadata={"pids": pids[:10]},
            )

    def _snapshot_app_files(self, package_name: str) -> set[str] | None:
        output = self._run_optional("shell", "run-as", package_name, "find", ".", "-maxdepth", "4", "-type", "f", timeout=15)
        if not output:
            return None
        return {line.strip() for line in output.splitlines() if line.strip()}

    def _extract_logcat_evidence(
        self,
        logcat: str,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> None:
        for evidence_type in LOG_SECURITY_PATTERNS:
            self._extract_token_evidence(logcat, state, builder, evidence_type)
        self._extract_network_destinations(logcat, state, builder)

    def _extract_token_evidence(
        self,
        logcat: str,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
        evidence_type: str,
    ) -> None:
        pattern = LOG_SECURITY_PATTERNS[evidence_type]
        package_name = str(state["package_name"])
        for line in self._relevant_lines(logcat, package_name):
            if pattern.search(line):
                builder.add(
                    evidence_type,
                    _description_for_log_evidence(evidence_type),
                    confidence=0.75,
                    metadata={"line": _clip(line, 500)},
                )

    def _extract_network_destinations(
        self,
        logcat: str,
        state: dict[str, Any],
        builder: _RuntimeEvidenceBuilder,
    ) -> None:
        package_name = str(state["package_name"])
        for line in self._relevant_lines(logcat, package_name):
            for destination in DESTINATION_RE.findall(line):
                normalized = destination.rstrip(".,;)")
                if normalized.lower() in ANDROID_NOISE_DOMAINS:
                    continue
                evidence_type = "dns_destination" if not normalized.startswith(("http://", "https://")) else "network_destination"
                builder.add(
                    evidence_type,
                    "Runtime output referenced a network destination without trusting response content",
                    confidence=0.55,
                    metadata={
                        "destination": _clip(normalized, 300),
                        "observation_source": "package-filtered logcat",
                        "content_trusted": False,
                    },
                )

    def _marker_seen_in_app_logcat(self, logcat: str, package_name: str) -> bool:
        return any(SYNTHETIC_OTP_MARKER in line and package_name in line for line in logcat.splitlines())

    @staticmethod
    def _relevant_lines(logcat: str, package_name: str) -> list[str]:
        return [line for line in logcat.splitlines() if package_name in line or SYNTHETIC_OTP_MARKER in line]

    def _try_clear_logcat(self, observations: dict[str, Any]) -> None:
        try:
            self._run("logcat", "-c", timeout=10)
        except Exception:
            observations["warnings"].append("Logcat clear did not complete; excerpts may include prior emulator noise")

    def _capture_logcat(self) -> str:
        return self._run("logcat", "-d", "-t", "500", timeout=20)

    def _capture_logcat_optional(self, observations: dict[str, Any]) -> str:
        try:
            return self._capture_logcat()
        except Exception:
            observations["warnings"].append("Final logcat capture did not complete")
            return ""

    def _package_logcat_excerpt(self, logcat: str, package_name: str) -> list[str]:
        return [_clip(line, 500) for line in self._relevant_lines(logcat, package_name)][-100:]

    def _run_optional(self, *args: str, timeout: int | None = None) -> str | None:
        try:
            return self._run(*args, timeout=timeout)
        except Exception:
            return None

    def _run(self, *args: str, timeout: int | None = None) -> str:
        command = [self.settings.adb_path, "-s", self.settings.adb_emulator_serial, *args]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout or self.settings.dynamic_timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or "ADB command failed")[:1000])
        return completed.stdout


def _description_for_log_evidence(evidence_type: str) -> str:
    return {
        "sms_access": "Application emitted SMS-related runtime signals",
        "accessibility_behavior": "Application emitted accessibility-related runtime signals",
        "dynamic_code_load": "Application emitted dynamic code loading runtime signals",
        "webview_activity": "Application emitted WebView-related runtime signals",
    }[evidence_type]


def _clip(value: str, limit: int) -> str:
    normalized = " ".join(str(value).split())
    return normalized[:limit]


def _compact_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {str(key)[:80]: _compact_value(value) for key, value in metadata.items() if value is not None}


def _compact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key)[:80]: _compact_value(entry) for key, entry in list(value.items())[:20]}
    if isinstance(value, list):
        return [_compact_value(entry) for entry in value[:50]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _clip(str(value), 1000)
