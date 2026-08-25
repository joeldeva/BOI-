from __future__ import annotations

import re
import shutil
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from fraudshield.core.config import Settings


HYPOTHESIS_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
FORBIDDEN_REQUEST_KEYS = {
    "command",
    "commands",
    "shell",
    "script",
    "scripts",
    "adb",
    "adb_args",
    "args",
    "arguments",
    "url",
    "urls",
    "path",
    "paths",
    "filesystem_path",
    "host",
    "target",
    "network_target",
}
FORBIDDEN_FREE_TEXT_RE = re.compile(
    r"("
    r"\badb\b|"
    r"\bshell\b|"
    r"\bsubprocess\b|"
    r"\b(?:cmd(?:\.exe)?|powershell|pwsh|bash|sh)\b|"
    r"\b(?:curl|wget|nc|ncat|netcat|python|perl|ruby|node)\b|"
    r"https?://|"
    r"javascript:|"
    r"<script|"
    r"#!|"
    r"\b(?!android\.permission\b)(?:[a-z0-9-]+\.)+[a-z]{2,24}\b|"
    r"(?:[A-Za-z]:\\)|"
    r"(?:^|\s)(?:/etc/|/var/|/home/|/Users/|/tmp/)|"
    r"\.\./|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r")",
    re.IGNORECASE,
)


class ExperimentType(str, Enum):
    LAUNCH_APP = "LAUNCH_APP"
    OBSERVE_STARTUP = "OBSERVE_STARTUP"
    SYNTHETIC_SMS = "SYNTHETIC_SMS"
    NETWORK_OBSERVATION = "NETWORK_OBSERVATION"
    ACCESSIBILITY_OBSERVATION = "ACCESSIBILITY_OBSERVATION"
    FILESYSTEM_DIFF = "FILESYSTEM_DIFF"
    DYNAMIC_CODE_LOAD_OBSERVATION = "DYNAMIC_CODE_LOAD_OBSERVATION"
    WEBVIEW_OBSERVATION = "WEBVIEW_OBSERVATION"
    UI_SCREENSHOT = "UI_SCREENSHOT"
    PACKAGE_STATE_CAPTURE = "PACKAGE_STATE_CAPTURE"
    LOGCAT_CAPTURE = "LOGCAT_CAPTURE"


class ExperimentStatus(str, Enum):
    PLANNED = "PLANNED"
    SKIPPED = "SKIPPED"
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    NOT_RUN = "NOT_RUN"
    DISABLED = "DISABLED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class ExperimentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    experiment_type: ExperimentType
    description: str = Field(min_length=1, max_length=300)
    required_capabilities: list[str] = Field(default_factory=list, max_length=12)
    timeout_seconds: int = Field(ge=1, le=600)
    safe_by_default: bool
    produces_evidence_types: list[str] = Field(default_factory=list, max_length=12)


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    experiment_id: str = Field(pattern=r"^EXP\d{3}$")
    hypothesis_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    experiment_type: ExperimentType
    objective: str = Field(min_length=1, max_length=300)
    expected_signal: str = Field(min_length=1, max_length=300)
    priority: int = Field(ge=1, le=10)

    @field_validator("objective", "expected_signal")
    @classmethod
    def reject_runtime_instructions(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if FORBIDDEN_FREE_TEXT_RE.search(normalized):
            raise ValueError("experiment text cannot contain commands, paths, URLs, or host targets")
        return normalized


class ExperimentPlanItem(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    experiment_id: str
    hypothesis_id: str
    experiment_type: ExperimentType
    objective: str
    expected_signal: str
    priority: int
    status: ExperimentStatus
    description: str
    required_capabilities: list[str]
    timeout_seconds: int
    safe_by_default: bool
    produces_evidence_types: list[str]
    supported: bool
    unsupported_reason: str | None = None


CATALOG_VERSION = "ai-experiments-2026.1"
SANDBOX_CAPABILITIES = {
    "dynamic_lite_enabled",
    "adb_available",
    "emulator_serial_configured",
    "safe_emulator_serial",
}


def experiment_catalog() -> dict[ExperimentType, ExperimentDefinition]:
    dynamic_caps = sorted(SANDBOX_CAPABILITIES)
    return {
        ExperimentType.LAUNCH_APP: ExperimentDefinition(
            experiment_type=ExperimentType.LAUNCH_APP,
            description="Install and launch the APK inside the configured isolated Android emulator.",
            required_capabilities=dynamic_caps,
            timeout_seconds=45,
            safe_by_default=True,
            produces_evidence_types=["launch_result", "package_state", "logcat_excerpt"],
        ),
        ExperimentType.OBSERVE_STARTUP: ExperimentDefinition(
            experiment_type=ExperimentType.OBSERVE_STARTUP,
            description="Observe startup behavior after a trusted backend launch sequence.",
            required_capabilities=dynamic_caps,
            timeout_seconds=60,
            safe_by_default=True,
            produces_evidence_types=["startup_events", "logcat_excerpt"],
        ),
        ExperimentType.SYNTHETIC_SMS: ExperimentDefinition(
            experiment_type=ExperimentType.SYNTHETIC_SMS,
            description="Deliver a synthetic benign OTP-shaped SMS to the emulator and observe app reactions.",
            required_capabilities=dynamic_caps,
            timeout_seconds=90,
            safe_by_default=True,
            produces_evidence_types=["sms_delivery_event", "api_observation", "logcat_excerpt"],
        ),
        ExperimentType.NETWORK_OBSERVATION: ExperimentDefinition(
            experiment_type=ExperimentType.NETWORK_OBSERVATION,
            description="Observe emulator network telemetry generated by the app without accepting LLM-supplied targets.",
            required_capabilities=dynamic_caps,
            timeout_seconds=120,
            safe_by_default=True,
            produces_evidence_types=["network_connection", "dns_query", "tls_metadata"],
        ),
        ExperimentType.ACCESSIBILITY_OBSERVATION: ExperimentDefinition(
            experiment_type=ExperimentType.ACCESSIBILITY_OBSERVATION,
            description="Observe declared accessibility-service behavior inside the emulator.",
            required_capabilities=dynamic_caps,
            timeout_seconds=90,
            safe_by_default=True,
            produces_evidence_types=["accessibility_event", "service_state", "logcat_excerpt"],
        ),
        ExperimentType.FILESYSTEM_DIFF: ExperimentDefinition(
            experiment_type=ExperimentType.FILESYSTEM_DIFF,
            description="Compare app-private filesystem state before and after trusted launch activities.",
            required_capabilities=dynamic_caps,
            timeout_seconds=120,
            safe_by_default=True,
            produces_evidence_types=["filesystem_delta", "package_state"],
        ),
        ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION: ExperimentDefinition(
            experiment_type=ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION,
            description="Observe runtime indicators associated with dynamic code loading inside the emulator.",
            required_capabilities=dynamic_caps,
            timeout_seconds=120,
            safe_by_default=True,
            produces_evidence_types=["classloader_event", "dex_load_indicator", "logcat_excerpt"],
        ),
        ExperimentType.WEBVIEW_OBSERVATION: ExperimentDefinition(
            experiment_type=ExperimentType.WEBVIEW_OBSERVATION,
            description="Observe WebView initialization and bridge-related runtime signals.",
            required_capabilities=dynamic_caps,
            timeout_seconds=90,
            safe_by_default=True,
            produces_evidence_types=["webview_event", "bridge_indicator", "logcat_excerpt"],
        ),
        ExperimentType.UI_SCREENSHOT: ExperimentDefinition(
            experiment_type=ExperimentType.UI_SCREENSHOT,
            description="Capture an emulator screenshot through trusted backend instrumentation.",
            required_capabilities=dynamic_caps,
            timeout_seconds=30,
            safe_by_default=True,
            produces_evidence_types=["ui_screenshot"],
        ),
        ExperimentType.PACKAGE_STATE_CAPTURE: ExperimentDefinition(
            experiment_type=ExperimentType.PACKAGE_STATE_CAPTURE,
            description="Capture package manager state for the analyzed app inside the emulator.",
            required_capabilities=dynamic_caps,
            timeout_seconds=30,
            safe_by_default=True,
            produces_evidence_types=["package_dump", "permission_state"],
        ),
        ExperimentType.LOGCAT_CAPTURE: ExperimentDefinition(
            experiment_type=ExperimentType.LOGCAT_CAPTURE,
            description="Capture a bounded logcat excerpt filtered by the analyzed package name.",
            required_capabilities=dynamic_caps,
            timeout_seconds=30,
            safe_by_default=True,
            produces_evidence_types=["logcat_excerpt"],
        ),
    }


class TrustedExperimentRegistry:
    """Maps enum values to trusted backend handlers without exposing commands to the LLM."""

    def __init__(self, definitions: dict[ExperimentType, ExperimentDefinition] | None = None) -> None:
        self.definitions = definitions or experiment_catalog()
        self._handlers: dict[
            ExperimentType,
            Callable[[ExperimentRequest, ExperimentDefinition, dict[str, bool]], ExperimentPlanItem],
        ] = {experiment_type: self._plan_only_handler for experiment_type in self.definitions}

    def catalog_payload(self) -> list[dict[str, Any]]:
        return [definition.model_dump(mode="json") for definition in self.definitions.values()]

    def environment_capabilities(self, settings: Settings) -> dict[str, bool]:
        serial = settings.adb_emulator_serial
        return {
            "dynamic_lite_enabled": settings.dynamic_analysis_enabled,
            "adb_available": bool(shutil.which(settings.adb_path)),
            "emulator_serial_configured": bool(serial),
            "safe_emulator_serial": serial.startswith("emulator-") if serial else False,
        }

    def plan_request(self, request: ExperimentRequest, settings: Settings) -> ExperimentPlanItem:
        definition = self.definitions[ExperimentType(request.experiment_type)]
        capabilities = self.environment_capabilities(settings)
        return self._handlers[ExperimentType(request.experiment_type)](request, definition, capabilities)

    @staticmethod
    def _plan_only_handler(
        request: ExperimentRequest,
        definition: ExperimentDefinition,
        capabilities: dict[str, bool],
    ) -> ExperimentPlanItem:
        missing = [capability for capability in definition.required_capabilities if not capabilities.get(capability)]
        status = ExperimentStatus.PLANNED
        unsupported_reason = None
        supported = True
        if missing:
            status = ExperimentStatus.UNSUPPORTED
            supported = False
            unsupported_reason = f"Missing required capabilities: {', '.join(missing)}"
        elif not definition.safe_by_default:
            status = ExperimentStatus.SKIPPED
            supported = False
            unsupported_reason = "Experiment is not marked safe by default"
        return ExperimentPlanItem(
            experiment_id=request.experiment_id,
            hypothesis_id=request.hypothesis_id,
            experiment_type=request.experiment_type,
            objective=request.objective,
            expected_signal=request.expected_signal,
            priority=request.priority,
            status=status,
            description=definition.description,
            required_capabilities=definition.required_capabilities,
            timeout_seconds=definition.timeout_seconds,
            safe_by_default=definition.safe_by_default,
            produces_evidence_types=definition.produces_evidence_types,
            supported=supported,
            unsupported_reason=unsupported_reason,
        )


class ExperimentPlanner:
    def __init__(
        self,
        settings: Settings,
        registry: TrustedExperimentRegistry | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry or TrustedExperimentRegistry()

    def plan_from_payload(
        self,
        payload: dict[str, Any],
        hypotheses: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        hypothesis_by_id = {str(item.get("hypothesis_id")): item for item in hypotheses}
        raw_requests = payload.get("experiment_requests") if isinstance(payload, dict) else None
        if raw_requests is None:
            requests, errors = self._requests_from_hypotheses(hypotheses)
        else:
            requests, errors = self._validate_raw_requests(raw_requests, hypothesis_by_id)
        planned = self.plan_requests(requests, hypothesis_by_id)
        return [item.model_dump(mode="json") for item in planned], errors

    def plan_requests(
        self,
        requests: list[ExperimentRequest],
        hypothesis_by_id: dict[str, dict[str, Any]],
    ) -> list[ExperimentPlanItem]:
        scored = [
            (
                self._score_request(request, hypothesis_by_id.get(request.hypothesis_id, {})),
                self.registry.plan_request(request, self.settings),
            )
            for request in requests
        ]
        scored.sort(key=lambda item: item[0], reverse=True)
        limit = min(self.settings.ai_experiment_plan_limit, self.settings.max_experiments_per_round)
        return [item for _, item in scored[:limit]]

    def _validate_raw_requests(
        self,
        raw_requests: Any,
        hypothesis_by_id: dict[str, dict[str, Any]],
    ) -> tuple[list[ExperimentRequest], list[str]]:
        if not isinstance(raw_requests, list):
            return [], ["experiment_requests must be a list"]
        requests: list[ExperimentRequest] = []
        errors: list[str] = []
        seen_ids: set[str] = set()
        for index, raw in enumerate(raw_requests[:30]):
            if not isinstance(raw, dict):
                errors.append(f"experiment_requests[{index}] must be an object")
                continue
            forbidden = sorted(FORBIDDEN_REQUEST_KEYS.intersection(raw))
            if forbidden:
                errors.append(
                    f"experiment_requests[{index}] contains forbidden execution fields: {', '.join(forbidden)}"
                )
                continue
            try:
                request = ExperimentRequest.model_validate(raw)
            except Exception as exc:
                errors.append(f"experiment_requests[{index}] invalid: {type(exc).__name__}")
                continue
            if request.hypothesis_id not in hypothesis_by_id:
                errors.append(
                    f"experiment_requests[{index}] references nonexistent hypothesis {request.hypothesis_id}"
                )
                continue
            if request.experiment_id in seen_ids:
                errors.append(f"experiment_requests[{index}] duplicates experiment_id {request.experiment_id}")
                continue
            seen_ids.add(request.experiment_id)
            requests.append(request)
        return requests, errors[:10]

    def _requests_from_hypotheses(
        self,
        hypotheses: list[dict[str, Any]],
    ) -> tuple[list[ExperimentRequest], list[str]]:
        requests: list[ExperimentRequest] = []
        errors: list[str] = []
        for hypothesis in hypotheses:
            hypothesis_id = str(hypothesis.get("hypothesis_id", ""))
            if not HYPOTHESIS_ID_RE.fullmatch(hypothesis_id):
                continue
            priority = _priority_for_hypothesis(hypothesis)
            for experiment_type in hypothesis.get("recommended_experiment_types", [])[:5]:
                try:
                    definition = self.registry.definitions[ExperimentType(experiment_type)]
                    requests.append(
                        ExperimentRequest(
                            experiment_id=f"EXP{len(requests) + 1:03d}",
                            hypothesis_id=hypothesis_id,
                            experiment_type=definition.experiment_type,
                            objective=_objective_for(hypothesis, definition),
                            expected_signal=_expected_signal_for(definition),
                            priority=priority,
                        )
                    )
                except Exception as exc:
                    errors.append(f"hypothesis {hypothesis_id} produced invalid experiment request: {type(exc).__name__}")
        return requests, errors[:10]

    def _score_request(self, request: ExperimentRequest, hypothesis: dict[str, Any]) -> float:
        definition = self.registry.definitions[ExperimentType(request.experiment_type)]
        planned = self.registry.plan_request(request, self.settings)
        supported_score = 1000.0 if planned.supported else 0.0
        confidence_score = float(hypothesis.get("confidence", 0.0) or 0.0) * 100.0
        impact_score = _banking_impact(str(hypothesis.get("category", ""))) * 10.0
        missing_score = min(len(hypothesis.get("missing_evidence", []) or []), 5) * 5.0
        priority_score = (11 - request.priority) * 4.0
        cost_penalty = definition.timeout_seconds / 15.0
        return supported_score + confidence_score + impact_score + missing_score + priority_score - cost_penalty


def _priority_for_hypothesis(hypothesis: dict[str, Any]) -> int:
    impact = _banking_impact(str(hypothesis.get("category", "")))
    confidence = float(hypothesis.get("confidence", 0.0) or 0.0)
    if impact >= 9 and confidence >= 0.6:
        return 1
    if impact >= 7 or confidence >= 0.5:
        return 2
    return 3


def _banking_impact(category: str) -> int:
    return {
        "OTP_INTERCEPTION": 10,
        "CREDENTIAL_PHISHING": 10,
        "REMOTE_CONTROL": 9,
        "BANK_IMPERSONATION": 9,
        "ACCESSIBILITY_ABUSE": 8,
        "OVERLAY_ATTACK": 8,
        "DATA_EXFILTRATION": 8,
        "DYNAMIC_CODE_LOADING": 7,
        "DEVICE_RECONNAISSANCE": 6,
        "UNKNOWN_SUSPICIOUS_BEHAVIOR": 4,
    }.get(category, 3)


def _objective_for(hypothesis: dict[str, Any], definition: ExperimentDefinition) -> str:
    title = str(hypothesis.get("title") or hypothesis.get("category") or "hypothesis")
    clean_title = re.sub(r"[^A-Za-z0-9 _.-]", "", title)[:120].strip() or "hypothesis"
    return f"Collect sandbox evidence relevant to {clean_title}."


def _expected_signal_for(definition: ExperimentDefinition) -> str:
    evidence = ", ".join(definition.produces_evidence_types[:3])
    return f"Trusted sandbox evidence of type {evidence}."
