from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from fraudshield.core.config import Settings
from fraudshield.deceptiscope.runtime.observer_registry import ObserverRegistry
from fraudshield.deceptiscope.runtime.runtime_models import (
    EvidenceTrustLevel,
    FridaRuntimeEvent,
    RuntimeObserverStatus,
)

if TYPE_CHECKING:
    from fraudshield.deceptiscope.dynamic import RuntimeEvidence, _RuntimeEvidenceBuilder


logger = logging.getLogger(__name__)


class FridaHost:
    """
    Manages safe, defensive Frida instrumentation sessions inside an isolated Android emulator.
    
    Security Guarantees:
    - AI cannot inject arbitrary JavaScript or shell commands.
    - Scripts are loaded exclusively from local trusted files.
    - Output is strictly validated as deceptiscope.runtime.v1 JSON messages.
    - Malformed messages and observer errors are contained without aborting the pipeline.
    """

    def __init__(
        self,
        settings: Settings,
        registry: ObserverRegistry | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry or ObserverRegistry()

    def status(self) -> dict[str, Any]:
        """Checks if Frida runtime capability is available on the host and emulator."""
        import importlib.util
        frida_installed = importlib.util.find_spec("frida") is not None

        return {
            "enabled": self.settings.dynamic_analysis_enabled,
            "frida_installed": frida_installed,
            "adb_path": self.settings.adb_path,
            "emulator_serial": self.settings.adb_emulator_serial or "default",
        }

    def process_raw_message(
        self,
        message: dict[str, Any],
        data: Any = None,
    ) -> FridaRuntimeEvent | None:
        """
        Validates and parses a raw message received from a Frida observer script.
        Returns a validated FridaRuntimeEvent or None if malformed/unknown.
        """
        if not isinstance(message, dict):
            return None

        msg_type = message.get("type")
        if msg_type != "send":
            # Ignore log/error messages that do not conform to structured send
            return None

        payload = message.get("payload")
        if not isinstance(payload, dict):
            return None

        try:
            event = FridaRuntimeEvent.model_validate(payload)
            if event.is_valid_event():
                return event
            logger.debug("Ignored unrecognized Frida event: %s/%s", event.observer, event.event_type)
            return None
        except Exception as exc:
            logger.debug("Rejected malformed Frida message payload: %s", exc)
            return None

    def normalize_to_evidence(
        self,
        events: list[FridaRuntimeEvent],
        builder: _RuntimeEvidenceBuilder,
    ) -> list[RuntimeEvidence]:
        """Converts structured Frida runtime events into canonical trusted RuntimeEvidence records."""
        added: list[RuntimeEvidence] = []
        for event in events:
            ev_type = self._map_event_to_canonical_type(event.observer, event.event_type)
            
            # Frida raw observations have INSTRUMENTED trust level.
            # PAYLOAD_CORRELATED is assigned ONLY after deterministic backend lineage correlation.
            trust_level = EvidenceTrustLevel.INSTRUMENTED

            desc = f"Instrumented {event.observer.upper()} observation: {event.event_type} at {event.api}"
            if event.metadata.get("has_synthetic_marker"):
                desc += " (synthetic marker detected in memory)"

            metadata: dict[str, Any] = {
                "schema": event.schema_version,
                "observer": event.observer,
                "event_type": event.event_type,
                "api": event.api,
                "target_package": event.target_package,
                "event_metadata": event.metadata,
            }
            # Copy specific metadata keys for direct compatibility
            if "destination" in event.metadata:
                metadata["destination"] = event.metadata["destination"]
            if "url" in event.metadata:
                metadata["destination"] = event.metadata["url"]
                metadata["url"] = event.metadata["url"]
            if "endpoint" in event.metadata:
                metadata["destination"] = event.metadata["endpoint"]
            if "dex_path" in event.metadata:
                metadata["dex_path"] = event.metadata["dex_path"]
            if "source_path" in event.metadata:
                metadata["source_path"] = event.metadata["source_path"]
            if "body_preview_redacted" in event.metadata:
                metadata["body_preview_redacted"] = event.metadata["body_preview_redacted"]
                metadata["payload"] = event.metadata["body_preview_redacted"]
            if "body_size" in event.metadata:
                metadata["body_size"] = event.metadata["body_size"]

            evidence = builder.add(
                evidence_type=ev_type,
                description=desc,
                confidence=0.95,
                trust_level=trust_level,
                process=event.target_package,
                metadata=metadata,
                timestamp_ms=event.timestamp_ms if event.timestamp_ms > 0 else None,
            )
            if evidence:
                added.append(evidence)

        return added

    @staticmethod
    def _map_event_to_canonical_type(observer: str, event_type: str) -> str:
        obs = observer.lower()
        evt = event_type.upper()
        if obs == "sms" or evt.startswith("SMS_"):
            return "sms_access"
        if obs == "network" or evt in {"HTTP_REQUEST_OBSERVED", "SOCKET_CONNECT_OBSERVED", "URL_OPENED"}:
            return "network_destination"
        if obs == "accessibility" or evt.startswith("ACCESSIBILITY_"):
            return "accessibility_behavior"
        if obs == "notification" or evt.startswith("NOTIFICATION_"):
            return "accessibility_behavior"
        if obs == "dynamic_dex" or evt in {"DEX_CLASS_LOADER_INIT", "PATH_CLASS_LOADER_INIT", "IN_MEMORY_DEX_LOADED", "DEX_FILE_LOADED"}:
            return "dynamic_code_load"
        if obs == "webview" or evt.startswith("WEBVIEW_"):
            return "webview_activity"
        return f"instrumented_{obs}"

    def observation_session(
        self,
        package_name: str,
        observer_names: list[str],
    ) -> FridaObservationSession:
        """Creates a managed observation session active during an experiment execution window."""
        return FridaObservationSession(self, package_name, observer_names)

    def run_observers(
        self,
        package_name: str,
        observer_names: list[str],
        timeout_seconds: int = 10,
    ) -> tuple[RuntimeObserverStatus, list[FridaRuntimeEvent], list[str]]:
        """
        Runs approved observer scripts against the target package on the emulator.
        
        Fail-Safe Invariant:
        If Frida is unavailable or the process fails, returns UNAVAILABLE or FAILED
        with diagnostic warnings without raising unhandled exceptions.
        """
        with self.observation_session(package_name, observer_names) as session:
            if session.status == RuntimeObserverStatus.COMPLETED:
                time.sleep(timeout_seconds)
            return session.status, session.events, session.warnings


class FridaObservationSession:
    """
    Manages an active Frida instrumentation session during an experiment execution window.
    Ensures hooks are attached and active BEFORE the controlled experiment action occurs.
    """

    def __init__(
        self,
        frida_host: FridaHost,
        package_name: str,
        observer_names: list[str],
    ) -> None:
        self.frida_host = frida_host
        self.package_name = package_name
        self.observer_names = observer_names
        self.status = RuntimeObserverStatus.UNAVAILABLE
        self.events: list[FridaRuntimeEvent] = []
        self.warnings: list[str] = []
        self._session: Any = None
        self._script: Any = None
        self._device: Any = None
        self._pid: int | None = None

    def __enter__(self) -> FridaObservationSession:
        st = self.frida_host.status()
        if not st.get("frida_installed"):
            self.warnings.append("Frida package is not installed in Python environment.")
            return self

        try:
            import frida  # type: ignore
        except ImportError:
            self.warnings.append("Frida module could not be loaded.")
            return self

        bundle_script = self.frida_host.registry.build_bundle(self.observer_names)
        if not bundle_script.strip():
            self.status = RuntimeObserverStatus.UNAVAILABLE
            return self

        def on_message(message: dict[str, Any], data: Any) -> None:
            parsed = self.frida_host.process_raw_message(message, data)
            if parsed:
                self.events.append(parsed)

        try:
            device_manager = frida.get_device_manager()
            if self.frida_host.settings.adb_emulator_serial:
                self._device = device_manager.get_device(self.frida_host.settings.adb_emulator_serial)
            else:
                self._device = frida.get_usb_device(timeout=2) or frida.get_remote_device()

            if not self._device:
                self.warnings.append("Frida could not find a connected Android emulator device.")
                return self

            # Attach to existing running process if possible, or spawn suspended -> attach -> load -> resume
            try:
                self._session = self._device.attach(self.package_name)
            except Exception:
                self._pid = self._device.spawn([self.package_name])
                self._session = self._device.attach(self._pid)

            self._script = self._session.create_script(bundle_script)
            self._script.on("message", on_message)
            self._script.load()

            if self._pid is not None:
                self._device.resume(self._pid)

            self.status = RuntimeObserverStatus.COMPLETED
        except Exception as exc:
            logger.warning("Frida dynamic observation session startup failed: %s", exc)
            self.status = RuntimeObserverStatus.FAILED
            self.warnings.append(f"Frida session startup failed: {type(exc).__name__}: {str(exc)[:200]}")

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._script:
            try:
                self._script.unload()
            except Exception:
                pass
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass

