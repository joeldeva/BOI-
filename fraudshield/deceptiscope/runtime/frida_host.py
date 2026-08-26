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
        """Converts structured Frida runtime events into trusted RuntimeEvidence records."""
        added: list[RuntimeEvidence] = []
        for event in events:
            has_marker = event.metadata.get("has_synthetic_marker", False)
            trust_level = (
                EvidenceTrustLevel.PAYLOAD_CORRELATED
                if has_marker
                else EvidenceTrustLevel.INSTRUMENTED
            )

            # Map event type to descriptive evidence description
            desc = f"Instrumented {event.observer.upper()} observation: {event.event_type} at {event.api}"
            if has_marker:
                desc += " (correlated synthetic test marker)"

            evidence = builder.add(
                evidence_type=f"instrumented_{event.observer}",
                description=desc,
                confidence=0.95 if has_marker else 0.90,
                trust_level=trust_level,
                process=event.target_package,
                metadata={
                    "schema": event.schema,
                    "observer": event.observer,
                    "event_type": event.event_type,
                    "api": event.api,
                    "event_metadata": event.metadata,
                },
            )
            if evidence:
                added.append(evidence)

        return added

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
        st = self.status()
        if not st.get("frida_installed"):
            return (
                RuntimeObserverStatus.UNAVAILABLE,
                [],
                ["Frida package is not installed in Python environment."],
            )

        try:
            import frida  # type: ignore
        except ImportError:
            return (
                RuntimeObserverStatus.UNAVAILABLE,
                [],
                ["Frida module could not be loaded."],
            )

        bundle_script = self.registry.build_bundle(observer_names)
        if not bundle_script.strip():
            return (
                RuntimeObserverStatus.SKIPPED,
                [],
                ["No observer scripts configured for requested experiments."],
            )

        events: list[FridaRuntimeEvent] = []
        warnings: list[str] = []

        def on_message(message: dict[str, Any], data: Any) -> None:
            parsed = self.process_raw_message(message, data)
            if parsed:
                events.append(parsed)

        session = None
        script = None
        try:
            device_manager = frida.get_device_manager()
            device = None
            if self.settings.adb_emulator_serial:
                device = device_manager.get_device(self.settings.adb_emulator_serial)
            else:
                device = frida.get_usb_device(timeout=2) or frida.get_remote_device()

            if not device:
                return (
                    RuntimeObserverStatus.UNAVAILABLE,
                    [],
                    ["Frida could not find a connected Android emulator device."],
                )

            pid = device.spawn([package_name])
            session = device.attach(pid)
            script = session.create_script(bundle_script)
            script.on("message", on_message)
            script.load()
            device.resume(pid)

            time.sleep(timeout_seconds)

            return RuntimeObserverStatus.COMPLETED, events, warnings
        except Exception as exc:
            logger.warning("Frida dynamic instrumentation session failed: %s", exc)
            return (
                RuntimeObserverStatus.FAILED,
                events,
                [f"Frida instrumentation failed: {type(exc).__name__}: {str(exc)[:200]}"],
            )
        finally:
            if script:
                try:
                    script.unload()
                except Exception:
                    pass
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
