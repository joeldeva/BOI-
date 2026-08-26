from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from fraudshield.deceptiscope.experiments import ExperimentType


logger = logging.getLogger(__name__)

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"

# Approved Mapping from ExperimentType to Defensive Observer Packs
EXPERIMENT_OBSERVER_MAP: dict[ExperimentType, tuple[str, ...]] = {
    ExperimentType.SYNTHETIC_SMS: ("sms", "network"),
    ExperimentType.ACCESSIBILITY_OBSERVATION: ("accessibility",),
    ExperimentType.NETWORK_OBSERVATION: ("network",),
    ExperimentType.DYNAMIC_CODE_LOAD_OBSERVATION: ("dynamic_dex",),
    ExperimentType.WEBVIEW_OBSERVATION: ("webview",),
    ExperimentType.LAUNCH_APP: ("sms", "network", "dynamic_dex", "accessibility", "webview"),
    ExperimentType.OBSERVE_STARTUP: ("dynamic_dex", "network"),
    ExperimentType.PACKAGE_STATE_CAPTURE: (),
    ExperimentType.LOGCAT_CAPTURE: (),
    ExperimentType.FILESYSTEM_DIFF: (),
    ExperimentType.UI_SCREENSHOT: (),
}

OBSERVER_SCRIPT_FILES: dict[str, str] = {
    "sms": "sms_observer.js",
    "notification": "notification_observer.js",
    "accessibility": "accessibility_observer.js",
    "network": "network_observer.js",
    "dynamic_dex": "dynamic_dex_observer.js",
    "webview": "webview_observer.js",
}


class ObserverRegistry:
    """Registry managing trusted, local defensive Frida observer scripts."""

    def __init__(self, scripts_dir: Path = SCRIPTS_DIR) -> None:
        self.scripts_dir = scripts_dir

    def get_observers_for_experiments(
        self,
        experiments: Sequence[ExperimentType],
    ) -> list[str]:
        """Returns deduplicated list of approved observer module names."""
        selected: list[str] = []
        for exp in experiments:
            for obs in EXPERIMENT_OBSERVER_MAP.get(exp, ()):
                if obs in OBSERVER_SCRIPT_FILES and obs not in selected:
                    selected.append(obs)
        return selected

    def load_observer_script(self, observer_name: str) -> str:
        """Loads a single trusted local observer script."""
        if observer_name not in OBSERVER_SCRIPT_FILES:
            raise ValueError(f"Unknown observer: {observer_name}")

        file_name = OBSERVER_SCRIPT_FILES[observer_name]
        script_path = self.scripts_dir / file_name
        if not script_path.exists():
            raise FileNotFoundError(f"Trusted script missing: {script_path}")

        return script_path.read_text(encoding="utf-8")

    def build_bundle(self, observer_names: Sequence[str]) -> str:
        """Combines multiple trusted observer scripts into a single sandboxed bundle."""
        snippets: list[str] = []
        for name in observer_names:
            if name in OBSERVER_SCRIPT_FILES:
                try:
                    script = self.load_observer_script(name)
                    snippets.append(f"// --- Observer: {name} ---\n{script}")
                except Exception as exc:
                    logger.warning("Failed to load observer script %s: %s", name, exc)

        return "\n\n".join(snippets)
