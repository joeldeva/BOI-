from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from fraudshield.core.config import Settings
from fraudshield.core.errors import ConfigurationError, ValidationError


class DynamicLiteAnalyzer:
    """Opt-in ADB observations, hard-guarded to an Android emulator.

    This component is disabled by default and is never invoked by static analysis.
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
        }

    def observe(self, apk_path: Path, package_name: str) -> dict[str, Any]:
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

        observations: dict[str, Any] = {
            "mode": "dynamic-lite",
            "emulator_serial": serial,
            "installed": False,
            "launched": False,
            "package_dump": "",
            "logcat_excerpt": [],
            "warnings": [],
        }
        try:
            self._run("install", "-r", "-t", str(apk_path))
            observations["installed"] = True
            launch = self._run("shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1")
            observations["launched"] = "Events injected: 1" in launch
            observations["package_dump"] = self._run("shell", "dumpsys", "package", package_name)[:20_000]
            logcat = self._run("logcat", "-d", "-t", "300")
            observations["logcat_excerpt"] = [line[:500] for line in logcat.splitlines() if package_name in line][-100:]
            return observations
        finally:
            if observations["installed"]:
                try:
                    self._run("uninstall", package_name, timeout=30)
                except Exception:
                    observations["warnings"].append("Automatic emulator uninstall did not complete")

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

