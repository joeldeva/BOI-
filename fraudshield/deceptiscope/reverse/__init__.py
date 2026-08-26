from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fraudshield.deceptiscope.reverse.behavior_registry import (
    BEHAVIOR_SIGNATURES,
    BehaviorCategory,
    BehaviorRegistry,
    BehaviorSignature,
)
from fraudshield.deceptiscope.reverse.disassembler import (
    APKDisassembler,
    DisassembledMethod,
    DisassemblyResult,
)
from fraudshield.deceptiscope.reverse.method_context import (
    MethodMatchEvidence,
    extract_bounded_context,
)
from fraudshield.deceptiscope.reverse.sdk_classifier import (
    CodeOwnership,
    SDKClassifier,
    SDKRule,
)
from fraudshield.deceptiscope.reverse.smali_scanner import SmaliScanner


logger = logging.getLogger(__name__)


class MethodLevelAnalyzer:
    """High-level facade for method-level Android reverse engineering."""

    def __init__(
        self,
        disassembler: APKDisassembler | None = None,
        scanner: SmaliScanner | None = None,
    ) -> None:
        self.disassembler = disassembler or APKDisassembler()
        self.scanner = scanner or SmaliScanner()

    def analyze(self, apk_path: Path, app_package: str | None = None) -> dict[str, Any]:
        """Runs disassembly and method-level behavioral reverse engineering on an APK."""
        try:
            disassembly = self.disassembler.disassemble(apk_path)
            if disassembly.status != "completed":
                return {
                    "status": disassembly.status,
                    "tool_used": disassembly.tool_used,
                    "dex_count": disassembly.dex_count,
                    "method_count": len(disassembly.methods),
                    "match_count": 0,
                    "matches": [],
                    "matches_by_category": {},
                    "application_code_matches": [],
                    "known_sdk_matches": [],
                    "warnings": disassembly.warnings,
                }

            matches = self.scanner.scan_disassembly(disassembly, app_package=app_package)
            serialized_matches = [m.model_dump(mode="json") for m in matches]

            by_cat: dict[str, list[dict[str, Any]]] = {}
            app_matches: list[dict[str, Any]] = []
            sdk_matches: list[dict[str, Any]] = []

            for m in serialized_matches:
                by_cat.setdefault(m["category"], []).append(m)
                if m["code_ownership"] == CodeOwnership.APPLICATION_CODE.value:
                    app_matches.append(m)
                else:
                    sdk_matches.append(m)

            return {
                "status": "completed",
                "tool_used": disassembly.tool_used,
                "dex_count": disassembly.dex_count,
                "method_count": len(disassembly.methods),
                "match_count": len(serialized_matches),
                "matches": serialized_matches,
                "matches_by_category": by_cat,
                "application_code_matches": app_matches,
                "known_sdk_matches": sdk_matches,
                "warnings": disassembly.warnings,
            }
        except Exception as exc:
            logger.warning("Method-level reverse engineering encountered error: %s", exc)
            return {
                "status": "failed",
                "tool_used": "error",
                "dex_count": 0,
                "method_count": 0,
                "match_count": 0,
                "matches": [],
                "matches_by_category": {},
                "application_code_matches": [],
                "known_sdk_matches": [],
                "warnings": [f"Reverse engineering failed: {type(exc).__name__}: {str(exc)[:200]}"],
            }


__all__ = [
    "APKDisassembler",
    "BEHAVIOR_SIGNATURES",
    "BehaviorCategory",
    "BehaviorRegistry",
    "BehaviorSignature",
    "CodeOwnership",
    "DisassembledMethod",
    "DisassemblyResult",
    "MethodLevelAnalyzer",
    "MethodMatchEvidence",
    "SDKClassifier",
    "SDKRule",
    "SmaliScanner",
    "extract_bounded_context",
]
