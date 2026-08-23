from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PERMISSION_WEIGHTS = {
    "android.permission.READ_SMS": 0.14,
    "android.permission.RECEIVE_SMS": 0.12,
    "android.permission.SEND_SMS": 0.10,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.14,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.10,
    "android.permission.QUERY_ALL_PACKAGES": 0.07,
    "android.permission.READ_CONTACTS": 0.05,
    "android.permission.READ_CALL_LOG": 0.07,
    "android.permission.RECORD_AUDIO": 0.04,
}

SIGNAL_WEIGHTS = {
    "dynamic_code_loading": 0.10,
    "installed_app_enumeration": 0.08,
    "sms_api": 0.08,
    "command_execution": 0.10,
    "input_injection": 0.12,
}


class FraudDeltaCalculator:
    version = "fraud-delta-2026.2"

    def __init__(self, baseline_path: Path) -> None:
        with baseline_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.baseline_version = str(payload.get("version", "unknown"))
        self.categories = payload.get("categories", {})

    def calculate(self, extracted: dict[str, Any], category: str) -> dict[str, Any]:
        normalized_category = category.strip().lower()
        baseline = self.categories.get(normalized_category) or self.categories.get("other")
        normalized_category = normalized_category if normalized_category in self.categories else "other"
        common = set(baseline.get("common_permissions", []))
        tolerated = set(baseline.get("tolerated_permissions", []))
        requested = set(extracted.get("permissions", {}).get("requested", []))
        unexpected = sorted(requested - common - tolerated)
        weighted_permissions = [permission for permission in unexpected if permission in PERMISSION_WEIGHTS]

        contributions: list[dict[str, Any]] = []
        raw = 0.0
        for permission in weighted_permissions:
            weight = PERMISSION_WEIGHTS[permission]
            raw += weight
            contributions.append(
                {
                    "kind": "permission",
                    "evidence": permission,
                    "weight": weight,
                    "reason": f"Unexpected for the declared '{normalized_category}' category",
                }
            )

        signals = extracted.get("code_signals", {})
        for signal, weight in SIGNAL_WEIGHTS.items():
            if signals.get(signal, {}).get("detected"):
                raw += weight
                contributions.append(
                    {
                        "kind": "code_signal",
                        "evidence": signal,
                        "weight": weight,
                        "reason": f"Observed signal is uncommon in the '{normalized_category}' baseline",
                    }
                )

        components = extracted.get("components", {})
        if components.get("accessibility_service"):
            raw += 0.13
            contributions.append(
                {
                    "kind": "component",
                    "evidence": "accessibility_service",
                    "weight": 0.13,
                    "reason": "Accessibility service is abnormal for the declared category",
                }
            )
        if components.get("sms_receiver"):
            raw += 0.10
            contributions.append(
                {
                    "kind": "component",
                    "evidence": "sms_receiver",
                    "weight": 0.10,
                    "reason": "SMS broadcast interception is abnormal for the declared category",
                }
            )
        if extracted.get("certificate", {}).get("bank_impersonation_flag"):
            raw += 0.15
            contributions.append(
                {
                    "kind": "identity",
                    "evidence": "bank_signer_not_in_trusted_inventory",
                    "weight": 0.15,
                    "reason": "Bank-branded identity uses a signer absent from the configured trusted inventory",
                }
            )

        score = min(1.0, round(raw, 4))
        return {
            "model_version": self.version,
            "baseline_version": self.baseline_version,
            "category": normalized_category,
            "score": score,
            "is_anomalous": score >= 0.35,
            "unexpected_permissions": unexpected,
            "contributions": contributions,
            "methodology_note": (
                "Heuristic category-distance score; it is not a malware probability and must be read with rule evidence."
            ),
        }
