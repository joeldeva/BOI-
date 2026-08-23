from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    category: str
    points: int
    rationale: str
    predicate: Callable[[dict[str, Any]], tuple[bool, list[str]]]


def _permission(name: str) -> Callable[[dict[str, Any]], tuple[bool, list[str]]]:
    def check(features: dict[str, Any]) -> tuple[bool, list[str]]:
        present = name in features["permissions"]
        return present, [name] if present else []

    return check


def _component(name: str) -> Callable[[dict[str, Any]], tuple[bool, list[str]]]:
    def check(features: dict[str, Any]) -> tuple[bool, list[str]]:
        present = bool(features["components"].get(name))
        return present, [name] if present else []

    return check


def _signal(name: str) -> Callable[[dict[str, Any]], tuple[bool, list[str]]]:
    def check(features: dict[str, Any]) -> tuple[bool, list[str]]:
        signal = features["signals"].get(name, {})
        return bool(signal.get("detected")), list(signal.get("evidence", []))

    return check


def _obfuscated(features: dict[str, Any]) -> tuple[bool, list[str]]:
    obfuscation = features["obfuscation"]
    detected = bool(obfuscation.get("likely_name_obfuscation"))
    return detected, [f"short_class_ratio={obfuscation.get('short_class_ratio', 0)}"] if detected else []


def _bank_impersonation(features: dict[str, Any]) -> tuple[bool, list[str]]:
    cert = features["certificate"]
    detected = bool(cert.get("bank_impersonation_flag"))
    artifacts = (
        [
            f"certificate_sha256={cert.get('sha256') or 'unknown'}",
            f"trust_evaluation={cert.get('trust_evaluation') or 'unknown'}",
        ]
        if detected
        else []
    )
    return detected, artifacts


def _embedded_payload(features: dict[str, Any]) -> tuple[bool, list[str]]:
    payloads = list(features["file"].get("embedded_payloads", []))
    return bool(payloads), payloads[:10]


RULES: tuple[Rule, ...] = (
    Rule("APK-CRED-001", "Read SMS messages", "credential_theft", 18, "Can access OTP-bearing SMS data", _permission("android.permission.READ_SMS")),
    Rule("APK-CRED-002", "Receive SMS broadcasts", "credential_theft", 14, "Can observe incoming OTP messages", _permission("android.permission.RECEIVE_SMS")),
    Rule("APK-CRED-003", "SMS receiver component", "credential_theft", 18, "Manifest declares an SMS broadcast receiver", _component("sms_receiver")),
    Rule("APK-CRED-004", "Accessibility service", "credential_theft", 22, "Accessibility events can expose sensitive on-screen text", _component("accessibility_service")),
    Rule("APK-CRED-005", "SMS API usage", "credential_theft", 10, "DEX evidence references SMS APIs", _signal("sms_api")),
    Rule("APK-PAY-001", "Overlay permission", "payment_manipulation", 22, "Draw-over-apps can support credential overlays", _permission("android.permission.SYSTEM_ALERT_WINDOW")),
    Rule("APK-PAY-002", "Installed-app enumeration", "payment_manipulation", 17, "Can identify targeted banking/payment apps", _signal("installed_app_enumeration")),
    Rule("APK-PAY-003", "Input injection APIs", "payment_manipulation", 28, "Accessibility automation can act inside other applications", _signal("input_injection")),
    Rule("APK-PAY-004", "Accessibility service", "payment_manipulation", 20, "Privileged UI observation/control increases transaction risk", _component("accessibility_service")),
    Rule("APK-IMP-001", "Bank identity/certificate mismatch", "fraud_impersonation", 45, "Bank branding is paired with a signer absent from the configured trusted inventory", _bank_impersonation),
    Rule("APK-IMP-002", "Package installation capability", "fraud_impersonation", 18, "Can request installation of additional APKs", _permission("android.permission.REQUEST_INSTALL_PACKAGES")),
    Rule("APK-EVA-001", "Dynamic code loading", "evasion_resilience", 25, "Runtime-loaded code can evade package-time inspection", _signal("dynamic_code_loading")),
    Rule("APK-EVA-002", "Reflection", "evasion_resilience", 12, "Reflection can conceal API use from simple scanners", _signal("reflection")),
    Rule("APK-EVA-003", "Command execution", "evasion_resilience", 25, "Process execution expands post-install capabilities", _signal("command_execution")),
    Rule("APK-EVA-004", "Name obfuscation", "evasion_resilience", 18, "High short-name ratio hinders static review", _obfuscated),
    Rule("APK-EVA-005", "Embedded executable payload", "evasion_resilience", 20, "APK contains secondary executable artifacts", _embedded_payload),
)


class RiskScorer:
    version = "apk-risk-2026.4"
    weights = {
        "credential_theft": 0.34,
        "payment_manipulation": 0.30,
        "fraud_impersonation": 0.20,
        "evasion_resilience": 0.16,
    }

    def calculate(
        self,
        extracted: dict[str, Any],
        fraud_delta: dict[str, Any],
        *,
        engine_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        features = {
            "permissions": set(extracted.get("permissions", {}).get("requested", [])),
            "components": extracted.get("components", {}),
            "signals": extracted.get("code_signals", {}),
            "certificate": extracted.get("certificate", {}),
            "obfuscation": extracted.get("obfuscation", {}),
            "file": extracted.get("file", {}),
        }
        totals = {name: 0 for name in self.weights}
        evidence: list[dict[str, Any]] = []
        for rule in RULES:
            matched, artifacts = rule.predicate(features)
            if not matched:
                continue
            totals[rule.category] += rule.points
            evidence.append(
                {
                    "rule_id": rule.id,
                    "title": rule.title,
                    "category": rule.category,
                    "points": rule.points,
                    "rationale": rule.rationale,
                    "artifacts": artifacts,
                }
            )

        permissions = features["permissions"]
        components = features["components"]
        if (
            "android.permission.READ_SMS" in permissions
            and "android.permission.RECEIVE_SMS" in permissions
            and components.get("sms_receiver")
        ):
            self._interaction(totals, evidence, "APK-INT-001", "credential_theft", 18, "SMS permission and receiver combination", ["READ_SMS", "RECEIVE_SMS", "sms_receiver"])
        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions and components.get("accessibility_service"):
            self._interaction(totals, evidence, "APK-INT-002", "payment_manipulation", 22, "Overlay and accessibility combination", ["SYSTEM_ALERT_WINDOW", "accessibility_service"])
        if features["signals"].get("dynamic_code_loading", {}).get("detected") and features["file"].get("embedded_payloads"):
            self._interaction(totals, evidence, "APK-INT-003", "evasion_resilience", 15, "Loader plus embedded-payload combination", list(features["file"]["embedded_payloads"])[:5])

        external_evidence_count = self._engine_evidence(
            totals,
            evidence,
            (engine_analysis or {}).get("normalized_findings", []),
        )

        sub_scores = {name: min(100, value) for name, value in totals.items()}
        weighted = sum(sub_scores[name] * weight for name, weight in self.weights.items())
        delta_adjustment = min(10.0, float(fraud_delta.get("score", 0.0)) * 10.0)
        overall = min(100, round(weighted + delta_adjustment))
        severity = self._severity(overall)
        coverage = extracted.get("coverage", {})
        covered = sum(1 for key in ("archive", "manifest", "dex", "certificate") if coverage.get(key))
        confidence = round(min(0.98, 0.45 + covered * 0.11 + min(len(evidence), 8) * 0.0125), 3)
        if extracted.get("analysis_quality") == "partial":
            confidence = min(confidence, 0.68)
        unavailable = int((engine_analysis or {}).get("summary", {}).get("unavailable_or_failed", 0))
        if unavailable:
            confidence = max(0.35, round(confidence - min(0.08, unavailable * 0.01), 3))
        return {
            "model_version": self.version,
            "overall_score": overall,
            "severity": severity,
            "confidence": confidence,
            "sub_scores": sub_scores,
            "evidence": sorted(evidence, key=lambda item: (-item["points"], item["rule_id"])),
            "fraud_delta_adjustment": round(delta_adjustment, 2),
            "external_engine_evidence_count": external_evidence_count,
            "thresholds": {"LOW": "0-24", "MEDIUM": "25-49", "HIGH": "50-74", "CRITICAL": "75-100"},
            "methodology_note": "Deterministic weighted rules; the score is not produced or modified by an LLM.",
        }

    @staticmethod
    def _engine_evidence(
        totals: dict[str, int],
        evidence: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> int:
        allowed_categories = set(totals)
        used: dict[tuple[str, str], int] = {}
        accepted = 0
        for finding in findings:
            if not finding.get("score_eligible") or float(finding.get("confidence", 0)) < 0.7:
                continue
            category = str(finding.get("risk_category", ""))
            if category not in allowed_categories:
                continue
            engine = str(finding.get("engine", "optional"))
            requested = max(0, min(30, int(finding.get("risk_points", 0))))
            key = (engine, category)
            remaining = max(0, 25 - used.get(key, 0))
            points = min(requested, remaining)
            if points <= 0:
                continue
            used[key] = used.get(key, 0) + points
            totals[category] += points
            accepted += 1
            evidence.append(
                {
                    "rule_id": f"APK-EXT-{engine.upper()}-{accepted:03d}",
                    "title": str(finding.get("title", "Optional engine finding"))[:300],
                    "category": category,
                    "points": points,
                    "rationale": (
                        f"Normalized local evidence from {engine}; contribution is capped per engine and risk dimension."
                    ),
                    "artifacts": [str(item)[:500] for item in finding.get("evidence", [])[:12]],
                    "source_finding_id": str(finding.get("id", ""))[:160],
                }
            )
        return accepted

    @staticmethod
    def _interaction(
        totals: dict[str, int],
        evidence: list[dict[str, Any]],
        rule_id: str,
        category: str,
        points: int,
        rationale: str,
        artifacts: list[str],
    ) -> None:
        totals[category] += points
        evidence.append(
            {
                "rule_id": rule_id,
                "title": "Correlated behavior combination",
                "category": category,
                "points": points,
                "rationale": rationale,
                "artifacts": artifacts,
            }
        )

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"
