from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from fraudshield.core.config import Settings


logger = logging.getLogger(__name__)
IP_OR_DOMAIN_RE = re.compile(
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class Narrative:
    text: str
    source: str
    warning: str | None = None


def deterministic_narrative(findings: dict[str, Any]) -> str:
    score = findings["risk"]["overall_score"]
    severity = findings["risk"]["severity"]
    app = findings["extraction"].get("app", {})
    evidence = findings["risk"].get("evidence", [])
    mitre = findings.get("mitre_attack", [])
    indicators = findings.get("indicator_candidates", [])
    assessment = findings.get("malware_assessment", {})
    engine_analysis = findings.get("engine_analysis", {})

    lines = [
        "Executive verdict",
        f"{app.get('app_label', 'Unknown app')} ({app.get('package_name', 'unknown')}) received a deterministic risk score of {score}/100 ({severity}).",
        f"Malware assessment: {assessment.get('verdict', 'INCONCLUSIVE')}. Legitimacy is not established and no safe-to-install claim is made.",
        "This score is evidence-weighted and was not generated or modified by a language model.",
        "",
        "Key verified evidence",
    ]
    if evidence:
        for item in evidence[:10]:
            artifacts = ", ".join(str(value) for value in item.get("artifacts", [])[:4])
            suffix = f" Evidence: {artifacts}." if artifacts else ""
            lines.append(f"- [{item['rule_id']}] {item['title']}: {item['rationale']}.{suffix}")
    else:
        lines.append("- No configured high-risk rule matched the extracted evidence.")
    lines.extend(["", "MITRE ATT&CK for Mobile mapping"])
    if mitre:
        lines.extend(f"- {item['technique_id']} — {item['name']}" for item in mitre)
    else:
        lines.append("- No supported MITRE technique was mapped from current evidence.")
    lines.extend(["", "Observed indicator candidates"])
    if indicators:
        lines.extend(f"- {item['type']}: {item['value']}" for item in indicators[:20])
    else:
        lines.append("- No indicator candidate met the emission policy.")
    lines.extend(["", "Engine coverage"])
    for engine in engine_analysis.get("engines", [])[:15]:
        lines.append(f"- {engine.get('label', engine.get('id'))}: {engine.get('status')} ({engine.get('privacy', 'unknown privacy mode')})")
    reputation = engine_analysis.get("reputation", {})
    lines.append(f"- Hash reputation: {reputation.get('verdict', 'not-queried')}. A not-found result is not proof of safety.")
    lines.extend(
        [
            "",
            "Recommended analyst actions",
            "- Validate the signer and package identity against the bank's trusted application inventory.",
            "- Review every high-point rule and its artifact before making an enforcement decision.",
            "- Correlate emitted indicators with endpoint telemetry, threat intelligence, and customer reports.",
            "- Use an isolated emulator for any runtime testing; never install an unknown APK on a personal device.",
        ]
    )
    return "\n".join(lines)


class LLMNarrativeClient:
    """Optional interpretation layer. Deterministic findings remain authoritative."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def explain(self, findings: dict[str, Any]) -> Narrative:
        fallback = deterministic_narrative(findings)
        provider = self.settings.llm_provider
        if provider == "disabled":
            return Narrative(fallback, "deterministic")
        try:
            if provider == "openai":
                text = self._openai(findings)
            elif provider == "gemini":
                text = self._gemini(findings)
            else:
                return Narrative(
                    fallback,
                    "deterministic",
                    f"Unsupported LLM provider '{provider}'; deterministic narrative used.",
                )
            self._validate_grounding(text, findings)
            return Narrative(text[:8000], provider)
        except Exception as exc:
            logger.warning("LLM narrative failed; deterministic narrative retained: %s", type(exc).__name__)
            return Narrative(
                fallback,
                "deterministic",
                "Optional LLM narrative was unavailable or failed grounding validation.",
            )

    def _prompt(self, findings: dict[str, Any]) -> str:
        compact = {
            "app": findings["extraction"].get("app", {}),
            "file": findings["extraction"].get("file", {}),
            "risk": findings["risk"],
            "malware_assessment": findings.get("malware_assessment", {}),
            "engine_analysis": findings.get("engine_analysis", {}),
            "fraud_delta": findings["fraud_delta"],
            "mitre_attack": findings["mitre_attack"],
            "indicator_candidates": findings["indicator_candidates"],
        }
        return json.dumps(compact, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _instructions() -> str:
        return (
            "You are a defensive bank malware-analysis report writer. Summarize only the supplied verified JSON. "
            "Never add a malware-family name, domain, IP, permission, package, score, technique, or capability that "
            "is absent from the input. Do not change any numeric score. Clearly distinguish observed evidence from "
            "analyst inference. Return plain text with sections: Verdict, Verified evidence, Limitations, Recommended review."
        )

    def _openai(self, findings: dict[str, Any]) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=self.settings.llm_api_key, timeout=self.settings.llm_timeout_seconds)
        response = client.responses.create(
            model=self.settings.llm_model,
            instructions=self._instructions(),
            input=self._prompt(findings),
        )
        return str(response.output_text)

    def _gemini(self, findings: dict[str, Any]) -> str:
        import httpx

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.settings.llm_model}:generateContent"
        payload = {
            "system_instruction": {"parts": [{"text": self._instructions()}]},
            "contents": [{"role": "user", "parts": [{"text": self._prompt(findings)}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1400},
        }
        with httpx.Client(timeout=self.settings.llm_timeout_seconds) as client:
            response = client.post(url, params={"key": self.settings.llm_api_key}, json=payload)
            response.raise_for_status()
            body = response.json()
        return "\n".join(
            part.get("text", "")
            for candidate in body.get("candidates", [])
            for part in candidate.get("content", {}).get("parts", [])
            if part.get("text")
        )

    @staticmethod
    def _validate_grounding(text: str, findings: dict[str, Any]) -> None:
        if not text or len(text) > 20_000:
            raise ValueError("invalid LLM response length")
        allowed: set[str] = set()
        network = findings["extraction"].get("network_indicators", {})
        for values in network.values():
            allowed.update(str(value).lower() for value in values)
        app = findings["extraction"].get("app", {})
        file_info = findings["extraction"].get("file", {})
        allowed.update(
            str(value).lower()
            for value in (app.get("package_name"), file_info.get("name"))
            if value
        )
        for match in IP_OR_DOMAIN_RE.findall(text):
            token = match.lower().rstrip(".")
            if token not in allowed and not token.endswith("attack.mitre.org"):
                raise ValueError(f"ungrounded network indicator: {token}")


def interpret_methods_locally(methods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evidence-preserving fallback that never pretends to decompile code."""
    results = []
    for item in methods:
        name = str(item.get("method") or item.get("name") or "unknown")[:300]
        source = str(item.get("source", ""))
        matched = []
        for token in (
            "DexClassLoader",
            "SmsManager",
            "AccessibilityService",
            "dispatchGesture",
            "getInstalledApplications",
            "SYSTEM_ALERT_WINDOW",
        ):
            if token.lower() in source.lower():
                matched.append(token)
        results.append(
            {
                "method": name,
                "observed_tokens": matched,
                "interpretation": (
                    "Potentially security-relevant APIs are present; review control flow and call sites."
                    if matched
                    else "No supported high-risk token was found in the supplied snippet."
                ),
                "source": "deterministic-token-review",
            }
        )
    return results
