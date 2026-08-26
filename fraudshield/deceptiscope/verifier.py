from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


TERMINAL_FAILURE_STATUSES = {"FAILED", "TIMED_OUT"}
UNAVAILABLE_STATUSES = {"UNAVAILABLE", "UNSUPPORTED"}


class HypothesisVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    category: str
    original_status: str
    verified_status: str
    evidence_strength: float = Field(ge=0.0, le=1.0)
    ai_confidence: float = Field(ge=0.0, le=1.0)
    static_evidence_ids: list[str] = Field(default_factory=list)
    runtime_evidence_ids: list[str] = Field(default_factory=list)
    experiment_result_ids: list[str] = Field(default_factory=list)
    observed_signals: list[str] = Field(default_factory=list)
    missing_signals: list[str] = Field(default_factory=list)
    deterministic_explanation: str
    confirmation_allowed: bool


def _trust_str(ev: dict[str, Any]) -> str:
    tl = ev.get("trust_level")
    if hasattr(tl, "value"):
        return str(tl.value).upper()
    return str(tl or "").upper()


class HypothesisVerifier:
    """Deterministically verifies hypothesis states from static/runtime evidence."""

    def verify_all(
        self,
        hypotheses: list[dict[str, Any]],
        findings: dict[str, Any],
        normalized_evidence: list[Any],
    ) -> list[dict[str, Any]]:
        return [
            self.verify(hypothesis, findings, normalized_evidence).model_dump(mode="json")
            for hypothesis in hypotheses
        ]

    def verify(
        self,
        hypothesis: dict[str, Any],
        findings: dict[str, Any],
        normalized_evidence: list[Any],
    ) -> HypothesisVerification:
        category = str(hypothesis.get("category", "UNKNOWN_SUSPICIOUS_BEHAVIOR"))
        if category == "OTP_INTERCEPTION":
            return self._verify_otp(hypothesis, findings, normalized_evidence)
        if category == "DATA_EXFILTRATION":
            return self._verify_data_exfiltration(hypothesis, findings, normalized_evidence)
        if category == "ACCESSIBILITY_ABUSE":
            return self._verify_accessibility(hypothesis, findings, normalized_evidence)
        return self._verify_general(hypothesis, findings, normalized_evidence)

    def _verify_otp(
        self,
        hypothesis: dict[str, Any],
        findings: dict[str, Any],
        normalized_evidence: list[Any],
    ) -> HypothesisVerification:
        static_signals = _otp_static_signals(findings)
        runtime = _runtime_index(findings)
        experiment = _experiment_index(findings)
        observed = list(static_signals)
        missing: list[str] = []

        synthetic_delivered_items = runtime["by_type"].get("synthetic_sms_delivered", [])
        sms_access_items = runtime["by_type"].get("sms_access", [])
        marker_items = runtime["by_type"].get("synthetic_marker_correlation", [])

        synthetic_delivered = bool(synthetic_delivered_items)
        sms_access = bool(sms_access_items)
        marker = bool(marker_items)

        if synthetic_delivered:
            observed.append("synthetic_sms_delivered")
        else:
            missing.append("synthetic_sms_delivered")
        if sms_access:
            observed.append("sms_access")
        else:
            missing.append("sms_access")
        if marker:
            observed.append("synthetic_marker_correlation")
        else:
            missing.append("synthetic_marker_correlation")

        failed = _has_failed_experiment(experiment, {"SYNTHETIC_SMS", "LOGCAT_CAPTURE"})
        completed_sms = _has_completed_experiment(experiment, {"SYNTHETIC_SMS"})
        static_supported = bool(static_signals)

        has_instrumented_delivery = any(
            _trust_str(ev) in {"INSTRUMENTED", "PAYLOAD_CORRELATED", "SYSTEM_OBSERVED"}
            for ev in synthetic_delivered_items
        )
        has_trusted_correlation = any(
            _trust_str(ev) in {"INSTRUMENTED", "PAYLOAD_CORRELATED"}
            for ev in (sms_access_items + marker_items)
        )
        confirmation_allowed = (
            static_supported
            and synthetic_delivered
            and (sms_access or marker)
            and has_instrumented_delivery
            and has_trusted_correlation
        )

        if confirmation_allowed:
            status = "CONFIRMED"
            strength = 1.0
            explanation = "OTP interception confirmed by static SMS capability plus instrumented synthetic SMS delivery and correlated marker access."
        elif failed:
            status = "INCONCLUSIVE"
            strength = 0.35 if static_supported else 0.1
            explanation = "OTP runtime experiment failed or timed out, so absence of runtime proof is inconclusive."
        elif completed_sms and synthetic_delivered and not (sms_access or marker):
            status = "CONTRADICTED"
            strength = 0.25
            explanation = "Synthetic SMS was delivered, but no package-associated SMS access or marker correlation was observed."
        elif static_supported and (synthetic_delivered or sms_access or marker):
            status = "SUPPORTED"
            strength = 0.75 if (sms_access or marker) else 0.55
            explanation = (
                "OTP hypothesis is supported by static capability and runtime signals, but generic log matching without verified instrumentation does not meet confirmation criteria."
                if not (has_instrumented_delivery and has_trusted_correlation)
                else "OTP hypothesis remains supported by static evidence and partial runtime evidence, but confirmation requirements are incomplete."
            )
        elif static_supported:
            status = "SUPPORTED"
            strength = 0.45
            explanation = "OTP hypothesis is statically supported, but runtime confirmation evidence is absent."
        else:
            status = _downgrade_unconfirmed(hypothesis, has_static_support=static_supported)
            strength = 0.15
            explanation = "OTP hypothesis lacks deterministic static and runtime support."

        return _verification(
            hypothesis,
            findings,
            normalized_evidence,
            status=status,
            strength=strength,
            observed=observed,
            missing=missing,
            explanation=explanation,
            confirmation_allowed=confirmation_allowed,
            static_tokens=["READ_SMS", "RECEIVE_SMS", "sms_receiver", "SmsManager"],
            runtime_types=["synthetic_sms_delivered", "sms_access", "synthetic_marker_correlation"],
            experiment_types=["SYNTHETIC_SMS", "LOGCAT_CAPTURE"],
        )

    def _verify_data_exfiltration(
        self,
        hypothesis: dict[str, Any],
        findings: dict[str, Any],
        normalized_evidence: list[Any],
    ) -> HypothesisVerification:
        runtime = _runtime_index(findings)
        experiment = _experiment_index(findings)
        marker_items = runtime["by_type"].get("synthetic_marker_correlation", [])
        network_items = runtime["by_type"].get("network_destination", []) + runtime["by_type"].get("dns_destination", [])
        marker_then_network = _marker_precedes_network(marker_items, network_items)
        static_supported = _has_static_network_signal(findings)
        failed = _has_failed_experiment(experiment, {"NETWORK_OBSERVATION", "SYNTHETIC_SMS"})
        completed_network = _has_completed_experiment(experiment, {"NETWORK_OBSERVATION"})

        has_payload_correlation = any(
            _trust_str(ev) == "PAYLOAD_CORRELATED"
            or ev.get("metadata", {}).get("payload_correlated") is True
            for ev in (marker_items + network_items)
        )

        observed = []
        missing = []
        if static_supported:
            observed.append("static_network_or_internet_signal")
        if marker_items:
            observed.append("synthetic_marker_correlation")
        else:
            missing.append("synthetic_marker_correlation")
        if network_items:
            observed.append("network_destination")
        else:
            missing.append("network_destination")

        confirmation_allowed = bool(
            marker_items
            and network_items
            and marker_then_network
            and has_payload_correlation
        )

        if confirmation_allowed:
            status = "CONFIRMED"
            strength = 0.95
            explanation = "Data exfiltration confirmed by verified payload-level correlation between synthetic marker and outbound transmission."
        elif failed:
            status = "INCONCLUSIVE"
            strength = 0.35 if static_supported else 0.1
            explanation = "Relevant runtime experiment failed or timed out, so exfiltration cannot be disproved."
        elif completed_network and marker_items and not network_items:
            status = "CONTRADICTED"
            strength = 0.3
            explanation = "Synthetic marker was observed, but completed network observation produced no outbound destination evidence."
        elif marker_items and network_items and marker_then_network:
            status = "SUPPORTED"
            strength = 0.60
            explanation = "Synthetic marker was observed in logcat, followed temporally by network activity, but payload content correlation was not verified (temporal correlation only; capped at SUPPORTED)."
        elif static_supported or marker_items or network_items:
            status = "SUPPORTED"
            strength = 0.50
            explanation = "Data exfiltration hypothesis has partial support, but deterministic confirmation requirements are incomplete."
        else:
            status = _downgrade_unconfirmed(hypothesis)
            strength = 0.15
            explanation = "Data exfiltration hypothesis lacks deterministic static or runtime support."

        return _verification(
            hypothesis,
            findings,
            normalized_evidence,
            status=status,
            strength=strength,
            observed=observed,
            missing=missing,
            explanation=explanation,
            confirmation_allowed=confirmation_allowed,
            static_tokens=["INTERNET", "network", "domain", "url", "ip"],
            runtime_types=["synthetic_marker_correlation", "network_destination", "dns_destination"],
            experiment_types=["NETWORK_OBSERVATION", "SYNTHETIC_SMS"],
        )

    def _verify_accessibility(
        self,
        hypothesis: dict[str, Any],
        findings: dict[str, Any],
        normalized_evidence: list[Any],
    ) -> HypothesisVerification:
        runtime = _runtime_index(findings)
        experiment = _experiment_index(findings)
        static_supported = _has_static_accessibility_signal(findings)
        acc_items = runtime["by_type"].get("accessibility_behavior", [])
        runtime_supported = bool(acc_items)
        failed = _has_failed_experiment(experiment, {"ACCESSIBILITY_OBSERVATION", "LOGCAT_CAPTURE"})
        completed_accessibility = _has_completed_experiment(experiment, {"ACCESSIBILITY_OBSERVATION"})

        has_system_binding = any(
            str(ev.get("trust_level")) in {"SYSTEM_OBSERVED", "INSTRUMENTED"}
            or "dumpsys" in str(ev.get("metadata", {}))
            for ev in acc_items
        )

        observed = []
        missing = []
        if static_supported:
            observed.append("static_accessibility_signal")
        else:
            missing.append("static_accessibility_signal")
        if runtime_supported:
            observed.append("accessibility_behavior")
        else:
            missing.append("accessibility_behavior")

        confirmation_allowed = static_supported and runtime_supported and has_system_binding

        if confirmation_allowed:
            status = "CONFIRMED"
            strength = 0.95
            explanation = "Accessibility abuse confirmed by static accessibility capability and verified system-level active service binding."
        elif failed:
            status = "INCONCLUSIVE"
            strength = 0.35 if static_supported else 0.1
            explanation = "Accessibility runtime experiment failed or timed out, so the hypothesis remains inconclusive."
        elif completed_accessibility and static_supported and not runtime_supported:
            status = "CONTRADICTED"
            strength = 0.3
            explanation = "Accessibility observation completed, but no accessibility runtime behavior was observed."
        elif static_supported and runtime_supported:
            status = "SUPPORTED"
            strength = 0.70
            explanation = "Accessibility behavior signals were observed in application logs, but active service binding was not confirmed by system instrumentation."
        elif static_supported or runtime_supported:
            status = "SUPPORTED"
            strength = 0.50
            explanation = "Accessibility hypothesis has partial deterministic support but lacks complete confirmation evidence."
        else:
            status = _downgrade_unconfirmed(hypothesis)
            strength = 0.15
            explanation = "Accessibility hypothesis lacks deterministic static and runtime support."

        return _verification(
            hypothesis,
            findings,
            normalized_evidence,
            status=status,
            strength=strength,
            observed=observed,
            missing=missing,
            explanation=explanation,
            confirmation_allowed=confirmation_allowed,
            static_tokens=["accessibility_service", "AccessibilityService", "accessibility_api"],
            runtime_types=["accessibility_behavior"],
            experiment_types=["ACCESSIBILITY_OBSERVATION", "LOGCAT_CAPTURE"],
        )

    def _verify_general(
        self,
        hypothesis: dict[str, Any],
        findings: dict[str, Any],
        normalized_evidence: list[Any],
    ) -> HypothesisVerification:
        runtime = _runtime_index(findings)
        experiment = _experiment_index(findings)
        failed = any(
            status in TERMINAL_FAILURE_STATUSES
            for statuses in experiment["statuses_by_type"].values()
            for status in statuses
        )
        if failed:
            status = "INCONCLUSIVE"
            strength = 0.25
            explanation = "A runtime experiment failed or timed out; no deterministic conclusion is drawn for this hypothesis."
        elif hypothesis.get("status") == "CONFIRMED":
            status = "SUPPORTED"
            strength = 0.45
            explanation = "No category-specific deterministic confirmation rule exists, so AI self-confirmation is reduced to supported."
        else:
            status = str(hypothesis.get("status", "PROPOSED"))
            strength = 0.35 if runtime["items"] else 0.2
            explanation = "No category-specific deterministic verifier is available; original hypothesis state is retained unless it claimed confirmation."
        return _verification(
            hypothesis,
            findings,
            normalized_evidence,
            status=status,
            strength=strength,
            observed=[],
            missing=[],
            explanation=explanation,
            confirmation_allowed=False,
            static_tokens=[],
            runtime_types=[],
            experiment_types=[],
        )


def apply_verifications_to_hypotheses(
    hypotheses: list[dict[str, Any]],
    verifications: list[dict[str, Any]],
    feedback_updates: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    by_id = {item["hypothesis_id"]: item for item in verifications}
    feedback_updates = feedback_updates or {}
    updated: list[dict[str, Any]] = []
    for hypothesis in hypotheses:
        item = dict(hypothesis)
        verification = by_id.get(str(item.get("hypothesis_id")))
        if verification:
            item["status"] = verification["verified_status"]
            item["evidence_strength"] = verification["evidence_strength"]
            item["verification_summary"] = verification["deterministic_explanation"]
            item["runtime_evidence_ids"] = verification["runtime_evidence_ids"]
            if verification["missing_signals"]:
                merged_missing = [*item.get("missing_evidence", []), *verification["missing_signals"]]
                item["missing_evidence"] = _unique_strings(merged_missing, 12)
        feedback = feedback_updates.get(str(item.get("hypothesis_id")))
        if feedback:
            for key in ("reasoning_summary", "recommended_next_steps", "limitations"):
                if key in feedback:
                    item[key] = feedback[key]
            if feedback.get("missing_evidence"):
                item["missing_evidence"] = _unique_strings(
                    [*item.get("missing_evidence", []), *feedback["missing_evidence"]],
                    12,
                )
        updated.append(item)
    return updated


def _verification(
    hypothesis: dict[str, Any],
    findings: dict[str, Any],
    normalized_evidence: list[Any],
    *,
    status: str,
    strength: float,
    observed: list[str],
    missing: list[str],
    explanation: str,
    confirmation_allowed: bool,
    static_tokens: list[str],
    runtime_types: list[str],
    experiment_types: list[str],
) -> HypothesisVerification:
    return HypothesisVerification(
        hypothesis_id=str(hypothesis.get("hypothesis_id", "")),
        category=str(hypothesis.get("category", "")),
        original_status=str(hypothesis.get("status", "PROPOSED")),
        verified_status=status,
        evidence_strength=max(0.0, min(1.0, strength)),
        ai_confidence=max(0.0, min(1.0, float(hypothesis.get("confidence", 0.0) or 0.0))),
        static_evidence_ids=_matching_static_evidence_ids(normalized_evidence, static_tokens),
        runtime_evidence_ids=_runtime_ids(findings, runtime_types),
        experiment_result_ids=_experiment_ids(findings, experiment_types),
        observed_signals=_unique_strings(observed, 20),
        missing_signals=_unique_strings(missing, 20),
        deterministic_explanation=explanation,
        confirmation_allowed=confirmation_allowed,
    )


def _otp_static_signals(findings: dict[str, Any]) -> list[str]:
    extraction = findings.get("extraction") if isinstance(findings.get("extraction"), dict) else findings
    permissions = set(extraction.get("permissions", {}).get("requested", []))
    components = extraction.get("components", {})
    signals = extraction.get("code_signals", {})
    observed = []
    if "android.permission.READ_SMS" in permissions:
        observed.append("READ_SMS")
    if "android.permission.RECEIVE_SMS" in permissions:
        observed.append("RECEIVE_SMS")
    if components.get("sms_receiver"):
        observed.append("sms_receiver")
    if signals.get("sms_api", {}).get("detected"):
        observed.append("SmsManager")
    return observed


def _has_static_network_signal(findings: dict[str, Any]) -> bool:
    extraction = findings.get("extraction") if isinstance(findings.get("extraction"), dict) else findings
    permissions = set(extraction.get("permissions", {}).get("requested", []))
    network = extraction.get("network_indicators", {})
    urls = extraction.get("urls", [])
    return "android.permission.INTERNET" in permissions or bool(urls) or any(network.get(key) for key in ("domains", "ips", "urls"))


def _has_static_accessibility_signal(findings: dict[str, Any]) -> bool:
    extraction = findings.get("extraction") if isinstance(findings.get("extraction"), dict) else findings
    components = extraction.get("components", {})
    signals = extraction.get("code_signals", {})
    return bool(components.get("accessibility_service") or signals.get("accessibility_api", {}).get("detected"))


def _runtime_index(findings: dict[str, Any]) -> dict[str, Any]:
    items = [item for item in findings.get("runtime_evidence", []) if isinstance(item, dict)]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        by_type.setdefault(str(item.get("evidence_type")), []).append(item)
    return {"items": items, "types": set(by_type), "by_type": by_type}


def _experiment_index(findings: dict[str, Any]) -> dict[str, Any]:
    raw_items = findings.get("experiment_results") or findings.get("dynamic_experiment_results") or []
    items = [item for item in raw_items if isinstance(item, dict)]
    statuses_by_type: dict[str, list[str]] = {}
    for item in items:
        statuses_by_type.setdefault(str(item.get("experiment_type")), []).append(str(item.get("status")))
    return {"items": items, "statuses_by_type": statuses_by_type}


def _has_failed_experiment(index: dict[str, Any], experiment_types: set[str]) -> bool:
    return any(
        status in TERMINAL_FAILURE_STATUSES
        for experiment_type in experiment_types
        for status in index["statuses_by_type"].get(experiment_type, [])
    )


def _has_completed_experiment(index: dict[str, Any], experiment_types: set[str]) -> bool:
    return any(
        status == "COMPLETED"
        for experiment_type in experiment_types
        for status in index["statuses_by_type"].get(experiment_type, [])
    )


def _marker_precedes_network(marker_items: list[dict[str, Any]], network_items: list[dict[str, Any]]) -> bool:
    if not marker_items or not network_items:
        return False
    earliest_marker = min(int(item.get("timestamp_ms", 0) or 0) for item in marker_items)
    return any(int(item.get("timestamp_ms", 0) or 0) >= earliest_marker for item in network_items)


def _matching_static_evidence_ids(normalized_evidence: list[Any], tokens: list[str]) -> list[str]:
    if not tokens:
        return []
    ids: list[str] = []
    lowered = [token.lower() for token in tokens]
    for item in normalized_evidence:
        payload = item.model_dump(mode="json") if hasattr(item, "model_dump") else item
        text = " ".join(str(payload.get(key, "")) for key in ("evidence_type", "source", "title", "value"))
        text = f"{text} {payload.get('metadata', {})}".lower()
        if any(token in text for token in lowered):
            ids.append(str(payload.get("evidence_id")))
    return _unique_strings(ids, 30)


def _runtime_ids(findings: dict[str, Any], runtime_types: list[str]) -> list[str]:
    allowed = set(runtime_types)
    return _unique_strings(
        [
            str(item.get("evidence_id"))
            for item in findings.get("runtime_evidence", [])
            if isinstance(item, dict) and str(item.get("evidence_type")) in allowed
        ],
        30,
    )


def _experiment_ids(findings: dict[str, Any], experiment_types: list[str]) -> list[str]:
    allowed = set(experiment_types)
    return _unique_strings(
        [
            str(item.get("experiment_id"))
            for item in findings.get("experiment_results", [])
            if isinstance(item, dict) and str(item.get("experiment_type")) in allowed
        ],
        30,
    )


def _downgrade_unconfirmed(hypothesis: dict[str, Any], has_static_support: bool = True) -> str:
    status = str(hypothesis.get("status", "PROPOSED"))
    if not has_static_support:
        return "PROPOSED"
    if status == "CONFIRMED":
        return "SUPPORTED"
    if status in {"SUPPORTED", "CONTRADICTED", "INCONCLUSIVE"}:
        return status
    return "PROPOSED"


def _unique_strings(values: list[str], limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text and text not in seen:
            result.append(text)
            seen.add(text)
        if len(result) >= limit:
            break
    return result
