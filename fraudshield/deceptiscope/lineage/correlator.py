from __future__ import annotations

import logging
from typing import Any, Sequence
from pydantic import BaseModel, ConfigDict, Field

from fraudshield.deceptiscope.lineage.markers import MarkerType, SyntheticMarker


logger = logging.getLogger(__name__)

INGRESS_INDICATORS = {
    "createfrompdu",
    "onreceive",
    "onnotificationposted",
    "gettext",
    "synthetic_sms_delivered",
    "sms_access",
}

EGRESS_INDICATORS = {
    "sendtextmessage",
    "sendmultiparttextmessage",
    "newcall",
    "openconnection",
    "connect",
    "http_request_observed",
    "socket_connect_observed",
    "network_destination",
}


class LineageStep(BaseModel):
    """A single deterministic observation step in a payload's data lineage."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(ge=0)
    evidence_id: str
    phase: str  # INGRESS, TRANSFORMATION, INTERNAL_STATE, EGRESS
    api: str
    transform_type: str  # raw, base64, hex, url_encoded, etc.
    matched_value: str
    description: str


class PayloadLineage(BaseModel):
    """End-to-end deterministic data lineage showing propagation of a synthetic marker."""

    model_config = ConfigDict(extra="forbid")

    lineage_id: str = Field(pattern=r"^P\d{3}$")
    marker_id: str
    marker_type: MarkerType
    marker_value: str
    evidence_chain: list[str] = Field(default_factory=list)
    steps: list[LineageStep] = Field(default_factory=list)
    source_evidence_id: str
    sink_evidence_id: str | None = None
    is_complete_exfiltration: bool = False
    trust_level: str = "PAYLOAD_CORRELATED"
    summary: str


class DataLineageCorrelator:
    """
    Deterministic lineage engine tracking propagation of synthetic test markers
    through malware execution paths.
    
    Security & Scientific Invariants:
    1. Time proximity alone is NOT payload correlation.
    2. A lineage chain is constructed only when the exact active synthetic marker
       (or its proven deterministic transformation) is observed inside the relevant runtime data payload.
    3. Egress exfiltration confirmation requires that the marker appears inside outbound data/body
       from trusted instrumentation, attributed to the target application package.
    4. URL-only coincidence, host-only coincidence, or unassociated logcat lines NEVER produce complete exfiltration.
    """

    def __init__(self) -> None:
        self._lineage_counter = 1

    def correlate(
        self,
        evidence_items: Sequence[dict[str, Any] | Any],
        markers: Sequence[SyntheticMarker],
        *,
        target_package: str | None = None,
    ) -> list[PayloadLineage]:
        """Correlates runtime evidence items against active synthetic markers."""
        if not evidence_items or not markers:
            return []

        lineages: list[PayloadLineage] = []

        for marker in markers:
            steps: list[LineageStep] = []
            chain_ids: list[str] = []

            for item in evidence_items:
                ev_dict = item if isinstance(item, dict) else (
                    item.model_dump(mode="json") if hasattr(item, "model_dump") else item.__dict__
                )
                ev_id = str(ev_dict.get("evidence_id", ""))
                if not ev_id:
                    continue

                # Enforce target package attribution if target_package is specified
                if target_package:
                    proc = str(ev_dict.get("process", ""))
                    ev_target_pkg = str(ev_dict.get("metadata", {}).get("target_package", ""))
                    if proc and target_package not in proc and ev_target_pkg and target_package not in ev_target_pkg:
                        continue

                matched, transform = self._find_marker_match(ev_dict, marker)
                if not matched or not transform:
                    continue

                # Determine phase
                api_str = str(ev_dict.get("metadata", {}).get("api", "") or ev_dict.get("api", "") or "").lower()
                ev_type = str(ev_dict.get("evidence_type", "")).lower()
                desc = str(ev_dict.get("description", ""))

                phase = "INTERNAL_STATE"
                if any(ind in api_str or ind in ev_type for ind in INGRESS_INDICATORS):
                    phase = "INGRESS"
                elif any(ind in api_str or ind in ev_type for ind in EGRESS_INDICATORS):
                    phase = "EGRESS"
                elif transform in ("base64", "hex", "url_encoded") or "transform" in desc.lower():
                    phase = "TRANSFORMATION"

                step = LineageStep(
                    step_index=len(steps) + 1,
                    evidence_id=ev_id,
                    phase=phase,
                    api=api_str or ev_type,
                    transform_type=transform,
                    matched_value=marker.get_transformations().get(transform, marker.value),
                    description=desc,
                )
                steps.append(step)
                if ev_id not in chain_ids:
                    chain_ids.append(ev_id)

            if steps:
                has_ingress = any(s.phase == "INGRESS" for s in steps)
                egress_steps = [s for s in steps if s.phase == "EGRESS"]
                
                # Exfiltration is proven complete ONLY if marker was found in outbound request body / data payload
                # from trusted instrumentation (not URL coincidence or unverified logcat).
                has_verified_body_egress = any(
                    self._is_verified_body_egress(step, evidence_items, marker)
                    for step in egress_steps
                )
                is_complete = has_ingress and has_verified_body_egress

                source_id = steps[0].evidence_id
                sink_id = egress_steps[-1].evidence_id if egress_steps else None

                summary = (
                    f"Deterministic payload lineage proven for synthetic {marker.marker_type.value} marker {marker.marker_id}: "
                    f"{' -> '.join(chain_ids)}"
                )
                if is_complete:
                    summary += " (Complete Outbound Body Exfiltration Proven)"
                else:
                    summary += " (Partial Ingestion / Transformation / Log Observation)"

                lineage = PayloadLineage(
                    lineage_id=f"P{self._lineage_counter:03d}",
                    marker_id=marker.marker_id,
                    marker_type=marker.marker_type,
                    marker_value=marker.value,
                    evidence_chain=chain_ids,
                    steps=steps,
                    source_evidence_id=source_id,
                    sink_evidence_id=sink_id,
                    is_complete_exfiltration=is_complete,
                    trust_level="PAYLOAD_CORRELATED" if is_complete else "INSTRUMENTED",
                    summary=summary,
                )
                self._lineage_counter += 1
                lineages.append(lineage)

        return lineages

    def _is_verified_body_egress(
        self,
        step: LineageStep,
        evidence_items: Sequence[Any],
        marker: SyntheticMarker,
    ) -> bool:
        """
        Verifies that an egress step corresponds to actual outbound request body/payload containment.
        
        Strict Trust Rules:
        - URL query parameter is NOT request body proof.
        - Destination/hostname/socket is NOT request body proof.
        - Description text is NOT request body proof.
        - LOG_OBSERVED evidence can NEVER produce complete exfiltration.
        - Boolean 'has_synthetic_marker' is NEVER trusted as identity proof.
        - ONLY explicit captured outbound body/payload fields from trusted instrumentation qualify.
        """
        # Explicitly allowed body/payload fields
        allowed_body_fields = (
            "body",
            "body_preview_redacted",
            "payload",
            "request_body",
            "body_bytes_decoded",
        )

        for item in evidence_items:
            ev = item if isinstance(item, dict) else (
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item.__dict__
            )
            if str(ev.get("evidence_id")) == step.evidence_id:
                trust = str(ev.get("trust_level", "")).upper()
                # Logcat or unverified observations cannot produce verified complete exfiltration
                if trust in {"LOG_OBSERVED", "INFERRED", "UNVERIFIED"}:
                    return False

                meta = ev.get("metadata", {})
                if not isinstance(meta, dict):
                    continue

                # Check ONLY explicit body/payload fields
                for k in allowed_body_fields:
                    val = meta.get(k)
                    if isinstance(val, str) and val:
                        matched, _ = marker.matches_payload(val)
                        if matched:
                            return True
                    elif isinstance(val, bytes) and val:
                        try:
                            decoded = val.decode("utf-8", errors="ignore")
                            matched, _ = marker.matches_payload(decoded)
                            if matched:
                                return True
                        except Exception:
                            pass

        return False

    def _find_marker_match(
        self,
        ev_dict: dict[str, Any],
        marker: SyntheticMarker,
    ) -> tuple[bool, str | None]:
        """Inspects text fields in an evidence dict for exact active marker (or valid transform) appearances."""
        # 1. Direct fields
        fields_to_check: list[str] = []
        for field in ("description", "value"):
            v = ev_dict.get(field)
            if isinstance(v, str) and v:
                fields_to_check.append(v)

        # 2. Metadata subfields
        metadata = ev_dict.get("metadata", {})
        if isinstance(metadata, dict):
            for k, v in metadata.items():
                if isinstance(v, str) and v:
                    fields_to_check.append(v)
                elif isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        if isinstance(sub_v, str) and sub_v:
                            fields_to_check.append(sub_v)

        for text in fields_to_check:
            matched, transform = marker.matches_payload(text)
            if matched:
                return True, transform

        return False, None
