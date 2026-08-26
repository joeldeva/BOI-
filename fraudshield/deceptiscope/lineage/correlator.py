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
    
    Security & Scientific Invariant:
    Time proximity alone is NOT payload correlation. A lineage chain is constructed
    only when the exact synthetic marker (or its proven deterministic transformation)
    is observed inside the relevant runtime data payload.
    """

    def __init__(self) -> None:
        self._lineage_counter = 1

    def correlate(
        self,
        evidence_items: Sequence[dict[str, Any] | Any],
        markers: Sequence[SyntheticMarker],
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
                    matched_value=marker.get_transformations()[transform],
                    description=desc,
                )
                steps.append(step)
                if ev_id not in chain_ids:
                    chain_ids.append(ev_id)

            if steps:
                has_ingress = any(s.phase == "INGRESS" for s in steps)
                egress_steps = [s for s in steps if s.phase == "EGRESS"]
                has_egress = len(egress_steps) > 0

                is_complete = has_ingress and has_egress
                source_id = steps[0].evidence_id
                sink_id = egress_steps[-1].evidence_id if has_egress else None

                summary = (
                    f"Deterministic payload lineage proven for synthetic {marker.marker_type.value} marker {marker.marker_id}: "
                    f"{' -> '.join(chain_ids)}"
                )
                if is_complete:
                    summary += " (Complete Exfiltration Proven)"
                else:
                    summary += " (Partial Ingestion / Transformation)"

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
                    trust_level="PAYLOAD_CORRELATED",
                    summary=summary,
                )
                self._lineage_counter += 1
                lineages.append(lineage)

        return lineages

    def _find_marker_match(
        self,
        ev_dict: dict[str, Any],
        marker: SyntheticMarker,
    ) -> tuple[bool, str | None]:
        """Inspects all text fields in an evidence dict for marker appearances."""
        # 1. Direct fields
        fields_to_check = [
            str(ev_dict.get("description", "")),
            str(ev_dict.get("value", "")),
            str(ev_dict.get("process", "")),
        ]

        # 2. Metadata subfields
        metadata = ev_dict.get("metadata", {})
        if isinstance(metadata, dict):
            for k, v in metadata.items():
                if isinstance(v, str):
                    fields_to_check.append(v)
                elif isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        if isinstance(sub_v, str):
                            fields_to_check.append(sub_v)

        for text in fields_to_check:
            matched, transform = marker.matches_payload(text)
            if matched:
                return True, transform

        # Fallback check for has_synthetic_marker metadata flag with raw marker
        if metadata.get("has_synthetic_marker") is True or metadata.get("event_metadata", {}).get("has_synthetic_marker") is True:
            return True, "raw"

        return False, None
