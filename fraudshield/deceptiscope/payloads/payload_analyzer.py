from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from fraudshield.deceptiscope.investigation import EvidenceItem
from fraudshield.deceptiscope.payloads.payload_models import (
    PayloadAnalysisStatus,
    RecoveredPayload,
)
from fraudshield.deceptiscope.reverse import MethodLevelAnalyzer


logger = logging.getLogger(__name__)


class PayloadAnalyzer:
    """
    Performs safe recursive static reverse engineering on recovered DEX/JAR payloads.
    
    Security & Architecture Rules:
    - Never executes or installs the recovered payload.
    - Runs Smali/bytecode reverse engineering, string extraction, and behavioral signature matching.
    - Emits normalized EvidenceItems with phase="PAYLOAD".
    """

    def __init__(self, method_analyzer: MethodLevelAnalyzer | None = None) -> None:
        self.method_analyzer = method_analyzer or MethodLevelAnalyzer()

    def analyze_payload(
        self,
        payload: RecoveredPayload,
        raw_bytes: bytes,
    ) -> list[EvidenceItem]:
        """Runs static reverse engineering on the recovered payload bytes."""
        if payload.analysis_status != PayloadAnalysisStatus.ANALYZED or not raw_bytes:
            return []

        evidence_items: list[EvidenceItem] = []
        capabilities: set[str] = set()

        # Write to temporary file for static disassembly analysis
        tmp = tempfile.NamedTemporaryFile(suffix=".dex", delete=False)
        try:
            tmp.write(raw_bytes)
            tmp.flush()
            tmp.close()
            tmp_path = Path(tmp.name)

            # 1. Run MethodLevelAnalyzer on recovered DEX
            analysis = self.method_analyzer.analyze(tmp_path, app_package=None)
            matches = analysis.get("matches", [])
            payload.method_level_evidence = matches

            for index, mth in enumerate(matches, start=1):
                # Convert to phase="PAYLOAD" EvidenceItem
                sig_id = str(mth.get("signature_id", f"SIG-{index}"))
                title = str(mth.get("title", "Payload Method Finding"))
                cat = str(mth.get("category", "RECOVERED_PAYLOAD"))
                cls_name = mth.get("class_name")
                mth_name = mth.get("method_name")
                call_site = mth.get("call_site")

                ev_item = EvidenceItem(
                    evidence_id=f"E{index:03d}",
                    evidence_type="payload_method_behavior",
                    source="recovered-payload",
                    title=f"[{sig_id}] {title} (in {payload.payload_id})",
                    value=f"{cls_name}->{mth_name}() | {call_site}",
                    confidence=0.95,
                    phase="PAYLOAD",
                    trust_level="STATIC_MATCH",
                    source_artifact=payload.payload_id,
                    class_name=cls_name,
                    method_name=mth_name,
                    call_site=call_site,
                    code_context=mth.get("code_context"),
                    code_ownership=mth.get("code_ownership", "APPLICATION_CODE"),
                    metadata={
                        "signature_id": sig_id,
                        "category": cat,
                        "payload_id": payload.payload_id,
                        "payload_sha256": payload.sha256,
                        "parent_sample_sha256": payload.parent_sample_sha256,
                        "loader": payload.loader,
                    },
                )
                evidence_items.append(ev_item)

                # Track high-level capability tags
                if "SMS" in cat:
                    capabilities.add("SMS_INTERCEPTION")
                elif "ACCESSIBILITY" in cat:
                    capabilities.add("ACCESSIBILITY_AUTOMATION")
                elif "NETWORKING" in cat:
                    capabilities.add("C2_COMMUNICATION")
                elif "DYNAMIC_CODE" in cat:
                    capabilities.add("SECONDARY_LOADER")
                elif "OVERLAY" in cat:
                    capabilities.add("UI_OVERLAY_HIJACKING")

            payload.extracted_capabilities = sorted(capabilities)
        except Exception as exc:
            logger.warning("Recursive static analysis of %s failed: %s", payload.payload_id, exc)
            payload.analysis_status = PayloadAnalysisStatus.FAILED
            payload.metadata["analysis_error"] = str(exc)
        finally:
            Path(tmp.name).unlink(missing_ok=True)

        return evidence_items
