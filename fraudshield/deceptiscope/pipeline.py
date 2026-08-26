from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from fraudshield.core.config import Settings
from fraudshield.core.errors import FraudShieldError
from fraudshield.core.repository import AnalysisRepository, IndicatorRepository
from fraudshield.deceptiscope.dynamic import DynamicLiteAnalyzer
from fraudshield.deceptiscope.engines import MultiEngineAnalyzer, malware_assessment
from fraudshield.deceptiscope.extractor import StaticAPKExtractor
from fraudshield.deceptiscope.fraud_delta import FraudDeltaCalculator
from fraudshield.deceptiscope.frauddna import CampaignCorrelator, FraudDNAExtractor
from fraudshield.deceptiscope.impact import derive_banking_impact
from fraudshield.deceptiscope.impersonation import (
    BrandImpersonationAnalyzer,
    FirebaseExtractor,
)
from fraudshield.deceptiscope.investigation import AIInvestigatorClient
from fraudshield.deceptiscope.lineage import DataLineageCorrelator, SyntheticMarkerManager
from fraudshield.deceptiscope.mitre import map_mitre_mobile
from fraudshield.deceptiscope.narrative import LLMNarrativeClient
from fraudshield.deceptiscope.payloads import (
    PayloadAnalysisStatus,
    PayloadAnalyzer,
    PayloadRecoveryManager,
    RecoveredPayload,
)
from fraudshield.deceptiscope.reverse import MethodLevelAnalyzer
from fraudshield.deceptiscope.scoring import RiskScorer


logger = logging.getLogger(__name__)


class APKAnalysisPipeline:
    def __init__(
        self,
        settings: Settings,
        analyses: AnalysisRepository,
        indicators: IndicatorRepository,
    ) -> None:
        self.settings = settings
        self.analyses = analyses
        self.indicators = indicators
        self.delta = FraudDeltaCalculator(settings.baseline_path)
        self.scorer = RiskScorer()
        self.narratives = LLMNarrativeClient(settings)
        self.ai_investigator = AIInvestigatorClient(settings)
        self.dynamic = DynamicLiteAnalyzer(settings)
        self.engines = MultiEngineAnalyzer(settings)
        self.reverse_analyzer = MethodLevelAnalyzer()
        self.payload_recovery_manager = PayloadRecoveryManager()
        self.payload_analyzer = PayloadAnalyzer(self.reverse_analyzer)
        self.campaign_correlator = CampaignCorrelator()
        self.frauddna_extractor = FraudDNAExtractor()
        self.brand_analyzer = BrandImpersonationAnalyzer()
        self.firebase_extractor = FirebaseExtractor()

    def analyze_uploaded(
        self,
        *,
        path: Path,
        original_name: str,
        sha256: str,
        size_bytes: int,
        category: str,
        dynamic: bool = False,
    ) -> dict[str, Any]:
        record = self.analyses.create(
            file_name=original_name,
            sha256=sha256,
            size_bytes=size_bytes,
            category=category,
            data_origin="uploaded",
        )
        self.analyses.mark_running(record["id"])
        try:
            extraction = StaticAPKExtractor(path, self.settings, original_name=original_name).extract()
            package_name = extraction.get("app", {}).get("package_name")
            method_evidence = self.reverse_analyzer.analyze(path, app_package=package_name)
            extraction["method_level_evidence"] = method_evidence
            if "coverage" in extraction and isinstance(extraction["coverage"], dict):
                extraction["coverage"]["reverse_engineering"] = (method_evidence.get("status") == "completed")
            engine_analysis = self.engines.analyze(
                path,
                sha256=sha256,
                extraction=extraction,
            )
            fraud_delta = self.delta.calculate(extraction, category)
            risk = self.scorer.calculate(extraction, fraud_delta, engine_analysis=engine_analysis)
            assessment = malware_assessment(extraction, risk, engine_analysis)
            mitre = map_mitre_mobile(extraction)
            candidates = self._indicator_candidates(extraction, risk)

            preliminary_findings: dict[str, Any] = {
                "schema_version": "3.0",
                "analysis_id": record["id"],
                "extraction": extraction,
                "engine_analysis": engine_analysis,
                "risk": risk,
                "malware_assessment": assessment,
                "fraud_delta": fraud_delta,
                "mitre_attack": mitre,
                "indicator_candidates": candidates,
                "emitted_indicators": [],
                "runtime_evidence": [],
                "experiment_results": [],
                "decision_notice": (
                    "Analyst decision support only; no automated enforcement or account action is performed."
                ),
            }

            ai_status, evidence, hypotheses, experiment_plan, validation_errors, ai_warning = (
                self.ai_investigator.plan_investigation(preliminary_findings)
            )

            runtime_evidence: list[dict[str, Any]] = []
            experiment_results: list[dict[str, Any]] = []

            marker_manager = SyntheticMarkerManager()
            otp_marker = marker_manager.create_otp_marker()
            recovered_payloads_list: list[dict[str, Any]] = []

            if dynamic:
                package_name = extraction.get("app", {}).get("package_name", "unknown")
                dynamic_status = self.dynamic.status()
                if dynamic_status.get("enabled") and dynamic_status.get("adb_available") and dynamic_status.get("safe_target_shape"):
                    try:
                        dynamic_observations = self.dynamic.observe(
                            path,
                            package_name,
                            plan_items=experiment_plan if experiment_plan else None,
                            active_marker=otp_marker,
                        )
                        extraction["dynamic_observations"] = dynamic_observations
                        runtime_evidence = dynamic_observations.get("runtime_evidence", [])
                        experiment_results = dynamic_observations.get("experiment_results", [])
                        extraction["runtime_evidence"] = runtime_evidence
                        extraction["dynamic_experiment_results"] = experiment_results
                        extraction["coverage"]["dynamic"] = True

                        # Safely process any dynamic secondary DEX loading events
                        dcl_events = [ev for ev in runtime_evidence if ev.get("evidence_type") == "dynamic_code_load"]
                        for dcl_ev in dcl_events:
                            meta = dcl_ev.get("metadata", {})
                            ev_meta = meta.get("event_metadata", {}) if isinstance(meta.get("event_metadata"), dict) else meta
                            dex_p = ev_meta.get("dex_path") or ev_meta.get("source_path") or meta.get("dex_path") or meta.get("source_path")
                            loader_name = str(ev_meta.get("loader_type") or "DexClassLoader")
                            r_ev_id = str(dcl_ev.get("evidence_id") or "")

                            dex_bytes: bytes | None = None
                            retrieval_err: str | None = None
                            if dex_p:
                                ok, retrieved_b, err_msg = self.dynamic.retrieve_file_from_emulator(
                                    package_name,
                                    str(dex_p),
                                )
                                if ok and retrieved_b:
                                    dex_bytes = retrieved_b
                                else:
                                    retrieval_err = err_msg or "Failed to retrieve DEX from emulator"
                            elif "raw_bytes" in ev_meta and isinstance(ev_meta["raw_bytes"], bytes):
                                dex_bytes = ev_meta["raw_bytes"]

                            if dex_bytes:
                                temp_dex = None
                                try:
                                    with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as tf:
                                        tf.write(dex_bytes)
                                        temp_dex = Path(tf.name)

                                    p_obj, raw_b = self.payload_recovery_manager.recover_from_file_path(
                                        parent_sha256=sha256,
                                        file_path=temp_dex,
                                        loader=loader_name,
                                        runtime_evidence_id=r_ev_id,
                                    )
                                    if p_obj.analysis_status == PayloadAnalysisStatus.ANALYZED and raw_b:
                                        self.payload_analyzer.analyze_payload(p_obj, raw_b)
                                finally:
                                    if temp_dex and temp_dex.exists():
                                        try:
                                            temp_dex.unlink()
                                        except Exception:
                                            pass
                            else:
                                p_obj = RecoveredPayload(
                                    payload_id=f"PAYLOAD-{len(recovered_payloads_list) + 1:03d}",
                                    parent_sample_sha256=sha256,
                                    sha256="0" * 64,
                                    payload_type="DEX",
                                    size_bytes=0,
                                    source="FILE_RECOVERED" if dex_p else "MEMORY_DUMP",
                                    loader=loader_name,
                                    runtime_evidence_id=r_ev_id,
                                    analysis_status=PayloadAnalysisStatus.UNAVAILABLE,
                                    metadata={"reason": f"Dynamic loader observed; DEX bytes unavailable ({retrieval_err or 'memory capture not configured'})"},
                                )

                            recovered_payloads_list.append(p_obj.model_dump(mode="json"))

                        results_by_id = {res.get("experiment_id"): res for res in experiment_results}
                        for plan_item in experiment_plan:
                            exp_id = plan_item.get("experiment_id")
                            if exp_id in results_by_id:
                                plan_item["status"] = results_by_id[exp_id].get("status", "COMPLETED")
                    except Exception as exc:
                        logger.warning("Dynamic sandbox execution encountered an error: %s", exc)
                        extraction["coverage"]["dynamic"] = False
                        for plan_item in experiment_plan:
                            plan_item["status"] = "FAILED"
                            plan_item["unsupported_reason"] = f"Dynamic execution failed: {type(exc).__name__}"
                else:
                    extraction["coverage"]["dynamic"] = False
                    for plan_item in experiment_plan:
                        if plan_item.get("status") in {"PLANNED", "COMPLETED"}:
                            plan_item["status"] = "UNAVAILABLE"
                            plan_item["unsupported_reason"] = "Dynamic emulator sandbox is disabled or unavailable"
            else:
                extraction["coverage"]["dynamic"] = False
                for plan_item in experiment_plan:
                    if plan_item.get("status") == "PLANNED":
                        plan_item["status"] = "SKIPPED"
                        plan_item["unsupported_reason"] = "Dynamic analysis was not requested"

            extraction["recovered_payloads"] = recovered_payloads_list

            package_name_str = extraction.get("app", {}).get("package_name", "unknown")
            lineages = DataLineageCorrelator().correlate(
                runtime_evidence,
                marker_manager.all_markers(),
                target_package=package_name_str,
            )
            payload_lineage_dicts = [pl.model_dump(mode="json") for pl in lineages]

            # If complete exfiltration is proven, ensure a PAYLOAD_CORRELATED synthetic_marker_correlation item is present
            has_exfil = any(pl.is_complete_exfiltration for pl in lineages)
            if has_exfil:
                has_corr = any(
                    ev.get("evidence_type") == "synthetic_marker_correlation"
                    and str(ev.get("trust_level")) == "PAYLOAD_CORRELATED"
                    for ev in runtime_evidence
                )
                if not has_corr:
                    corr_ev = {
                        "evidence_id": f"R{len(runtime_evidence) + 1:03d}",
                        "timestamp_ms": 0,
                        "evidence_type": "synthetic_marker_correlation",
                        "source": "dynamic",
                        "trust_level": "PAYLOAD_CORRELATED",
                        "process": package_name_str,
                        "description": f"Verified synthetic marker correlation in outbound network body: {otp_marker.value}",
                        "confidence": 1.0,
                        "metadata": {
                            "marker": otp_marker.value,
                            "marker_id": otp_marker.marker_id,
                            "payload_correlated": True,
                            "target_package": package_name_str,
                        },
                    }
                    runtime_evidence.append(corr_ev)

            # Firebase Static Extraction
            firebase_infra = self.firebase_extractor.extract_from_findings(extraction, apk_path=path)

            # Banking-Brand Impersonation Analysis
            brand_impersonation = self.brand_analyzer.analyze(
                extraction=extraction,
                method_evidence=method_evidence,
            )

            # FraudDNA Fingerprinting & Campaign Correlation
            frauddna_fp = self.frauddna_extractor.extract({
                "extraction": extraction,
                "engine_analysis": engine_analysis,
                "recovered_payloads": recovered_payloads_list,
                "method_level_reverse": method_evidence,
                "firebase_infrastructure": firebase_infra.model_dump(mode="json"),
                "analysis_id": record["id"],
                "sha256": sha256,
            })
            campaign, related_samples = self.campaign_correlator.correlate(frauddna_fp)

            findings: dict[str, Any] = {
                "schema_version": "3.0",
                "analysis_id": record["id"],
                "extraction": extraction,
                "engine_analysis": engine_analysis,
                "risk": risk,
                "malware_assessment": assessment,
                "fraud_delta": fraud_delta,
                "mitre_attack": mitre,
                "indicator_candidates": candidates,
                "emitted_indicators": [],
                "runtime_evidence": runtime_evidence,
                "experiment_results": experiment_results,
                "recovered_payloads": recovered_payloads_list,
                "payload_lineage": payload_lineage_dicts,
                "brand_impersonation": brand_impersonation.model_dump(mode="json"),
                "firebase_infrastructure": firebase_infra.model_dump(mode="json"),
                "frauddna": frauddna_fp.model_dump(mode="json"),
                "related_samples": [r.model_dump(mode="json") for r in related_samples],
                "decision_notice": (
                    "Analyst decision support only; no automated enforcement or account action is performed."
                ),
            }
            if campaign:
                findings["campaign"] = campaign.model_dump(mode="json")

            ai_investigation = self.ai_investigator.verify_and_finalize(
                status=ai_status,
                evidence=evidence,
                hypotheses=hypotheses,
                experiment_plan=experiment_plan,
                findings=findings,
                validation_errors=validation_errors,
                warning=ai_warning,
            )
            findings["ai_investigation"] = ai_investigation

            # Stage 2 Deterministic Risk Scoring
            final_risk = self.scorer.calculate(
                extraction,
                fraud_delta,
                engine_analysis=engine_analysis,
                runtime_evidence=runtime_evidence,
                experiment_results=experiment_results,
                verifications=ai_investigation.get("hypothesis_verifications"),
            )
            findings["risk"] = final_risk

            final_assessment = malware_assessment(extraction, final_risk, engine_analysis)
            findings["malware_assessment"] = final_assessment

            findings["banking_impact"] = derive_banking_impact(findings)

            final_candidates = self._indicator_candidates(extraction, final_risk)
            findings["indicator_candidates"] = final_candidates
            emitted = self._emit_candidates(record["id"], final_candidates, final_risk)
            findings["emitted_indicators"] = emitted

            narrative = self.narratives.explain(findings)
            findings["narrative_metadata"] = {
                "source": narrative.source,
                "warning": narrative.warning,
                "llm_controls_score": False,
            }
            return self.analyses.complete(
                record["id"],
                result=findings,
                narrative=narrative.text,
                overall_score=final_risk["overall_score"],
                severity=final_risk["severity"],
                confidence=final_risk["confidence"],
                analysis_quality=extraction["analysis_quality"],
            )
        except FraudShieldError as exc:
            self.analyses.fail(record["id"], code=exc.code, message=exc.message)
            raise
        except Exception:
            logger.exception("APK analysis failed")
            self.analyses.fail(
                record["id"],
                code="analysis_failed",
                message="Static analysis did not complete; inspect server logs using the analysis ID.",
            )
            raise
        finally:
            if not self.settings.retain_uploads:
                path.unlink(missing_ok=True)

    @staticmethod
    def _indicator_candidates(extraction: dict[str, Any], risk: dict[str, Any]) -> list[dict[str, Any]]:
        if risk["overall_score"] < 50:
            return []
        severity = risk["severity"]
        confidence = max(0.5, risk["confidence"] - 0.1)
        candidates: list[dict[str, Any]] = []
        network = extraction.get("network_indicators", {})
        apk_sha256 = extraction.get("file", {}).get("sha256")
        if apk_sha256:
            candidates.append(
                {
                    "type": "apk_sha256",
                    "value": apk_sha256,
                    "severity": severity,
                    "confidence": risk["confidence"],
                }
            )
        for domain in network.get("domains", []):
            candidates.append({"type": "domain", "value": domain, "severity": severity, "confidence": confidence})
        for ip in network.get("ips", []):
            candidates.append({"type": "ip", "value": ip, "severity": severity, "confidence": confidence})
        certificate = extraction.get("certificate", {})
        if certificate.get("sha256"):
            candidates.append(
                {
                    "type": "certificate_sha256",
                    "value": certificate["sha256"],
                    "severity": severity,
                    "confidence": risk["confidence"],
                }
            )
        package = extraction.get("app", {}).get("package_name")
        if package and package != "unknown":
            candidates.append(
                {
                    "type": "package",
                    "value": package,
                    "severity": severity,
                    "confidence": risk["confidence"],
                }
            )
        dedup: dict[tuple[str, str], dict[str, Any]] = {}
        for item in candidates:
            dedup[(item["type"], item["value"])] = item
        return list(dedup.values())

    def _emit_candidates(
        self,
        analysis_id: str,
        candidates: list[dict[str, Any]],
        risk: dict[str, Any],
    ) -> list[dict[str, Any]]:
        emitted = []
        for candidate in candidates:
            emitted.append(
                self.indicators.upsert(
                    indicator_type=candidate["type"],
                    value=candidate["value"],
                    severity=candidate["severity"],
                    confidence=candidate["confidence"],
                    description="Observed in an APK scoring HIGH/CRITICAL; validate before enforcement.",
                    source_analysis_id=analysis_id,
                    metadata={"risk_model": risk["model_version"], "source": "deceptiscope-apk"},
                    context={"overall_score": risk["overall_score"]},
                )
            )
        return emitted
