from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fraudshield.deceptiscope.frauddna.models import (
    Campaign,
    FraudDNAFingerprint,
    RelatedSample,
)
from fraudshield.deceptiscope.frauddna.similarity import FraudDNASimilarityCalculator

if TYPE_CHECKING:
    from fraudshield.core.repository import FraudDNARepository


logger = logging.getLogger(__name__)


class CampaignCorrelator:
    """
    Deterministic campaign correlation engine.
    
    Hard Link Anchors (Required for campaign joining):
    - Same Firebase project ID
    - Same Signer Certificate Fingerprint
    - Same Recovered Payload SHA256
    - Very high DEX similarity (>= 85%)
    
    Safety Rule:
    Icon similarity or package similarity alone NEVER merges campaigns.
    """

    def __init__(
        self,
        calculator: FraudDNASimilarityCalculator | None = None,
        min_related_threshold: float = 0.25,
        repository: FraudDNARepository | None = None,
    ) -> None:
        self.calculator = calculator or FraudDNASimilarityCalculator()
        self.min_related_threshold = min_related_threshold
        self.repository = repository
        self._corpus: dict[str, FraudDNAFingerprint] = {}
        self._campaigns: dict[str, Campaign] = {}
        self._sample_to_campaign: dict[str, str] = {}
        self._next_campaign_index = 1

    def correlate(
        self,
        sample: FraudDNAFingerprint,
        analysis_id: str | None = None,
    ) -> tuple[Campaign | None, list[RelatedSample]]:
        """
        Correlates a newly analyzed sample against the known corpus,
        assigns deterministic campaign membership, and returns related samples.
        """
        if self.repository is not None:
            with self.repository.db.transaction() as conn:
                # 1. Persist sample into DB corpus
                self.repository.save_fingerprint(sample, analysis_id=analysis_id, connection=conn)

                # 2. Query all existing fingerprints
                corpus_samples = self.repository.list_fingerprints(
                    exclude_sha256=sample.apk_sha256,
                    connection=conn,
                )

                # 3. Compare with known corpus
                related_samples: list[RelatedSample] = []
                target_campaign_id: str | None = None

                for existing_fp in corpus_samples:
                    existing_sha = existing_fp.apk_sha256
                    sim = self.calculator.compare(sample, existing_fp)
                    if sim.overall_similarity >= self.min_related_threshold or sim.match_reasons:
                        existing_camp = self.repository.get_campaign_for_sample(existing_sha, connection=conn)
                        camp_id = existing_camp.campaign_id if existing_camp else None
                        related_samples.append(
                            RelatedSample(
                                sha256=existing_sha,
                                similarity=sim.overall_similarity,
                                reasons=sim.match_reasons,
                                campaign_id=camp_id,
                                app_label=existing_fp.app_label,
                                package_name=existing_fp.package_name,
                            )
                        )

                        # Hard Link Anchors required for campaign merging
                        is_hard_linked = (
                            sim.firebase_overlap
                            or sim.signer_match
                            or sim.payload_overlap
                            or (sim.dex_similarity is not None and sim.dex_similarity >= 0.85)
                        )

                        if is_hard_linked and camp_id and not target_campaign_id:
                            target_campaign_id = camp_id

                # Sort related samples by similarity descending
                related_samples.sort(key=lambda r: r.similarity, reverse=True)

                assigned_campaign: Campaign | None = None

                # Check if sample was already assigned a campaign in DB
                current_camp = self.repository.get_campaign_for_sample(sample.apk_sha256, connection=conn)
                if current_camp and not target_campaign_id:
                    target_campaign_id = current_camp.campaign_id

                if target_campaign_id:
                    assigned_campaign = self.repository.get_campaign(target_campaign_id, connection=conn)
                    if assigned_campaign:
                        if sample.apk_sha256 not in assigned_campaign.member_sha256s:
                            assigned_campaign.member_sha256s.append(sample.apk_sha256)
                        assigned_campaign.primary_signatures = sorted(
                            set(assigned_campaign.primary_signatures + sample.behavior_signatures)
                        )
                        assigned_campaign.shared_infrastructure = sorted(
                            set(assigned_campaign.shared_infrastructure + sample.domains + sample.urls)
                        )
                        assigned_campaign.shared_firebase_projects = sorted(
                            set(assigned_campaign.shared_firebase_projects + sample.firebase_project_ids)
                        )
                        assigned_campaign.shared_signer_fingerprints = sorted(
                            set(assigned_campaign.shared_signer_fingerprints + sample.signer_fingerprints)
                        )
                        self.repository.save_campaign(assigned_campaign, connection=conn)
                elif related_samples and any(r.similarity >= 0.45 for r in related_samples):
                    cid = self.repository.generate_next_campaign_id(conn)
                    members = [sample.apk_sha256]
                    for r in related_samples:
                        if r.similarity >= 0.45 and r.sha256 not in members:
                            members.append(r.sha256)

                    assigned_campaign = Campaign(
                        campaign_id=cid,
                        name=f"Banking Campaign {cid} ({sample.app_label or sample.package_name})",
                        member_sha256s=members,
                        primary_signatures=list(sample.behavior_signatures),
                        shared_infrastructure=list(sample.domains + sample.urls),
                        shared_firebase_projects=list(sample.firebase_project_ids),
                        shared_signer_fingerprints=list(sample.signer_fingerprints),
                    )
                    self.repository.save_campaign(assigned_campaign, connection=conn)

                if assigned_campaign:
                    for r in related_samples:
                        if r.sha256 in assigned_campaign.member_sha256s:
                            r.campaign_id = assigned_campaign.campaign_id

                return assigned_campaign, related_samples

        # In-memory fallback mode for isolated unit testing
        related_samples_mem: list[RelatedSample] = []
        target_campaign_id_mem: str | None = None

        for existing_sha, existing_fp in self._corpus.items():
            if existing_sha == sample.apk_sha256:
                continue

            sim = self.calculator.compare(sample, existing_fp)
            if sim.overall_similarity >= self.min_related_threshold or sim.match_reasons:
                camp_id = self._sample_to_campaign.get(existing_sha)
                related_samples_mem.append(
                    RelatedSample(
                        sha256=existing_sha,
                        similarity=sim.overall_similarity,
                        reasons=sim.match_reasons,
                        campaign_id=camp_id,
                        app_label=existing_fp.app_label,
                        package_name=existing_fp.package_name,
                    )
                )

                # Check for Hard Link Anchors to join campaign
                is_hard_linked = (
                    sim.firebase_overlap
                    or sim.signer_match
                    or sim.payload_overlap
                    or (sim.dex_similarity is not None and sim.dex_similarity >= 0.85)
                )

                if is_hard_linked and camp_id and not target_campaign_id_mem:
                    target_campaign_id_mem = camp_id

        # Sort related samples by similarity descending
        related_samples_mem.sort(key=lambda r: r.similarity, reverse=True)

        assigned_campaign_mem: Campaign | None = None

        if target_campaign_id_mem and target_campaign_id_mem in self._campaigns:
            assigned_campaign_mem = self._campaigns[target_campaign_id_mem]
            if sample.apk_sha256 not in assigned_campaign_mem.member_sha256s:
                assigned_campaign_mem.member_sha256s.append(sample.apk_sha256)
                assigned_campaign_mem.primary_signatures = sorted(
                    set(assigned_campaign_mem.primary_signatures + sample.behavior_signatures)
                )
                assigned_campaign_mem.shared_infrastructure = sorted(
                    set(assigned_campaign_mem.shared_infrastructure + sample.domains + sample.urls)
                )
                assigned_campaign_mem.shared_firebase_projects = sorted(
                    set(assigned_campaign_mem.shared_firebase_projects + sample.firebase_project_ids)
                )
                assigned_campaign_mem.shared_signer_fingerprints = sorted(
                    set(assigned_campaign_mem.shared_signer_fingerprints + sample.signer_fingerprints)
                )
            self._sample_to_campaign[sample.apk_sha256] = target_campaign_id_mem
        elif related_samples_mem and any(r.similarity >= 0.45 for r in related_samples_mem):
            cid = f"CAMP-{self._next_campaign_index:03d}"
            self._next_campaign_index += 1
            members = [sample.apk_sha256]
            for r in related_samples_mem:
                if r.similarity >= 0.45 and r.sha256 not in members:
                    members.append(r.sha256)
                    self._sample_to_campaign[r.sha256] = cid

            assigned_campaign_mem = Campaign(
                campaign_id=cid,
                name=f"Banking Campaign {cid} ({sample.app_label or sample.package_name})",
                member_sha256s=members,
                primary_signatures=list(sample.behavior_signatures),
                shared_infrastructure=list(sample.domains + sample.urls),
                shared_firebase_projects=list(sample.firebase_project_ids),
                shared_signer_fingerprints=list(sample.signer_fingerprints),
            )
            self._campaigns[cid] = assigned_campaign_mem
            self._sample_to_campaign[sample.apk_sha256] = cid

        # Register sample into corpus
        self._corpus[sample.apk_sha256] = sample

        # Update campaign_id references in returned related samples
        for r in related_samples_mem:
            if not r.campaign_id:
                r.campaign_id = self._sample_to_campaign.get(r.sha256)

        return assigned_campaign_mem, related_samples_mem

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        if self.repository is not None:
            return self.repository.get_campaign(campaign_id)
        return self._campaigns.get(campaign_id)
