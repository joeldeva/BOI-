from __future__ import annotations

import logging

from fraudshield.deceptiscope.frauddna.models import (
    Campaign,
    FraudDNAFingerprint,
    RelatedSample,
)
from fraudshield.deceptiscope.frauddna.similarity import FraudDNASimilarityCalculator


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
    ) -> None:
        self.calculator = calculator or FraudDNASimilarityCalculator()
        self.min_related_threshold = min_related_threshold
        self._corpus: dict[str, FraudDNAFingerprint] = {}
        self._campaigns: dict[str, Campaign] = {}
        self._sample_to_campaign: dict[str, str] = {}
        self._next_campaign_index = 1

    def correlate(
        self,
        sample: FraudDNAFingerprint,
    ) -> tuple[Campaign | None, list[RelatedSample]]:
        """
        Correlates a newly analyzed sample against the known corpus,
        assigns deterministic campaign membership, and returns related samples.
        """
        related_samples: list[RelatedSample] = []
        target_campaign_id: str | None = None

        for existing_sha, existing_fp in self._corpus.items():
            if existing_sha == sample.apk_sha256:
                continue

            sim = self.calculator.compare(sample, existing_fp)
            if sim.overall_similarity >= self.min_related_threshold or sim.match_reasons:
                camp_id = self._sample_to_campaign.get(existing_sha)
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

                # Check for Hard Link Anchors to join campaign
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

        if target_campaign_id and target_campaign_id in self._campaigns:
            assigned_campaign = self._campaigns[target_campaign_id]
            if sample.apk_sha256 not in assigned_campaign.member_sha256s:
                assigned_campaign.member_sha256s.append(sample.apk_sha256)
                # Aggregate shared signatures and infra
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
            self._sample_to_campaign[sample.apk_sha256] = target_campaign_id
        elif related_samples and any(r.similarity >= 0.45 for r in related_samples):
            # Create a new campaign for this correlated cluster
            cid = f"CAMP-{self._next_campaign_index:03d}"
            self._next_campaign_index += 1
            members = [sample.apk_sha256]
            for r in related_samples:
                if r.similarity >= 0.45 and r.sha256 not in members:
                    members.append(r.sha256)
                    self._sample_to_campaign[r.sha256] = cid

            assigned_campaign = Campaign(
                campaign_id=cid,
                name=f"Banking Campaign {cid} ({sample.app_label or sample.package_name})",
                member_sha256s=members,
                primary_signatures=list(sample.behavior_signatures),
                shared_infrastructure=list(sample.domains + sample.urls),
                shared_firebase_projects=list(sample.firebase_project_ids),
                shared_signer_fingerprints=list(sample.signer_fingerprints),
            )
            self._campaigns[cid] = assigned_campaign
            self._sample_to_campaign[sample.apk_sha256] = cid

        # Register sample into corpus
        self._corpus[sample.apk_sha256] = sample

        # Update campaign_id references in returned related samples
        for r in related_samples:
            if not r.campaign_id:
                r.campaign_id = self._sample_to_campaign.get(r.sha256)

        return assigned_campaign, related_samples

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        return self._campaigns.get(campaign_id)
