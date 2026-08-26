from __future__ import annotations

from fraudshield.deceptiscope.frauddna.campaigns import CampaignCorrelator
from fraudshield.deceptiscope.frauddna.extractor import (
    FraudDNAExtractor,
    compute_app_identity,
)
from fraudshield.deceptiscope.frauddna.icon_hasher import IconHasher
from fraudshield.deceptiscope.frauddna.models import (
    Campaign,
    ComponentSimilarity,
    FraudDNAFingerprint,
    RelatedSample,
)
from fraudshield.deceptiscope.frauddna.similarity import FraudDNASimilarityCalculator

__all__ = [
    "Campaign",
    "CampaignCorrelator",
    "ComponentSimilarity",
    "FraudDNAExtractor",
    "FraudDNAFingerprint",
    "FraudDNASimilarityCalculator",
    "IconHasher",
    "RelatedSample",
    "compute_app_identity",
]
