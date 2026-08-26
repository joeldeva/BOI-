from __future__ import annotations

from difflib import SequenceMatcher

from fraudshield.deceptiscope.frauddna.icon_hasher import IconHasher
from fraudshield.deceptiscope.frauddna.models import ComponentSimilarity, FraudDNAFingerprint


def _jaccard(set_a: set[str], set_b: set[str]) -> float:
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


class FraudDNASimilarityCalculator:
    """Calculates multi-dimensional component-wise and overall similarity between FraudDNA fingerprints."""

    def __init__(self, icon_hasher: IconHasher | None = None) -> None:
        self.icon_hasher = icon_hasher or IconHasher()

    def compare(self, fp1: FraudDNAFingerprint, fp2: FraudDNAFingerprint) -> ComponentSimilarity:
        """Calculates component similarity and returns human-readable match reasons."""
        if fp1.apk_sha256 == fp2.apk_sha256:
            # Exact sample match
            return ComponentSimilarity(
                signer_match=bool(fp1.signer_fingerprints),
                package_similarity=1.0,
                dex_similarity=1.0,
                behavior_similarity=1.0,
                icon_similarity=1.0 if fp1.icon_phash else None,
                infrastructure_overlap=1.0 if (fp1.domains or fp1.urls or fp1.ips) else 0.0,
                firebase_overlap=bool(fp1.firebase_project_ids),
                payload_overlap=bool(fp1.recovered_payload_hashes),
                overall_similarity=1.0,
                match_reasons=["identical sample sha256"],
            )

        match_reasons: list[str] = []

        # 1. Signer Match
        s1 = set(fp1.signer_fingerprints)
        s2 = set(fp2.signer_fingerprints)
        shared_signers = s1 & s2
        signer_match = bool(shared_signers)
        if signer_match:
            match_reasons.append("same signer certificate")

        # 2. Package Similarity
        pkg1, pkg2 = fp1.package_name.lower().strip(), fp2.package_name.lower().strip()
        package_sim = SequenceMatcher(None, pkg1, pkg2).ratio()
        if package_sim >= 0.90 and pkg1 != pkg2:
            match_reasons.append(f"package similarity {int(package_sim * 100)}%")

        # 3. DEX Similarity
        dex1 = set(fp1.dex_fingerprints)
        dex2 = set(fp2.dex_fingerprints)
        dex_sim: float | None = None
        if dex1 or dex2:
            dex_sim = _jaccard(dex1, dex2)
            if dex_sim >= 0.80:
                match_reasons.append(f"dex similarity {int(dex_sim * 100)}%")

        # 4. Behavior Similarity
        b1 = set(fp1.behavior_signatures)
        b2 = set(fp2.behavior_signatures)
        behavior_sim = _jaccard(b1, b2)
        if behavior_sim >= 0.60:
            match_reasons.append(f"behavior overlap {int(behavior_sim * 100)}%")

        # 5. Icon Similarity (Supporting Signal Only)
        icon_sim = self.icon_hasher.similarity(fp1.icon_phash, fp2.icon_phash)
        if icon_sim is not None and icon_sim >= 0.85:
            match_reasons.append(f"icon visual similarity {int(icon_sim * 100)}%")

        # 6. Infrastructure Overlap
        infra1 = set(fp1.domains + fp1.urls + fp1.ips)
        infra2 = set(fp2.domains + fp2.urls + fp2.ips)
        infra_sim = _jaccard(infra1, infra2)
        if infra_sim >= 0.30:
            match_reasons.append("shared network infrastructure")

        # 7. Firebase Overlap (Strong Anchor)
        fb1 = set(fp1.firebase_project_ids)
        fb2 = set(fp2.firebase_project_ids)
        shared_fb = fb1 & fb2
        firebase_overlap = bool(shared_fb)
        if firebase_overlap:
            match_reasons.append("same firebase project")

        # 8. Payload Overlap (Strong Anchor)
        p1 = set(fp1.recovered_payload_hashes)
        p2 = set(fp2.recovered_payload_hashes)
        shared_payloads = p1 & p2
        payload_overlap = bool(shared_payloads)
        if payload_overlap:
            match_reasons.append("same recovered payload")

        # Deterministic Weighted Overall Similarity Calculation
        # Weights: Signer (0.25), Firebase (0.25), Payload (0.20), DEX (0.15), Behavior (0.10), Infra (0.05)
        score = 0.0
        if signer_match:
            score += 0.25
        if firebase_overlap:
            score += 0.25
        if payload_overlap:
            score += 0.20
        if dex_sim is not None:
            score += 0.15 * dex_sim
        if behavior_sim:
            score += 0.10 * behavior_sim
        if infra_sim:
            score += 0.05 * infra_sim

        overall = max(0.0, min(1.0, score))

        return ComponentSimilarity(
            signer_match=signer_match,
            package_similarity=package_sim,
            dex_similarity=dex_sim,
            behavior_similarity=behavior_sim,
            icon_similarity=icon_sim,
            infrastructure_overlap=infra_sim,
            firebase_overlap=firebase_overlap,
            payload_overlap=payload_overlap,
            overall_similarity=overall,
            match_reasons=match_reasons,
        )
