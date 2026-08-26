from __future__ import annotations

from difflib import SequenceMatcher
from enum import Enum
import logging
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from fraudshield.deceptiscope.frauddna.icon_hasher import IconHasher
from fraudshield.deceptiscope.impersonation.bank_profile import (
    BankProfile,
    BankProfileManager,
)


logger = logging.getLogger(__name__)


class BrandImpersonationVerdict(str, Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    SUSPICIOUS = "SUSPICIOUS"
    NONE = "NONE"
    OFFICIAL_LEGITIMATE = "OFFICIAL_LEGITIMATE"


class BrandImpersonationResult(BaseModel):
    """Deterministic banking-brand impersonation analysis result."""

    model_config = ConfigDict(extra="forbid")

    target_bank_id: str | None = None
    target_bank_name: str | None = None
    app_label_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    package_name_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    icon_similarity: float | None = Field(ge=0.0, le=1.0, default=None)
    is_official_package: bool = False
    is_trusted_signer: bool = False
    domain_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    brand_keywords_detected: list[str] = Field(default_factory=list)
    has_credential_forms: bool = False
    impersonation_score: float = Field(ge=0.0, le=1.0, default=0.0)
    verdict: BrandImpersonationVerdict = BrandImpersonationVerdict.NONE
    reasons: list[str] = Field(default_factory=list)


class BrandImpersonationAnalyzer:
    """
    Analyzes whether an APK is impersonating a known banking institution.
    
    Safety Invariants:
    1. Multi-signal requirement: High/Very High verdict strictly requires brand identity overlap
       combined with untrusted signer/package and malicious/credential capabilities.
    2. Icon-only similarity alone NEVER produces a HIGH or VERY HIGH impersonation verdict.
    3. Official package + trusted signer produces OFFICIAL_LEGITIMATE.
    """

    def __init__(
        self,
        profile_manager: BankProfileManager | None = None,
        icon_hasher: IconHasher | None = None,
    ) -> None:
        self.profile_manager = profile_manager or BankProfileManager()
        self.icon_hasher = icon_hasher or IconHasher()

    def analyze(
        self,
        extraction: dict[str, Any],
        method_evidence: dict[str, Any] | None = None,
        icon_phash: str | None = None,
    ) -> BrandImpersonationResult:
        app = extraction.get("app", {})
        certificate = extraction.get("certificate", {})
        network_info = extraction.get("network_indicators", {})

        app_label = str(app.get("app_label") or "").strip()
        package_name = str(app.get("package_name") or "").strip()

        signers: list[str] = []
        if certificate.get("sha256"):
            signers.append(str(certificate["sha256"]))
        for fp in certificate.get("sha256_fingerprints", []):
            if fp and fp not in signers:
                signers.append(str(fp))

        domains = network_info.get("domains", [])
        icon_hash = icon_phash or extraction.get("icon_phash")

        # Detect credential form indicators (MPIN, Password, NetBanking, Debit Card)
        code_signals = extraction.get("code_signals", {})
        has_cred_forms = bool(
            code_signals.get("credential_theft", {}).get("detected")
            or code_signals.get("phishing_indicators", {}).get("detected")
            or any("CREDENTIAL" in str(m.get("category", "")) for m in (method_evidence or {}).get("matches", []))
            or any("SMS" in str(m.get("category", "")) for m in (method_evidence or {}).get("matches", []))
        )

        best_result = BrandImpersonationResult()
        highest_score = -1.0

        for profile in self.profile_manager.all_profiles():
            result = self._evaluate_profile(
                profile=profile,
                app_label=app_label,
                package_name=package_name,
                signers=signers,
                domains=domains,
                icon_hash=icon_hash,
                has_cred_forms=has_cred_forms,
            )
            if result.impersonation_score > highest_score:
                highest_score = result.impersonation_score
                best_result = result

        return best_result

    def _evaluate_profile(
        self,
        profile: BankProfile,
        app_label: str,
        package_name: str,
        signers: list[str],
        domains: list[str],
        icon_hash: str | None,
        has_cred_forms: bool,
    ) -> BrandImpersonationResult:
        reasons: list[str] = []
        app_label_lower = app_label.lower()
        package_name_lower = package_name.lower()

        # 1. Official Package & Signer Match
        is_official_pkg = package_name_lower in [p.lower() for p in profile.official_packages]
        is_trusted_sig = bool(
            profile.trusted_signer_fingerprints
            and set(signers) & set(profile.trusted_signer_fingerprints)
        )

        if is_official_pkg and is_trusted_sig:
            return BrandImpersonationResult(
                target_bank_id=profile.bank_id,
                target_bank_name=profile.official_names[0] if profile.official_names else profile.bank_id,
                app_label_similarity=1.0,
                package_name_similarity=1.0,
                icon_similarity=1.0 if icon_hash else None,
                is_official_package=True,
                is_trusted_signer=True,
                impersonation_score=0.0,
                verdict=BrandImpersonationVerdict.OFFICIAL_LEGITIMATE,
                reasons=["Official package name and trusted signing certificate verified"],
            )

        # 2. App Label Similarity & Keyword Search
        label_sims = [
            SequenceMatcher(None, app_label_lower, name.lower()).ratio()
            for name in profile.official_names
        ]
        label_similarity = max(label_sims) if label_sims else 0.0

        keywords_detected: list[str] = []
        for name in profile.official_names:
            if name.lower() in app_label_lower or name.lower() in package_name_lower:
                keywords_detected.append(name)
        for abbrev in profile.known_abbreviations:
            # Match whole words or clean tokens for abbreviations
            if abbrev.lower() in app_label_lower.split() or abbrev.lower() in package_name_lower.split("."):
                if abbrev not in keywords_detected:
                    keywords_detected.append(abbrev)

        # 3. Package Name Similarity
        pkg_sims = [
            SequenceMatcher(None, package_name_lower, p.lower()).ratio()
            for p in profile.official_packages
        ]
        pkg_similarity = max(pkg_sims) if pkg_sims else 0.0

        # 4. Icon Perceptual Similarity
        icon_sim = self.icon_hasher.similarity(icon_hash, profile.reference_icon_phash)

        # 5. Domain Similarity
        domain_sim = 0.0
        for off_dom in profile.official_domains:
            for d in domains:
                sim = SequenceMatcher(None, d.lower(), off_dom.lower()).ratio()
                if sim > domain_sim:
                    domain_sim = sim

        # 6. Reasons Assembly & Score Calculation
        score = 0.0

        if is_official_pkg and not is_trusted_sig:
            score += 0.50
            reasons.append("Uses official bank package name but untrusted signing certificate (Trojan / Repackaged)")
        elif pkg_similarity >= 0.70:
            score += 0.20
            reasons.append(f"Package name similarity to official package ({int(pkg_similarity * 100)}%)")

        if keywords_detected:
            score += 0.30
            reasons.append(f"Official bank brand keywords detected: {', '.join(keywords_detected)}")
        elif label_similarity >= 0.70:
            score += 0.25
            reasons.append(f"App title highly similar to official bank brand ({int(label_similarity * 100)}%)")

        if domain_sim >= 0.70:
            score += 0.20
            reasons.append(f"Domain name similarity to official bank domain ({int(domain_sim * 100)}%)")

        if icon_sim is not None and icon_sim >= 0.85:
            score += 0.15
            reasons.append(f"Launcher icon visually similar to reference bank icon ({int(icon_sim * 100)}%)")

        if has_cred_forms:
            score += 0.15
            reasons.append("Credential or OTP interception capability detected")

        if not is_trusted_sig and (keywords_detected or label_similarity >= 0.60):
            if not profile.trusted_signer_fingerprints:
                reasons.append("Official signer inventory not configured for target bank")
            else:
                reasons.append("Untrusted signing certificate (Not signed by official bank identity)")

        impersonation_score = max(0.0, min(1.0, score))

        # 7. Verdict Determination (Enforcing Multi-Signal & Icon-Only Safety)
        has_brand_identity_signal = bool(keywords_detected or label_similarity >= 0.65 or (is_official_pkg and not is_trusted_sig))

        if not has_brand_identity_signal:
            # If only icon similarity matched without brand title / keyword overlap -> MUST NOT BE HIGH
            if icon_sim is not None and icon_sim >= 0.85:
                verdict = BrandImpersonationVerdict.SUSPICIOUS
                impersonation_score = min(0.35, impersonation_score)
            else:
                verdict = BrandImpersonationVerdict.NONE
                impersonation_score = 0.0
        else:
            if impersonation_score >= 0.75:
                verdict = BrandImpersonationVerdict.VERY_HIGH
            elif impersonation_score >= 0.50:
                verdict = BrandImpersonationVerdict.HIGH
            elif impersonation_score >= 0.30:
                verdict = BrandImpersonationVerdict.SUSPICIOUS
            else:
                verdict = BrandImpersonationVerdict.NONE

        target_name = profile.official_names[0] if profile.official_names else profile.bank_id

        return BrandImpersonationResult(
            target_bank_id=profile.bank_id if verdict != BrandImpersonationVerdict.NONE else None,
            target_bank_name=target_name if verdict != BrandImpersonationVerdict.NONE else None,
            app_label_similarity=label_similarity,
            package_name_similarity=pkg_similarity,
            icon_similarity=icon_sim,
            is_official_package=is_official_pkg,
            is_trusted_signer=is_trusted_sig,
            domain_similarity=domain_sim,
            brand_keywords_detected=keywords_detected,
            has_credential_forms=has_cred_forms,
            impersonation_score=impersonation_score,
            verdict=verdict,
            reasons=reasons,
        )
