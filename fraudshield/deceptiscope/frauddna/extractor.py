from __future__ import annotations

import hashlib
import re
from typing import Any

from fraudshield.deceptiscope.frauddna.models import FraudDNAFingerprint


def compute_app_identity(package_name: str, signers: list[str]) -> str:
    """
    Computes deterministic application identity:
    SHA256(normalized_package_name + '\n' + sorted_signer_fingerprints)
    
    Distinguishes application code lineage from individual APK file mutations.
    """
    norm_pkg = package_name.strip().lower()
    norm_signers = ";".join(sorted(s.strip().lower() for s in signers if s))
    content = f"{norm_pkg}\n{norm_signers}".encode("utf-8")
    return hashlib.sha256(content).hexdigest()


class FraudDNAExtractor:
    """Extracts a complete FraudDNA fingerprint from DeceptiScope investigation findings."""

    FIREBASE_URL_PATTERN = re.compile(r"https?://([a-zA-Z0-9_-]+)\.firebaseio\.com", re.IGNORECASE)
    FIREBASE_APP_PATTERN = re.compile(r"https?://([a-zA-Z0-9_-]+)\.appspot\.com", re.IGNORECASE)

    @classmethod
    def extract_firebase_projects(cls, urls: list[str], domains: list[str]) -> list[str]:
        """Extracts unique Firebase project identifiers from network indicators."""
        projects: set[str] = set()
        for u in urls:
            m1 = cls.FIREBASE_URL_PATTERN.search(u)
            if m1:
                projects.add(m1.group(1).lower())
            m2 = cls.FIREBASE_APP_PATTERN.search(u)
            if m2:
                projects.add(m2.group(1).lower())
        for d in domains:
            m1 = cls.FIREBASE_URL_PATTERN.search(f"https://{d}")
            if m1:
                projects.add(m1.group(1).lower())
        return sorted(projects)

    def extract(self, findings: dict[str, Any]) -> FraudDNAFingerprint:
        """Constructs a normalized FraudDNAFingerprint from findings."""
        extraction = findings.get("extraction", {})
        app = extraction.get("app", {})
        file_info = extraction.get("file", {})
        certificate = extraction.get("certificate", {})
        permissions_info = extraction.get("permissions", {})
        network_info = extraction.get("network_indicators", {})
        method_analysis = findings.get("method_level_reverse", {}) or extraction.get("method_level_reverse", {})

        # 1. Base hashes and identity
        apk_sha256 = (
            file_info.get("sha256")
            or findings.get("sha256")
            or findings.get("analysis_id", "0" * 64)
        )
        if len(apk_sha256) != 64:
            apk_sha256 = hashlib.sha256(str(apk_sha256).encode("utf-8")).hexdigest()

        package_name = app.get("package_name") or "unknown.package"
        app_label = app.get("app_label") or ""

        # Signers
        signers: list[str] = []
        if certificate.get("sha256"):
            signers.append(str(certificate["sha256"]))
        for fp in certificate.get("sha256_fingerprints", []):
            if fp and fp not in signers:
                signers.append(str(fp))

        app_identity = compute_app_identity(package_name, signers)

        # 2. Icon perceptual hash
        icon_phash = extraction.get("icon_phash") or file_info.get("icon_phash")

        # 3. DEX hashes & fuzzy hash
        dex_fps: list[str] = []
        for d in file_info.get("dex_hashes", []):
            if isinstance(d, str):
                dex_fps.append(d)
            elif isinstance(d, dict) and d.get("sha256"):
                dex_fps.append(d["sha256"])

        dex_fuzzy = file_info.get("dex_fuzzy_hash") or file_info.get("ssdeep")

        # 4. Method behavior signatures
        behavior_sigs: set[str] = set()
        for m in method_analysis.get("matches", []):
            if isinstance(m, dict) and m.get("signature_id"):
                behavior_sigs.add(str(m["signature_id"]))

        # 5. Permissions
        permissions: list[str] = sorted(set(permissions_info.get("requested", [])))

        # 6. Banking Capabilities
        capabilities: set[str] = set()
        if any("SMS" in sig for sig in behavior_sigs) or permissions_info.get("sms_receiver"):
            capabilities.add("SMS_INTERCEPTION")
        if any("ACCESSIBILITY" in sig for sig in behavior_sigs) or extraction.get("components", {}).get("accessibility_service"):
            capabilities.add("ACCESSIBILITY_AUTOMATION")
        if any("OVERLAY" in sig for sig in behavior_sigs):
            capabilities.add("UI_OVERLAY_HIJACKING")
        if any("DCL" in sig or "DYNAMIC_CODE" in sig for sig in behavior_sigs):
            capabilities.add("DYNAMIC_CODE_LOADING")
        if any("NET" in sig or "NETWORK" in sig for sig in behavior_sigs) or network_info.get("domains"):
            capabilities.add("C2_COMMUNICATION")

        # 7. Network Indicators
        domains = sorted(set(network_info.get("domains", [])))
        urls = sorted(set(network_info.get("urls", [])))
        ips = sorted(set(network_info.get("ips", [])))
        firebase_projects = self.extract_firebase_projects(urls, domains)

        # 8. Recovered payload hashes
        recovered_payloads = findings.get("recovered_payloads", [])
        payload_hashes = sorted(
            {str(p.get("sha256")) for p in recovered_payloads if isinstance(p, dict) and p.get("sha256") and p.get("sha256") != "0" * 64}
        )

        return FraudDNAFingerprint(
            apk_sha256=apk_sha256,
            app_identity=app_identity,
            package_name=package_name,
            app_label=app_label,
            signer_fingerprints=signers,
            icon_phash=icon_phash,
            dex_fingerprints=sorted(dex_fps),
            dex_fuzzy_hash=dex_fuzzy,
            behavior_signatures=sorted(behavior_sigs),
            permissions=permissions,
            banking_capabilities=sorted(capabilities),
            domains=domains,
            urls=urls,
            ips=ips,
            firebase_project_ids=firebase_projects,
            recovered_payload_hashes=payload_hashes,
        )
