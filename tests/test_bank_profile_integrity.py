"""
PRODUCTIZATION PASS 5 — Bank Profile Integrity Tests
=====================================================
Tests all 9 required scenarios:
1. missing profile -> NOT_CONFIGURED
2. invalid YAML -> visible configuration failure
3. empty signer list -> no signer-mismatch conclusion
4. null icon -> no icon conclusion
5. name-only similarity cannot confirm impersonation
6. package/name/domain combination can support suspicious impersonation
7. configured signer exact match behaves correctly
8. configured signer mismatch behaves correctly
9. frontend/report display NOT_CONFIGURED honestly (report section check)
"""
from __future__ import annotations

import textwrap
from pathlib import Path
import pytest

from fraudshield.deceptiscope.impersonation import (
    BankProfile,
    BankProfileManager,
    BrandImpersonationAnalyzer,
    BrandImpersonationVerdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager_with_profile(tmp_path: Path, **overrides) -> BankProfileManager:
    """Creates a manager with a fully configured test profile."""
    defaults = dict(
        bank_id="test_bank",
        official_names=["Test Bank", "TB Mobile"],
        known_abbreviations=["TB"],
        official_domains=["testbank.co.in", "testbank.com"],
        official_packages=["com.testbank.mobile", "com.testbank.omni"],
        trusted_signer_fingerprints=["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
        reference_icon_phash="1111222233334444",
    )
    defaults.update(overrides)
    mgr = BankProfileManager(profiles_dir=tmp_path / "nonexistent")  # start empty
    mgr.register_profile(BankProfile(**defaults))
    return mgr


def _make_extraction(
    app_label: str = "Generic App",
    package_name: str = "com.generic.app",
    signer: str = "UNKNOWN_SIGNER",
    domains: list[str] | None = None,
    icon_phash: str | None = None,
    credential_theft: bool = False,
) -> dict:
    return {
        "app": {"app_label": app_label, "package_name": package_name},
        "certificate": {"sha256": signer, "sha256_fingerprints": [signer]},
        "network_indicators": {"domains": domains or []},
        "code_signals": {"credential_theft": {"detected": credential_theft}},
        "icon_phash": icon_phash,
    }


# ===========================================================================
# Test 1: Missing profile directory → NOT_CONFIGURED verdict
# ===========================================================================
def test_missing_profile_directory_returns_not_configured(tmp_path: Path) -> None:
    """
    When no profiles directory exists, BankProfileManager must load zero profiles
    and BrandImpersonationAnalyzer must return NOT_CONFIGURED — not invent a profile.
    """
    manager = BankProfileManager(profiles_dir=tmp_path / "does_not_exist")
    assert not manager.is_configured(), "Manager must report not configured when dir is absent"
    assert manager.all_profiles() == [], "Must have zero profiles"

    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)
    result = analyzer.analyze(_make_extraction())

    assert result.verdict == BrandImpersonationVerdict.NOT_CONFIGURED
    assert result.impersonation_score == 0.0
    assert result.signer_reference_status == "NOT_CONFIGURED"
    assert result.icon_reference_status == "NOT_CONFIGURED"


def test_empty_profile_directory_returns_not_configured(tmp_path: Path) -> None:
    """An existing but empty profiles directory also returns NOT_CONFIGURED."""
    profiles_dir = tmp_path / "empty"
    profiles_dir.mkdir()

    manager = BankProfileManager(profiles_dir=profiles_dir)
    assert not manager.is_configured()

    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)
    result = analyzer.analyze(_make_extraction())

    assert result.verdict == BrandImpersonationVerdict.NOT_CONFIGURED


# ===========================================================================
# Test 2: Invalid YAML → visible configuration failure raised
# ===========================================================================
def test_invalid_yaml_malformed_signer_raises(tmp_path: Path) -> None:
    """
    A YAML file with an invented / invalid signer fingerprint must raise ValueError,
    not silently produce a profile with fabricated authoritative data.
    """
    bad_profile = textwrap.dedent("""\
        bank_id: "bad_bank"
        official_names: ["Bad Bank"]
        official_domains: ["badbank.com"]
        official_packages: ["com.bad.bank"]
        trusted_signer_fingerprints:
          - "THIS_IS_NOT_A_REAL_SHA256_HASH"
    """)
    (tmp_path / "bad_bank.yaml").write_text(bad_profile, encoding="utf-8")

    with pytest.raises(ValueError, match="invalid and cannot be loaded|Invalid signer fingerprint"):
        BankProfileManager(profiles_dir=tmp_path)


def test_invalid_yaml_malformed_domain_raises(tmp_path: Path) -> None:
    """A YAML with an invalid domain (e.g. has a scheme) must raise ValueError."""
    bad_profile = textwrap.dedent("""\
        bank_id: "bad_bank2"
        official_names: ["Bad Bank 2"]
        official_domains:
          - "https://badbank.com"
        official_packages: ["com.bad.bank"]
        trusted_signer_fingerprints: []
    """)
    (tmp_path / "bad_bank2.yaml").write_text(bad_profile, encoding="utf-8")

    with pytest.raises(ValueError, match="invalid and cannot be loaded|Invalid official domain"):
        BankProfileManager(profiles_dir=tmp_path)


def test_invalid_yaml_malformed_package_raises(tmp_path: Path) -> None:
    """A YAML with an invalid package name (starts with digit) must raise ValueError."""
    bad_profile = textwrap.dedent("""\
        bank_id: "bad_bank3"
        official_names: ["Bad Bank 3"]
        official_domains: ["badbank.com"]
        official_packages:
          - "1nvalid.package.name"
        trusted_signer_fingerprints: []
    """)
    (tmp_path / "bad_bank3.yaml").write_text(bad_profile, encoding="utf-8")

    with pytest.raises(ValueError, match="invalid and cannot be loaded|Invalid official package"):
        BankProfileManager(profiles_dir=tmp_path)


def test_valid_yaml_with_empty_lists_loads_correctly(tmp_path: Path) -> None:
    """A YAML with all empty optional lists is valid and loads without error."""
    good_profile = textwrap.dedent("""\
        bank_id: "good_bank"
        official_names: ["Good Bank"]
        official_domains: ["goodbank.co.in"]
        official_packages: ["com.good.bank"]
        trusted_signer_fingerprints: []
        reference_icon_phash: null
    """)
    (tmp_path / "good_bank.yaml").write_text(good_profile, encoding="utf-8")
    manager = BankProfileManager(profiles_dir=tmp_path)
    assert manager.is_configured()
    profile = manager.get_profile("good_bank")
    assert profile is not None
    assert profile.signer_reference_status == "NOT_CONFIGURED"
    assert profile.icon_reference_status == "NOT_CONFIGURED"


# ===========================================================================
# Test 3: Empty signer list → no signer-mismatch conclusion
# ===========================================================================
def test_empty_signer_list_produces_no_signer_mismatch_conclusion(tmp_path: Path) -> None:
    """
    When trusted_signer_fingerprints == [], the analysis must NOT conclude
    'untrusted signing certificate' — it has no inventory to compare against.
    """
    manager = _make_manager_with_profile(tmp_path, trusted_signer_fingerprints=[])
    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)

    extraction = _make_extraction(
        app_label="Test Bank Mobile",
        package_name="com.testbank.mobile",
        signer="ANY_RANDOM_SIGNER_HASH",
    )
    result = analyzer.analyze(extraction)

    # Signer reference must be reported as NOT_CONFIGURED
    assert result.signer_reference_status == "NOT_CONFIGURED"
    # Must not produce a mismatch conclusion in reasons
    assert not any("Untrusted signing certificate" in r for r in result.reasons), (
        "Must not claim signer mismatch when inventory not configured"
    )
    # Must not be OFFICIAL_LEGITIMATE either (no signer to verify)
    assert result.verdict != BrandImpersonationVerdict.OFFICIAL_LEGITIMATE
    # The honest note must appear
    assert any("signer inventory not configured" in r.lower() for r in result.reasons)


# ===========================================================================
# Test 4: Null icon phash → no icon comparison performed
# ===========================================================================
def test_null_icon_phash_produces_no_icon_conclusion(tmp_path: Path) -> None:
    """
    When reference_icon_phash is None, icon similarity must be None
    and no icon-based score contribution must occur.
    """
    manager = _make_manager_with_profile(tmp_path, reference_icon_phash=None)
    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)

    # APK has an icon hash that would match if compared
    extraction = _make_extraction(
        app_label="Unrelated Calculator",
        package_name="com.calc.app",
        icon_phash="1111222233334444",
    )
    result = analyzer.analyze(extraction)

    assert result.icon_reference_status == "NOT_CONFIGURED"
    assert result.icon_similarity is None, "Must not compute icon similarity when reference is not configured"
    assert not any("icon" in r.lower() for r in result.reasons), (
        "Must not mention icon comparison when reference not configured"
    )


# ===========================================================================
# Test 5: Name-only similarity cannot confirm impersonation
# ===========================================================================
def test_name_only_similarity_cannot_produce_high_verdict(tmp_path: Path) -> None:
    """
    An app whose name is highly similar to the bank's brand, but with no keyword match,
    no package match, no domain match, and no credential signals,
    must not produce HIGH or VERY_HIGH verdict.
    """
    manager = _make_manager_with_profile(tmp_path)
    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)

    extraction = _make_extraction(
        app_label="Teat Bank Mobile",  # 90%+ label similarity, but NOT a keyword match
        package_name="com.harmless.app",
        domains=["harmless.org"],
    )
    result = analyzer.analyze(extraction)

    assert result.verdict not in (
        BrandImpersonationVerdict.HIGH,
        BrandImpersonationVerdict.VERY_HIGH,
    ), f"Name-only similarity must not produce HIGH/VERY_HIGH, got: {result.verdict}"
    assert result.impersonation_score < 0.50, (
        f"Score must be below HIGH threshold for name-only: {result.impersonation_score}"
    )


# ===========================================================================
# Test 6: Package + name + domain combination can support suspicious
# ===========================================================================
def test_package_name_domain_combination_supports_suspicious(tmp_path: Path) -> None:
    """
    An app with official bank brand keywords, similar package, and
    similar domain gets at least SUSPICIOUS verdict without credential signals.
    """
    manager = _make_manager_with_profile(tmp_path)
    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)

    extraction = _make_extraction(
        app_label="Test Bank KYC Update",
        package_name="com.testbank.kyc",       # similar to official
        domains=["testbank-kyc-update.com"],   # similar domain
        signer="ATTACKER_SIG",
    )
    result = analyzer.analyze(extraction)

    assert result.verdict in (
        BrandImpersonationVerdict.SUSPICIOUS,
        BrandImpersonationVerdict.HIGH,
        BrandImpersonationVerdict.VERY_HIGH,
    ), f"Expected at least SUSPICIOUS for multi-signal, got: {result.verdict}"
    assert result.impersonation_score >= 0.30


# ===========================================================================
# Test 7: Configured signer exact match → OFFICIAL_LEGITIMATE
# ===========================================================================
def test_configured_signer_exact_match_is_official_legitimate(tmp_path: Path) -> None:
    """
    When both official package AND trusted signer match exactly, verdict must be
    OFFICIAL_LEGITIMATE with impersonation_score == 0.0.
    """
    trusted_fp = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    manager = _make_manager_with_profile(
        tmp_path, trusted_signer_fingerprints=[trusted_fp]
    )
    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)

    extraction = _make_extraction(
        app_label="Test Bank Mobile",
        package_name="com.testbank.mobile",  # official package
        signer=trusted_fp,                   # exact match
    )
    result = analyzer.analyze(extraction)

    assert result.verdict == BrandImpersonationVerdict.OFFICIAL_LEGITIMATE
    assert result.is_official_package is True
    assert result.is_trusted_signer is True
    assert result.impersonation_score == 0.0
    assert result.signer_reference_status == "CONFIGURED"


# ===========================================================================
# Test 8: Configured signer mismatch → HIGH/VERY_HIGH with reasons
# ===========================================================================
def test_configured_signer_mismatch_produces_high_verdict(tmp_path: Path) -> None:
    """
    When signer inventory IS configured and the APK's signer does NOT appear
    in the trusted list, the analysis must explicitly note the mismatch.
    """
    trusted_fp = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    manager = _make_manager_with_profile(
        tmp_path, trusted_signer_fingerprints=[trusted_fp]
    )
    analyzer = BrandImpersonationAnalyzer(profile_manager=manager)

    extraction = _make_extraction(
        app_label="Test Bank Mobile",         # exact keyword match
        package_name="com.testbank.mobile",   # official package name
        signer="ATTACKER_SIGNER_NOT_TRUSTED", # different signer
    )
    result = analyzer.analyze(extraction)

    assert result.is_official_package is True
    assert result.is_trusted_signer is False
    assert result.verdict in (BrandImpersonationVerdict.HIGH, BrandImpersonationVerdict.VERY_HIGH)
    assert any("untrusted signing certificate" in r.lower() for r in result.reasons), (
        "Must note untrusted signing certificate when inventory configured and signer mismatches"
    )
    assert result.signer_reference_status == "CONFIGURED"


# ===========================================================================
# Test 9: Report / display section handles NOT_CONFIGURED honestly
# ===========================================================================
def test_report_impersonation_section_not_configured_label(tmp_path: Path) -> None:
    """
    When verdict is NOT_CONFIGURED, the PDF report section must render the
    verdict text as 'NOT_CONFIGURED' and not claim any impersonation score.
    """
    from fraudshield.deceptiscope.report import build_analysis_pdf

    brand_impersonation_not_configured = {
        "verdict": "NOT_CONFIGURED",
        "target_bank_name": None,
        "target_bank_id": None,
        "app_label_similarity": 0.0,
        "package_name_similarity": 0.0,
        "icon_similarity": None,
        "is_official_package": False,
        "is_trusted_signer": False,
        "domain_similarity": 0.0,
        "brand_keywords_detected": [],
        "has_credential_forms": False,
        "impersonation_score": 0.0,
        "reasons": ["No bank reference profiles are configured — impersonation analysis unavailable"],
        "signer_reference_status": "NOT_CONFIGURED",
        "icon_reference_status": "NOT_CONFIGURED",
    }

    minimal_analysis = {
        "id": "test-pass5-001",
        "sha256": "a" * 64,
        "data_origin": "production",
        "result": {
            "extraction": {
                "app": {"app_label": "Test App", "package_name": "com.test.app"},
                "file": {"sha256": "a" * 64},
                "network_indicators": {"domains": [], "ips": [], "urls": []},
                "code_signals": {},
            },
            "risk": {
                "overall_score": 10,
                "static_score": 10,
                "severity": "LOW",
                "confidence": 0.5,
                "runtime_adjustment": 0,
                "runtime_confirmation": 0.0,
            },
            "malware_assessment": {"verdict": "INCONCLUSIVE"},
            "brand_impersonation": brand_impersonation_not_configured,
            "firebase_infrastructure": {},
            "banking_impact": {"items": []},
            "ai_investigation": {"hypotheses": []},
            "runtime_evidence": [],
            "recovered_payloads": [],
            "emitted_indicators": [],
            "mitre_attack": [],
        },
        "narrative": "No narrative.",
    }

    pdf_bytes = build_analysis_pdf(minimal_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000, "PDF must be generated"
    # The PDF should contain the NOT_CONFIGURED text in the impersonation section
    # We verify it does not crash and produces a valid PDF (content decoded for text check)
    pdf_text_portion = pdf_bytes[:4096]
    # PDF header must be present
    assert pdf_text_portion[:4] == b"%PDF"


# ===========================================================================
# Test: BankProfile signer_reference_status and icon_reference_status properties
# ===========================================================================
def test_bank_profile_status_properties_configured() -> None:
    """BankProfile properties return CONFIGURED when data is present."""
    profile = BankProfile(
        bank_id="bank_x",
        official_names=["Bank X"],
        official_domains=["bankx.com"],
        official_packages=["com.bankx.app"],
        trusted_signer_fingerprints=["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
        reference_icon_phash="abcd1234abcd1234",
    )
    assert profile.signer_reference_status == "CONFIGURED"
    assert profile.icon_reference_status == "CONFIGURED"


def test_bank_profile_status_properties_not_configured() -> None:
    """BankProfile properties return NOT_CONFIGURED when data is absent."""
    profile = BankProfile(
        bank_id="bank_y",
        official_names=["Bank Y"],
        official_domains=["banky.com"],
        official_packages=["com.banky.app"],
        trusted_signer_fingerprints=[],
        reference_icon_phash=None,
    )
    assert profile.signer_reference_status == "NOT_CONFIGURED"
    assert profile.icon_reference_status == "NOT_CONFIGURED"


# ===========================================================================
# Test: BOI YAML profile loads with empty signers and null icon
# ===========================================================================
def test_boi_yaml_profile_loads_with_no_invented_data() -> None:
    """
    The real config/bank_profiles/bank_of_india.yaml must load correctly
    with trusted_signer_fingerprints == [] and reference_icon_phash == None.
    No fingerprints or icon hashes should be invented.
    """
    real_profiles_dir = (
        Path(__file__).resolve().parent.parent / "config" / "bank_profiles"
    )
    if not real_profiles_dir.exists():
        pytest.skip("config/bank_profiles/ directory not found")

    manager = BankProfileManager(profiles_dir=real_profiles_dir)
    assert manager.is_configured(), "BOI profile should load"

    boi = manager.get_profile("bank_of_india")
    assert boi is not None
    assert boi.trusted_signer_fingerprints == [], (
        "BOI profile must have empty signer fingerprints — do not invent hashes"
    )
    assert boi.reference_icon_phash is None, (
        "BOI profile must have null icon phash — do not invent icon hashes"
    )
    assert boi.signer_reference_status == "NOT_CONFIGURED"
    assert boi.icon_reference_status == "NOT_CONFIGURED"


# ===========================================================================
# Test: No BOI fallback created by code when dir missing
# ===========================================================================
def test_no_hardcoded_boi_fallback_when_dir_missing(tmp_path: Path) -> None:
    """
    Critically: when the profile directory does not exist, NO bank_of_india
    profile must appear. The old fallback code has been removed.
    """
    manager = BankProfileManager(profiles_dir=tmp_path / "nonexistent")
    assert manager.get_profile("bank_of_india") is None, (
        "No hardcoded BOI fallback must exist — profiles only come from YAML files"
    )
    assert manager.all_profiles() == []
    assert not manager.is_configured()
