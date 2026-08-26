from __future__ import annotations

from pathlib import Path
import pytest

from fraudshield.deceptiscope.frauddna import FraudDNAExtractor
from fraudshield.deceptiscope.impersonation import (
    BankProfile,
    BankProfileManager,
    BrandImpersonationAnalyzer,
    BrandImpersonationVerdict,
    FirebaseExtractor,
)


# Valid 64-char hex SHA-256 test signer fingerprint (not a real certificate)
_TEST_SIGNER_FP = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
# A different attacker signer fingerprint
_ATTACKER_SIGNER_FP = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


@pytest.fixture
def custom_profile_manager(tmp_path: Path) -> BankProfileManager:
    manager = BankProfileManager(profiles_dir=tmp_path)
    profile = BankProfile(
        bank_id="bank_of_india",
        official_names=["Bank of India", "BOI", "BOI Mobile", "BOI Omni Neo"],
        known_abbreviations=["BOI", "BKID"],
        official_domains=["bankofindia.co.in", "bankofindia.com"],
        official_packages=["com.boi.mobile", "com.bankofindia.omni"],
        trusted_signer_fingerprints=[_TEST_SIGNER_FP],
        reference_icon_phash="1111222233334444",
    )
    manager.register_profile(profile)
    return manager


# ---------------------------------------------------------------------------
# Test 1: Strong Multi-Signal Impersonation
# ---------------------------------------------------------------------------
def test_strong_multisignal_impersonation(custom_profile_manager: BankProfileManager) -> None:
    analyzer = BrandImpersonationAnalyzer(profile_manager=custom_profile_manager)

    extraction = {
        "app": {
            "app_label": "Bank of India Mobile KYC",
            "package_name": "com.fake.boi.rewards",
        },
        "certificate": {
            "sha256": _ATTACKER_SIGNER_FP,
            "sha256_fingerprints": [_ATTACKER_SIGNER_FP],
        },
        "network_indicators": {
            "domains": ["bankofindia-kyc-update.com"],
        },
        "code_signals": {
            "credential_theft": {"detected": True},
        },
        "icon_phash": "1111222233334444",  # Same icon
    }

    result = analyzer.analyze(extraction)

    assert result.verdict == BrandImpersonationVerdict.VERY_HIGH
    assert result.target_bank_id == "bank_of_india"
    assert result.impersonation_score >= 0.75
    assert not result.is_trusted_signer
    assert "Official bank brand keywords detected: Bank of India, BOI" in result.reasons or any("keywords detected" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Test 2: Icon-Only Similarity Does NOT Produce HIGH Verdict
# ---------------------------------------------------------------------------
def test_icon_only_similarity_does_not_produce_high_verdict(custom_profile_manager: BankProfileManager) -> None:
    analyzer = BrandImpersonationAnalyzer(profile_manager=custom_profile_manager)

    # Completely unrelated clean app with a generic icon hash matching BOI's icon
    extraction = {
        "app": {
            "app_label": "Super Simple Calculator",
            "package_name": "com.clean.simplecalc",
        },
        "certificate": {
            "sha256": "CLEAN_DEV_SIGNER_HASH",
            "sha256_fingerprints": ["CLEAN_DEV_SIGNER_HASH"],
        },
        "network_indicators": {
            "domains": ["simplecalc.org"],
        },
        "code_signals": {},
        "icon_phash": "1111222233334444",  # Matches icon only
    }

    result = analyzer.analyze(extraction)

    # Must NOT be HIGH or VERY_HIGH
    assert result.verdict in (BrandImpersonationVerdict.NONE, BrandImpersonationVerdict.SUSPICIOUS)
    assert result.verdict != BrandImpersonationVerdict.HIGH
    assert result.verdict != BrandImpersonationVerdict.VERY_HIGH
    assert result.impersonation_score <= 0.35


# ---------------------------------------------------------------------------
# Test 3: Legitimate Official App Recognized as OFFICIAL_LEGITIMATE
# ---------------------------------------------------------------------------
def test_official_legitimate_app(custom_profile_manager: BankProfileManager) -> None:
    analyzer = BrandImpersonationAnalyzer(profile_manager=custom_profile_manager)

    extraction = {
        "app": {
            "app_label": "BOI Mobile",
            "package_name": "com.boi.mobile",
        },
        "certificate": {
            "sha256": _TEST_SIGNER_FP,  # matches the trusted fingerprint in the fixture
            "sha256_fingerprints": [_TEST_SIGNER_FP],
        },
        "network_indicators": {
            "domains": ["bankofindia.co.in"],
        },
        "code_signals": {},
        "icon_phash": "1111222233334444",
    }

    result = analyzer.analyze(extraction)

    assert result.verdict == BrandImpersonationVerdict.OFFICIAL_LEGITIMATE
    assert result.is_official_package is True
    assert result.is_trusted_signer is True
    assert result.impersonation_score == 0.0


# ---------------------------------------------------------------------------
# Test 4: Repackaged / Trojanized Official Package Name
# ---------------------------------------------------------------------------
def test_repackaged_official_package_name(custom_profile_manager: BankProfileManager) -> None:
    analyzer = BrandImpersonationAnalyzer(profile_manager=custom_profile_manager)

    # Uses official package name com.boi.mobile, but signed by attacker
    extraction = {
        "app": {
            "app_label": "BOI Mobile",
            "package_name": "com.boi.mobile",
        },
        "certificate": {
            "sha256": _ATTACKER_SIGNER_FP,  # different from trusted fingerprint
            "sha256_fingerprints": [_ATTACKER_SIGNER_FP],
        },
        "network_indicators": {
            "domains": ["c2-evil.net"],
        },
        "code_signals": {},
    }

    result = analyzer.analyze(extraction)

    assert result.is_official_package is True
    assert result.is_trusted_signer is False
    assert result.verdict in (BrandImpersonationVerdict.HIGH, BrandImpersonationVerdict.VERY_HIGH)
    assert any("Uses official bank package name but untrusted signing certificate" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Test 5: Firebase Static Extraction
# ---------------------------------------------------------------------------
def test_firebase_static_extraction() -> None:
    extractor = FirebaseExtractor()
    extraction = {
        "network_indicators": {
            "urls": [
                "https://boi-kyc-fraud-2026.firebaseio.com/users.json",
                "https://boi-kyc-fraud-2026.appspot.com/upload",
            ],
            "domains": ["boi-kyc-fraud-2026.firebaseio.com"],
        }
    }

    infra = extractor.extract_from_findings(extraction)

    assert infra.project_id == "boi-kyc-fraud-2026"
    assert infra.storage_bucket == "boi-kyc-fraud-2026.appspot.com"
    assert "https://boi-kyc-fraud-2026.firebaseio.com" in infra.database_urls


# ---------------------------------------------------------------------------
# Test 6: Firebase Identifiers Enter FraudDNA
# ---------------------------------------------------------------------------
def test_firebase_enters_frauddna() -> None:
    extractor = FraudDNAExtractor()
    findings = {
        "extraction": {
            "app": {"package_name": "com.fake.bank", "app_label": "Fake Bank"},
            "file": {"sha256": "f" * 64},
            "certificate": {"sha256": "SIG_1"},
            "network_indicators": {
                "urls": ["https://target-bank-c2.firebaseio.com/stolen.json"],
                "domains": ["target-bank-c2.firebaseio.com"],
            },
        }
    }

    fp = extractor.extract(findings)
    assert "target-bank-c2" in fp.firebase_project_ids


# ---------------------------------------------------------------------------
# Test 7: Missing Bank Reference Data Handled Gracefully → NOT_CONFIGURED
# ---------------------------------------------------------------------------
def test_missing_bank_profile_handled_gracefully(tmp_path: Path) -> None:
    """
    When no profiles directory/file exists, BankProfileManager must not create
    synthetic fallback profiles. The result must be NOT_CONFIGURED, not NONE
    with 0.0 score from a fabricated profile.
    """
    empty_manager = BankProfileManager(profiles_dir=tmp_path / "empty_dir")
    assert not empty_manager.is_configured(), "Manager must report not configured"
    assert empty_manager.all_profiles() == [], "No synthetic profiles must exist"

    analyzer = BrandImpersonationAnalyzer(profile_manager=empty_manager)

    extraction = {
        "app": {"app_label": "Generic App", "package_name": "com.generic.app"},
        "certificate": {"sha256": "GENERIC_SIG"},
        "network_indicators": {},
    }

    result = analyzer.analyze(extraction)
    # NOT_CONFIGURED is the honest verdict — no profiles loaded
    assert result.verdict == BrandImpersonationVerdict.NOT_CONFIGURED
    assert result.impersonation_score == 0.0
    assert result.signer_reference_status == "NOT_CONFIGURED"
    assert result.icon_reference_status == "NOT_CONFIGURED"
