from __future__ import annotations

import time

from fraudshield.deceptiscope.frauddna import (
    CampaignCorrelator,
    FraudDNAFingerprint,
    FraudDNASimilarityCalculator,
    compute_app_identity,
)


def _make_sample(
    sha_suffix: str = "1",
    pkg: str = "com.fake.bank",
    signers: list[str] | None = None,
    dex: list[str] | None = None,
    firebase: list[str] | None = None,
    payloads: list[str] | None = None,
    behaviors: list[str] | None = None,
    icon_phash: str | None = None,
) -> FraudDNAFingerprint:
    apk_sha = f"{sha_suffix * 64}"[:64]
    signer_list = signers or ["SIGNER_A_SHA256"]
    app_id = compute_app_identity(pkg, signer_list)

    return FraudDNAFingerprint(
        apk_sha256=apk_sha,
        app_identity=app_id,
        package_name=pkg,
        app_label="Fake Bank",
        signer_fingerprints=signer_list,
        icon_phash=icon_phash or "a1b2c3d4e5f60718",
        dex_fingerprints=dex or ["DEX_HASH_1"],
        dex_fuzzy_hash=None,
        behavior_signatures=behaviors or ["MTH-SMS-001", "MTH-NET-001"],
        permissions=["android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
        banking_capabilities=["SMS_INTERCEPTION", "C2_COMMUNICATION"],
        domains=["c2-evil.net"],
        urls=["https://c2-evil.net/exfil"],
        ips=["192.168.1.100"],
        firebase_project_ids=firebase or ["bank-fraud-prod"],
        recovered_payload_hashes=payloads or [],
    )


# ---------------------------------------------------------------------------
# Test 1: Identical Fingerprints
# ---------------------------------------------------------------------------
def test_identical_fingerprints() -> None:
    calc = FraudDNASimilarityCalculator()
    s1 = _make_sample("1")
    s2 = _make_sample("1")

    res = calc.compare(s1, s2)
    assert res.overall_similarity == 1.0
    assert "identical sample sha256" in res.match_reasons


# ---------------------------------------------------------------------------
# Test 2: Unrelated Samples
# ---------------------------------------------------------------------------
def test_unrelated_samples() -> None:
    calc = FraudDNASimilarityCalculator()
    s1 = _make_sample(
        "1",
        pkg="com.evil.trojan",
        signers=["SIGNER_A"],
        firebase=["firebase-trojan-1"],
        dex=["DEX_A"],
        behaviors=["MTH-SMS-001"],
        icon_phash="1111111111111111",
    )
    s1.domains = ["evil1.com"]
    s1.urls = ["https://evil1.com"]
    s1.ips = ["1.1.1.1"]

    s2 = _make_sample(
        "2",
        pkg="com.totally.different.cleanapp",
        signers=["SIGNER_B"],
        firebase=["firebase-clean-2"],
        dex=["DEX_B"],
        behaviors=["MTH-RECON-001"],
        icon_phash="2222222222222222",
    )
    s2.domains = ["clean2.com"]
    s2.urls = ["https://clean2.com"]
    s2.ips = ["2.2.2.2"]

    res = calc.compare(s1, s2)
    assert res.overall_similarity == 0.0
    assert not res.signer_match
    assert not res.firebase_overlap


# ---------------------------------------------------------------------------
# Test 3: Same Signer
# ---------------------------------------------------------------------------
def test_same_signer_linkage() -> None:
    calc = FraudDNASimilarityCalculator()
    s1 = _make_sample("1", signers=["SHARED_SIGNER_CERT_HEX"])
    s2 = _make_sample("2", signers=["SHARED_SIGNER_CERT_HEX"], firebase=["other-fb"])

    res = calc.compare(s1, s2)
    assert res.signer_match is True
    assert "same signer certificate" in res.match_reasons
    assert res.overall_similarity >= 0.25


# ---------------------------------------------------------------------------
# Test 4: Same Firebase Project (Hard Anchor)
# ---------------------------------------------------------------------------
def test_same_firebase_project() -> None:
    calc = FraudDNASimilarityCalculator()
    s1 = _make_sample("1", firebase=["target-bank-c2"], signers=["SIGNER_1"])
    s2 = _make_sample("2", firebase=["target-bank-c2"], signers=["SIGNER_2"])

    res = calc.compare(s1, s2)
    assert res.firebase_overlap is True
    assert "same firebase project" in res.match_reasons
    assert res.overall_similarity >= 0.25


# ---------------------------------------------------------------------------
# Test 5: High DEX Similarity
# ---------------------------------------------------------------------------
def test_high_dex_similarity() -> None:
    calc = FraudDNASimilarityCalculator()
    dex_shared = [f"DEX_PART_{i}" for i in range(10)]
    s1 = _make_sample("1", dex=dex_shared, signers=["SIGNER_1"], firebase=["fb1"])
    s2 = _make_sample("2", dex=dex_shared, signers=["SIGNER_2"], firebase=["fb2"])

    res = calc.compare(s1, s2)
    assert res.dex_similarity == 1.0
    assert any("dex similarity" in r for r in res.match_reasons)


# ---------------------------------------------------------------------------
# Test 6: Icon-Only Similarity Does Not Over-Link
# ---------------------------------------------------------------------------
def test_icon_only_similarity_does_not_overlink() -> None:
    calc = FraudDNASimilarityCalculator()
    # Same icon hash, but completely different package, signer, firebase, dex, behavior
    s1 = _make_sample("1", icon_phash="ffff0000ffff0000", signers=["SIG1"], firebase=["fb1"], dex=["d1"], behaviors=["MTH-SMS-001"])
    s2 = _make_sample("2", icon_phash="ffff0000ffff0000", signers=["SIG2"], firebase=["fb2"], dex=["d2"], behaviors=["MTH-RECON-001"])

    res = calc.compare(s1, s2)
    assert res.icon_similarity == 1.0
    # Overall score must remain low (< 0.20) because icon similarity is supporting only
    assert res.overall_similarity <= 0.15
    assert not res.signer_match
    assert not res.firebase_overlap


# ---------------------------------------------------------------------------
# Test 7: Optional Similarity Engine Unavailable Handled Gracefully
# ---------------------------------------------------------------------------
def test_optional_similarity_engine_graceful_handling() -> None:
    calc = FraudDNASimilarityCalculator()
    s1 = _make_sample("1")
    s2 = _make_sample("2")
    s1.dex_fuzzy_hash = None
    s2.dex_fuzzy_hash = None

    # Should compute without raising exceptions
    res = calc.compare(s1, s2)
    assert isinstance(res.overall_similarity, float)


# ---------------------------------------------------------------------------
# Test 8: Deterministic Campaign Assignment
# ---------------------------------------------------------------------------
def test_deterministic_campaign_assignment() -> None:
    correlator = CampaignCorrelator()

    # Sample A
    sA = _make_sample("1", firebase=["dropper-campaign-alpha"], signers=["SIGNER_ALPHA"])
    campA, relatedA = correlator.correlate(sA)
    assert campA is None  # First sample in corpus, no prior links

    # Sample B sharing Firebase project with A
    sB = _make_sample("2", firebase=["dropper-campaign-alpha"], signers=["SIGNER_BETA"])
    campB, relatedB = correlator.correlate(sB)
    assert campB is not None
    assert campB.campaign_id.startswith("CAMP-")
    assert sA.apk_sha256 in campB.member_sha256s
    assert sB.apk_sha256 in campB.member_sha256s

    # Sample C sharing signer with A
    sC = _make_sample("3", firebase=["other-fb"], signers=["SIGNER_ALPHA"])
    campC, relatedC = correlator.correlate(sC)
    assert campC is not None
    assert campC.campaign_id == campB.campaign_id
    assert sC.apk_sha256 in campC.member_sha256s


# ---------------------------------------------------------------------------
# Test 9: Related Sample Result Preserves Reasons
# ---------------------------------------------------------------------------
def test_related_sample_preserves_reasons() -> None:
    correlator = CampaignCorrelator()
    s1 = _make_sample("1", firebase=["c2-campaign-x"], signers=["SHARED_SIG"])
    s2 = _make_sample("2", firebase=["c2-campaign-x"], signers=["SHARED_SIG"])

    correlator.correlate(s1)
    _, related = correlator.correlate(s2)

    assert len(related) >= 1
    target = related[0]
    assert target.sha256 == s1.apk_sha256
    assert "same firebase project" in target.reasons
    assert "same signer certificate" in target.reasons


# ---------------------------------------------------------------------------
# Test 10: Performance for Prototype Corpus
# ---------------------------------------------------------------------------
def test_corpus_matching_performance() -> None:
    correlator = CampaignCorrelator()

    # Pre-populate corpus with 30 samples
    for i in range(30):
        s = _make_sample(
            str(i % 10),
            pkg=f"com.fake.bank.{i}",
            signers=[f"SIGNER_{i % 5}"],
            firebase=[f"fb-{i % 3}"],
        )
        correlator.correlate(s)

    # Measure matching speed for 31st sample
    target = _make_sample("9", pkg="com.fake.bank.target", signers=["SIGNER_2"], firebase=["fb-1"])
    start = time.perf_counter()
    camp, related = correlator.correlate(target)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.10  # Must complete in under 100ms
    assert len(related) > 0
