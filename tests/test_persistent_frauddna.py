from __future__ import annotations

import concurrent.futures
from pathlib import Path

from fraudshield.core.config import Settings
from fraudshield.core.database import Database
from fraudshield.deceptiscope.frauddna import (
    CampaignCorrelator,
    FraudDNAFingerprint,
    compute_app_identity,
)
from fraudshield.services.container import ServiceContainer


def _make_fp(
    sha_suffix: str = "1",
    pkg: str = "com.fake.bank",
    signers: list[str] | None = None,
    dex: list[str] | None = None,
    firebase: list[str] | None = None,
    payloads: list[str] | None = None,
    behaviors: list[str] | None = None,
    icon_phash: str | None = None,
    app_label: str = "Fake Bank",
) -> FraudDNAFingerprint:
    apk_sha = f"{sha_suffix * 64}"[:64]
    signer_list = signers or ["SIGNER_A_SHA256"]
    app_id = compute_app_identity(pkg, signer_list)

    return FraudDNAFingerprint(
        apk_sha256=apk_sha,
        app_identity=app_id,
        package_name=pkg,
        app_label=app_label,
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
# Test 1: Fingerprint persists across ServiceContainer restart
# ---------------------------------------------------------------------------
def test_fingerprint_persists_across_container_restart(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container1 = ServiceContainer.build(settings)
    fp1 = _make_fp("a", pkg="com.test.alpha", app_label="Alpha Bank")
    container1.frauddna.save_fingerprint(fp1)

    # Simulate full container restart
    container2 = ServiceContainer.build(settings)
    loaded = container2.frauddna.get_fingerprint(fp1.apk_sha256)

    assert loaded is not None
    assert loaded.apk_sha256 == fp1.apk_sha256
    assert loaded.package_name == "com.test.alpha"
    assert loaded.app_label == "Alpha Bank"
    assert loaded.signer_fingerprints == fp1.signer_fingerprints


# ---------------------------------------------------------------------------
# Test 2: Related sample still found after restart
# ---------------------------------------------------------------------------
def test_related_sample_still_found_after_restart(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    # Process 1 stores sample A
    container1 = ServiceContainer.build(settings)
    correlator1 = CampaignCorrelator(repository=container1.frauddna)
    sA = _make_fp("a", pkg="com.malware.a", firebase=["shared-c2-project"])
    correlator1.correlate(sA)

    # Process 2 (after restart) receives sample B sharing the Firebase project
    container2 = ServiceContainer.build(settings)
    correlator2 = CampaignCorrelator(repository=container2.frauddna)
    sB = _make_fp("b", pkg="com.malware.b", firebase=["shared-c2-project"])
    campB, relatedB = correlator2.correlate(sB)

    assert len(relatedB) == 1
    assert relatedB[0].sha256 == sA.apk_sha256
    assert "same firebase project" in relatedB[0].reasons


# ---------------------------------------------------------------------------
# Test 3: Campaign survives restart
# ---------------------------------------------------------------------------
def test_campaign_survives_restart(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container1 = ServiceContainer.build(settings)
    correlator1 = CampaignCorrelator(repository=container1.frauddna)
    s1 = _make_fp("1", signers=["SIG_CAMPAIGN_X"])
    s2 = _make_fp("2", signers=["SIG_CAMPAIGN_X"])

    correlator1.correlate(s1)
    camp1, _ = correlator1.correlate(s2)
    assert camp1 is not None
    cid = camp1.campaign_id

    # Restart
    container2 = ServiceContainer.build(settings)
    correlator2 = CampaignCorrelator(repository=container2.frauddna)
    camp_loaded = correlator2.get_campaign(cid)

    assert camp_loaded is not None
    assert camp_loaded.campaign_id == cid
    assert s1.apk_sha256 in camp_loaded.member_sha256s
    assert s2.apk_sha256 in camp_loaded.member_sha256s


# ---------------------------------------------------------------------------
# Test 4: Two workers using same DB see same corpus
# ---------------------------------------------------------------------------
def test_two_workers_using_same_db_see_same_corpus(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    worker_a = ServiceContainer.build(settings)
    worker_b = ServiceContainer.build(settings)

    correlator_a = CampaignCorrelator(repository=worker_a.frauddna)
    correlator_b = CampaignCorrelator(repository=worker_b.frauddna)

    # Worker A processes sample 1
    s1 = _make_fp("1", pkg="com.trojan.bank1", firebase=["fb-worker-test"])
    correlator_a.correlate(s1)

    # Worker B processes sample 2
    s2 = _make_fp("2", pkg="com.trojan.bank2", firebase=["fb-worker-test"])
    camp_b, related_b = correlator_b.correlate(s2)

    assert camp_b is not None
    assert len(related_b) == 1
    assert related_b[0].sha256 == s1.apk_sha256

    # Both workers query campaign
    camp_from_a = correlator_a.get_campaign(camp_b.campaign_id)
    assert camp_from_a is not None
    assert set(camp_from_a.member_sha256s) == {s1.apk_sha256, s2.apk_sha256}


# ---------------------------------------------------------------------------
# Test 5: Duplicate sample does not duplicate fingerprint
# ---------------------------------------------------------------------------
def test_duplicate_sample_does_not_duplicate_fingerprint(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container = ServiceContainer.build(settings)
    s = _make_fp("1", app_label="Original Label")
    container.frauddna.save_fingerprint(s)

    # Save same SHA with updated app_label
    s_updated = _make_fp("1", app_label="Updated Label")
    container.frauddna.save_fingerprint(s_updated)

    fps = container.frauddna.list_fingerprints()
    assert len(fps) == 1
    assert fps[0].app_label == "Updated Label"


# ---------------------------------------------------------------------------
# Test 6: Concurrent correlation does not create duplicate memberships
# ---------------------------------------------------------------------------
def test_concurrent_correlation_does_not_create_duplicate_memberships(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container = ServiceContainer.build(settings)
    repo = container.frauddna

    # Create root sample
    root = _make_fp("0", signers=["CONCURRENT_SHARED_SIGNER"])
    CampaignCorrelator(repository=repo).correlate(root)

    samples = [_make_fp(str(i), signers=["CONCURRENT_SHARED_SIGNER"]) for i in range(1, 6)]

    def _worker_correlate(s: FraudDNAFingerprint) -> None:
        c = CampaignCorrelator(repository=repo)
        c.correlate(s)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(_worker_correlate, samples))

    # Verify no duplicate memberships in DB
    with container.db.connect() as conn:
        cursor = conn.execute(
            "SELECT campaign_id, apk_sha256, COUNT(*) as cnt FROM campaign_members GROUP BY campaign_id, apk_sha256 HAVING cnt > 1"
        )
        dups = cursor.fetchall()
        assert len(dups) == 0

    camps = repo.list_campaigns()
    assert len(camps) >= 1
    # Check total unique member count
    all_members = set()
    for c in camps:
        all_members.update(c.member_sha256s)
    assert len(all_members) == 6


# ---------------------------------------------------------------------------
# Test 7: Hard anchors persist
# ---------------------------------------------------------------------------
def test_hard_anchors_persist(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container = ServiceContainer.build(settings)
    correlator = CampaignCorrelator(repository=container.frauddna)

    # 4 hard anchors: Firebase, Signer, Payload Hash, High DEX similarity
    s1 = _make_fp(
        "1",
        firebase=["fb-hard-anchor"],
        signers=["SIG_HARD_ANCHOR"],
        payloads=["PAYLOAD_SHA_HEX"],
        dex=["DEX_PART_A", "DEX_PART_B"],
    )
    correlator.correlate(s1)

    # Reload from DB and verify all anchors present in fingerprint
    saved = container.frauddna.get_fingerprint(s1.apk_sha256)
    assert saved is not None
    assert saved.firebase_project_ids == ["fb-hard-anchor"]
    assert saved.signer_fingerprints == ["SIG_HARD_ANCHOR"]
    assert saved.recovered_payload_hashes == ["PAYLOAD_SHA_HEX"]
    assert saved.dex_fingerprints == ["DEX_PART_A", "DEX_PART_B"]


# ---------------------------------------------------------------------------
# Test 8: Icon/package alone cannot create campaign
# ---------------------------------------------------------------------------
def test_icon_package_alone_cannot_create_campaign(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container = ServiceContainer.build(settings)
    correlator = CampaignCorrelator(repository=container.frauddna)

    # Two samples with same icon phash and similar package name, but completely different signer, firebase, dex, behavior
    s1 = _make_fp("1", pkg="com.bank.fake1", icon_phash="1111222233334444", signers=["SIG_1"], firebase=["fb1"], dex=["d1"], behaviors=["B1"])
    s2 = _make_fp("2", pkg="com.bank.fake2", icon_phash="1111222233334444", signers=["SIG_2"], firebase=["fb2"], dex=["d2"], behaviors=["B2"])

    camp1, _ = correlator.correlate(s1)
    camp2, related2 = correlator.correlate(s2)

    assert camp1 is None
    assert camp2 is None
    # No campaign was created
    camps = container.frauddna.list_campaigns()
    assert len(camps) == 0


# ---------------------------------------------------------------------------
# Test 9: Historical analysis can resolve persisted campaign
# ---------------------------------------------------------------------------
def test_historical_analysis_can_resolve_persisted_campaign(tmp_path: Path) -> None:
    db_file = tmp_path / "test_frauddna.db"
    settings = Settings(database_url=f"sqlite:///{db_file.as_posix()}")

    container = ServiceContainer.build(settings)
    correlator = CampaignCorrelator(repository=container.frauddna)

    # Create real analysis records first
    rec1 = container.analyses.create(
        file_name="fake1.apk",
        sha256="1" * 64,
        size_bytes=1024,
        category="banking",
        data_origin="uploaded",
    )
    rec2 = container.analyses.create(
        file_name="fake2.apk",
        sha256="2" * 64,
        size_bytes=1024,
        category="banking",
        data_origin="uploaded",
    )

    s1 = _make_fp("1", firebase=["hist-campaign-fb"])
    s2 = _make_fp("2", firebase=["hist-campaign-fb"])

    correlator.correlate(s1, analysis_id=rec1["id"])
    camp, _ = correlator.correlate(s2, analysis_id=rec2["id"])

    assert camp is not None
    cid = camp.campaign_id

    # Query campaign for historical sample 1
    found_camp = container.frauddna.get_campaign_for_sample(s1.apk_sha256)
    assert found_camp is not None
    assert found_camp.campaign_id == cid


# ---------------------------------------------------------------------------
# Test 10: Database migration works on SQLite tests
# ---------------------------------------------------------------------------
def test_database_migration_works_on_sqlite(tmp_path: Path) -> None:
    db_file = tmp_path / "test_migration.db"
    db = Database(f"sqlite:///{db_file.as_posix()}")
    db.initialize()

    with db.connect() as conn:
        # Check all tables created by migrations including migration 7
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r["name"] for r in cursor.fetchall()}
        assert "analyses" in tables
        assert "indicators" in tables
        assert "audit_events" in tables
        assert "jobs" in tables
        assert "frauddna_fingerprints" in tables
        assert "campaigns" in tables
        assert "campaign_members" in tables
