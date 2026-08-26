from __future__ import annotations

import hashlib
from pathlib import Path

from fraudshield.core.config import Settings
from fraudshield.deceptiscope.experiments import ExperimentPlanner
from fraudshield.deceptiscope.investigation import EvidenceNormalizer
from fraudshield.deceptiscope.payloads import (
    PayloadAnalysisStatus,
    PayloadAnalyzer,
    PayloadRecoveryManager,
    PayloadType,
)


# Minimal synthetic DEX header (starts with standard magic dex\n035\0)
DEX_HEADER_MAGIC = b"dex\n035\x00"
MINIMAL_SYNTHETIC_DEX = DEX_HEADER_MAGIC + b"\x00" * 104
PARENT_SAMPLE_SHA256 = "a" * 64


# ---------------------------------------------------------------------------
# Test 1: Valid DEX Accepted
# ---------------------------------------------------------------------------
def test_valid_dex_accepted() -> None:
    manager = PayloadRecoveryManager()
    payload, raw = manager.process_payload_bytes(
        parent_sha256=PARENT_SAMPLE_SHA256,
        raw_bytes=MINIMAL_SYNTHETIC_DEX,
        source="MEMORY_DUMP",
        loader="InMemoryDexClassLoader",
        runtime_evidence_id="R041",
    )

    assert payload.payload_id == "PAYLOAD-001"
    assert payload.payload_type == PayloadType.DEX
    assert payload.analysis_status == PayloadAnalysisStatus.ANALYZED
    assert payload.parent_sample_sha256 == PARENT_SAMPLE_SHA256
    assert payload.runtime_evidence_id == "R041"
    assert raw == MINIMAL_SYNTHETIC_DEX


# ---------------------------------------------------------------------------
# Test 2: Bad Magic Rejected
# ---------------------------------------------------------------------------
def test_bad_magic_rejected() -> None:
    manager = PayloadRecoveryManager()
    corrupt_bytes = b"CORRUPT_MAGIC_NOT_A_DEX_FILE_CONTENT"
    payload, raw = manager.process_payload_bytes(
        parent_sha256=PARENT_SAMPLE_SHA256,
        raw_bytes=corrupt_bytes,
    )

    assert payload.analysis_status == PayloadAnalysisStatus.INVALID_MAGIC
    assert payload.payload_type == PayloadType.UNKNOWN
    assert raw is None


# ---------------------------------------------------------------------------
# Test 3: Oversized Payload Rejected
# ---------------------------------------------------------------------------
def test_oversized_payload_rejected() -> None:
    # 1MB limit for testing
    manager = PayloadRecoveryManager(max_payload_size=1024)
    huge_bytes = DEX_HEADER_MAGIC + b"\x00" * 2000
    payload, raw = manager.process_payload_bytes(
        parent_sha256=PARENT_SAMPLE_SHA256,
        raw_bytes=huge_bytes,
    )

    assert payload.analysis_status == PayloadAnalysisStatus.OVERSIZED
    assert raw is None


# ---------------------------------------------------------------------------
# Test 4: Max Payload Count Enforced
# ---------------------------------------------------------------------------
def test_max_payload_count_enforced() -> None:
    manager = PayloadRecoveryManager(max_payload_count=2)

    p1, r1 = manager.process_payload_bytes(parent_sha256=PARENT_SAMPLE_SHA256, raw_bytes=MINIMAL_SYNTHETIC_DEX)
    assert p1.analysis_status == PayloadAnalysisStatus.ANALYZED
    assert r1 is not None

    p2, r2 = manager.process_payload_bytes(parent_sha256=PARENT_SAMPLE_SHA256, raw_bytes=MINIMAL_SYNTHETIC_DEX)
    assert p2.analysis_status == PayloadAnalysisStatus.ANALYZED
    assert r2 is not None

    # 3rd payload exceeds limit
    p3, r3 = manager.process_payload_bytes(parent_sha256=PARENT_SAMPLE_SHA256, raw_bytes=MINIMAL_SYNTHETIC_DEX)
    assert p3.analysis_status == PayloadAnalysisStatus.UNAVAILABLE
    assert "exceeded" in p3.metadata.get("reason", "")
    assert r3 is None


# ---------------------------------------------------------------------------
# Test 5: Path Not Supplied by AI
# ---------------------------------------------------------------------------
def test_path_not_supplied_by_ai() -> None:
    planner = ExperimentPlanner(Settings())
    injected_plan = [
        {
            "experiment_id": "EXP001",
            "hypothesis_id": "H001",
            "experiment_type": "DYNAMIC_CODE_LOAD_OBSERVATION",
            "objective": "Observe dynamic code loading",
            "expected_signal": "Signal",
            "priority": 8,
            "path": "/data/data/com.fakebank/payload.dex",  # Forbidden injected path
        }
    ]
    items, errors = planner.plan_from_payload(
        {"experiment_requests": injected_plan},
        hypotheses=[{"hypothesis_id": "H001"}],
    )
    assert len(items) == 0
    assert any("forbidden execution fields: path" in err for err in errors)


# ---------------------------------------------------------------------------
# Test 6: In-Memory Payload Normalized
# ---------------------------------------------------------------------------
def test_in_memory_payload_normalized() -> None:
    manager = PayloadRecoveryManager()
    payload, raw = manager.process_payload_bytes(
        parent_sha256=PARENT_SAMPLE_SHA256,
        raw_bytes=MINIMAL_SYNTHETIC_DEX,
        source="MEMORY_DUMP",
        loader="InMemoryDexClassLoader",
        runtime_evidence_id="R050",
    )

    assert payload.source == "MEMORY_DUMP"
    assert payload.loader == "InMemoryDexClassLoader"
    assert payload.size_bytes == len(MINIMAL_SYNTHETIC_DEX)
    assert payload.sha256 == hashlib.sha256(MINIMAL_SYNTHETIC_DEX).hexdigest()


# ---------------------------------------------------------------------------
# Test 7: Recursive Static Analysis Runs on Recovered DEX
# ---------------------------------------------------------------------------
def test_recursive_static_analysis_runs(tmp_path: Path) -> None:
    manager = PayloadRecoveryManager()
    payload, raw = manager.process_payload_bytes(
        parent_sha256=PARENT_SAMPLE_SHA256,
        raw_bytes=MINIMAL_SYNTHETIC_DEX,
        source="FILE_RECOVERED",
        loader="DexClassLoader",
    )

    analyzer = PayloadAnalyzer()
    evidence_items = analyzer.analyze_payload(payload, raw)

    # Analyzed without crashing, status is ANALYZED
    assert payload.analysis_status == PayloadAnalysisStatus.ANALYZED
    assert isinstance(evidence_items, list)
    assert isinstance(payload.extracted_capabilities, list)


# ---------------------------------------------------------------------------
# Test 8: Payload Evidence Linked to Parent Sample
# ---------------------------------------------------------------------------
def test_payload_evidence_linked_to_parent() -> None:
    normalizer = EvidenceNormalizer()
    findings = {
        "permissions": {"requested": []},
        "components": {},
        "recovered_payloads": [
            {
                "payload_id": "PAYLOAD-001",
                "parent_sample_sha256": PARENT_SAMPLE_SHA256,
                "sha256": "b" * 64,
                "payload_type": "DEX",
                "size_bytes": 1024,
                "source": "MEMORY_DUMP",
                "loader": "InMemoryDexClassLoader",
                "analysis_status": "ANALYZED",
                "extracted_capabilities": ["SMS_INTERCEPTION"],
                "method_level_evidence": [
                    {
                        "signature_id": "MTH-SMS-001",
                        "title": "SMS Message Ingestion & PDU Parsing",
                        "category": "SMS / CREDENTIAL THEFT",
                        "class_name": "com.payload.HiddenReceiver",
                        "method_name": "onReceive",
                        "call_site": "SmsMessage->createFromPdu",
                        "code_ownership": "APPLICATION_CODE",
                    }
                ],
            }
        ],
    }

    evidence = normalizer.normalize(findings)
    payload_ev = [ev for ev in evidence if ev.phase == "PAYLOAD"]

    assert len(payload_ev) == 1
    assert payload_ev[0].source == "recovered-payload"
    assert payload_ev[0].source_artifact == "PAYLOAD-001"
    assert payload_ev[0].metadata["parent_sample_sha256"] == PARENT_SAMPLE_SHA256
    assert payload_ev[0].metadata["loader"] == "InMemoryDexClassLoader"


# ---------------------------------------------------------------------------
# Test 9: Failure to Recover Payload Does Not Kill Analysis
# ---------------------------------------------------------------------------
def test_recovery_failure_graceful_handling() -> None:
    manager = PayloadRecoveryManager()
    nonexistent = Path("/nonexistent/path/to/missing.dex")
    payload, raw = manager.recover_from_file_path(
        parent_sha256=PARENT_SAMPLE_SHA256,
        file_path=nonexistent,
    )

    assert payload.analysis_status == PayloadAnalysisStatus.UNAVAILABLE
    assert raw is None


# ---------------------------------------------------------------------------
# Test 10: Recursion Depth Strictly Enforced (MAX_RECURSION_DEPTH = 1)
# ---------------------------------------------------------------------------
def test_recursion_depth_enforced() -> None:
    manager = PayloadRecoveryManager(max_recursion_depth=1)

    # Depth 0: Allowed
    p0, r0 = manager.process_payload_bytes(
        parent_sha256=PARENT_SAMPLE_SHA256,
        raw_bytes=MINIMAL_SYNTHETIC_DEX,
        recursion_depth=0,
    )
    assert p0.analysis_status == PayloadAnalysisStatus.ANALYZED
    assert r0 is not None

    # Depth 1: Reached max depth limit -> rejected
    p1, r1 = manager.process_payload_bytes(
        parent_sha256=p0.sha256,
        raw_bytes=MINIMAL_SYNTHETIC_DEX,
        recursion_depth=1,
    )
    assert p1.analysis_status == PayloadAnalysisStatus.UNAVAILABLE
    assert "Maximum recursion depth reached" in p1.metadata.get("reason", "")
    assert r1 is None
