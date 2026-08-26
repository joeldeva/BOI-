from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from fraudshield.deceptiscope.payloads.payload_models import (
    PayloadAnalysisStatus,
    PayloadType,
    RecoveredPayload,
)


logger = logging.getLogger(__name__)

MAX_RECOVERED_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit
MAX_RECOVERED_PAYLOAD_COUNT = 5
MAX_RECURSION_DEPTH = 1

DEX_MAGICS = (
    b"dex\n035\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
)
ZIP_MAGIC = b"PK\x03\x04"


class PayloadRecoveryManager:
    """Manages validation, bounding, and extraction of dynamically loaded DEX/JAR payloads."""

    def __init__(
        self,
        max_payload_size: int = MAX_RECOVERED_PAYLOAD_SIZE,
        max_payload_count: int = MAX_RECOVERED_PAYLOAD_COUNT,
        max_recursion_depth: int = MAX_RECURSION_DEPTH,
    ) -> None:
        self.max_payload_size = max_payload_size
        self.max_payload_count = max_payload_count
        self.max_recursion_depth = max_recursion_depth
        self._recovered_count = 0

    def validate_magic(self, raw_bytes: bytes) -> tuple[bool, PayloadType, str | None]:
        """Validates payload magic bytes (DEX or ZIP/JAR)."""
        if len(raw_bytes) < 8:
            return False, PayloadType.UNKNOWN, "Payload is too short to contain valid magic"

        if raw_bytes[:8] in DEX_MAGICS or raw_bytes[:4] == b"dex\n":
            return True, PayloadType.DEX, None
        if raw_bytes[:4] == ZIP_MAGIC:
            return True, PayloadType.JAR, None

        return False, PayloadType.UNKNOWN, f"Invalid magic header: {raw_bytes[:8]!r}"

    def process_payload_bytes(
        self,
        *,
        parent_sha256: str,
        raw_bytes: bytes,
        source: str = "MEMORY_DUMP",
        loader: str = "InMemoryDexClassLoader",
        runtime_evidence_id: str | None = None,
        recursion_depth: int = 0,
    ) -> tuple[RecoveredPayload, bytes | None]:
        """
        Validates, bounds, and registers recovered payload bytes.
        Returns a RecoveredPayload descriptor and the raw bytes (or None if invalid/oversized).
        """
        if recursion_depth >= self.max_recursion_depth:
            # Enforce strict recursion depth limit to prevent infinite analysis loops
            payload_id = f"PAYLOAD-{self._recovered_count + 1:03d}"
            return (
                RecoveredPayload(
                    payload_id=payload_id,
                    parent_sample_sha256=parent_sha256,
                    sha256="0" * 64,
                    payload_type=PayloadType.UNKNOWN,
                    size_bytes=len(raw_bytes),
                    source=source,
                    loader=loader,
                    runtime_evidence_id=runtime_evidence_id,
                    analysis_status=PayloadAnalysisStatus.UNAVAILABLE,
                    metadata={"reason": "Maximum recursion depth reached"},
                ),
                None,
            )

        if self._recovered_count >= self.max_payload_count:
            payload_id = f"PAYLOAD-{self._recovered_count + 1:03d}"
            return (
                RecoveredPayload(
                    payload_id=payload_id,
                    parent_sample_sha256=parent_sha256,
                    sha256="0" * 64,
                    payload_type=PayloadType.UNKNOWN,
                    size_bytes=len(raw_bytes),
                    source=source,
                    loader=loader,
                    runtime_evidence_id=runtime_evidence_id,
                    analysis_status=PayloadAnalysisStatus.UNAVAILABLE,
                    metadata={"reason": "Maximum recovered payload count exceeded"},
                ),
                None,
            )

        self._recovered_count += 1
        payload_id = f"PAYLOAD-{self._recovered_count:03d}"

        # 1. Size Validation
        if len(raw_bytes) > self.max_payload_size:
            return (
                RecoveredPayload(
                    payload_id=payload_id,
                    parent_sample_sha256=parent_sha256,
                    sha256=hashlib.sha256(raw_bytes).hexdigest(),
                    payload_type=PayloadType.UNKNOWN,
                    size_bytes=len(raw_bytes),
                    source=source,
                    loader=loader,
                    runtime_evidence_id=runtime_evidence_id,
                    analysis_status=PayloadAnalysisStatus.OVERSIZED,
                    metadata={"max_allowed_bytes": self.max_payload_size},
                ),
                None,
            )

        # 2. Magic Header Validation
        valid, ptype, err = self.validate_magic(raw_bytes)
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        if not valid:
            return (
                RecoveredPayload(
                    payload_id=payload_id,
                    parent_sample_sha256=parent_sha256,
                    sha256=sha256_hash,
                    payload_type=PayloadType.UNKNOWN,
                    size_bytes=len(raw_bytes),
                    source=source,
                    loader=loader,
                    runtime_evidence_id=runtime_evidence_id,
                    analysis_status=PayloadAnalysisStatus.INVALID_MAGIC,
                    metadata={"error": err},
                ),
                None,
            )

        # Valid payload ready for recursive static analysis
        return (
            RecoveredPayload(
                payload_id=payload_id,
                parent_sample_sha256=parent_sha256,
                sha256=sha256_hash,
                payload_type=ptype,
                size_bytes=len(raw_bytes),
                source=source,
                loader=loader,
                runtime_evidence_id=runtime_evidence_id,
                analysis_status=PayloadAnalysisStatus.ANALYZED,
            ),
            raw_bytes,
        )

    def recover_from_file_path(
        self,
        *,
        parent_sha256: str,
        file_path: Path,
        loader: str = "DexClassLoader",
        runtime_evidence_id: str | None = None,
        recursion_depth: int = 0,
    ) -> tuple[RecoveredPayload, bytes | None]:
        """Safely reads and processes payload from a local recovered file path."""
        if not file_path.exists() or not file_path.is_file():
            payload_id = f"PAYLOAD-{self._recovered_count + 1:03d}"
            return (
                RecoveredPayload(
                    payload_id=payload_id,
                    parent_sample_sha256=parent_sha256,
                    sha256="0" * 64,
                    payload_type=PayloadType.UNKNOWN,
                    size_bytes=0,
                    source="FILE_RECOVERED",
                    loader=loader,
                    runtime_evidence_id=runtime_evidence_id,
                    analysis_status=PayloadAnalysisStatus.UNAVAILABLE,
                    metadata={"error": "File does not exist or is not a regular file"},
                ),
                None,
            )

        try:
            raw_bytes = file_path.read_bytes()
            return self.process_payload_bytes(
                parent_sha256=parent_sha256,
                raw_bytes=raw_bytes,
                source="FILE_RECOVERED",
                loader=loader,
                runtime_evidence_id=runtime_evidence_id,
                recursion_depth=recursion_depth,
            )
        except Exception as exc:
            payload_id = f"PAYLOAD-{self._recovered_count + 1:03d}"
            return (
                RecoveredPayload(
                    payload_id=payload_id,
                    parent_sample_sha256=parent_sha256,
                    sha256="0" * 64,
                    payload_type=PayloadType.UNKNOWN,
                    size_bytes=0,
                    source="FILE_RECOVERED",
                    loader=loader,
                    runtime_evidence_id=runtime_evidence_id,
                    analysis_status=PayloadAnalysisStatus.FAILED,
                    metadata={"error": str(exc)},
                ),
                None,
            )
