from __future__ import annotations

import re
from typing import Sequence
from fraudshield.deceptiscope.lineage.markers import SyntheticMarker


# Patterns that might look like sensitive authentication tokens or credentials
TOKEN_PATTERNS = re.compile(
    r"(bearer\s+[A-Za-z0-9_\-\.]{20,}|basic\s+[A-Za-z0-9+/=]{16,}|password=([^\s&]+)|secret=([^\s&]+))",
    re.IGNORECASE,
)


def redact_sensitive_payload(
    text: str,
    known_markers: Sequence[SyntheticMarker] = (),
    max_preview_len: int = 40,
) -> str:
    """
    Sanitizes string data before persisting evidence or display.
    - Preserves known synthetic test markers verbatim.
    - Redacts potential real secrets and truncates large non-synthetic data blocks.
    """
    if not text or not isinstance(text, str):
        return ""

    # Check if text contains a known synthetic marker
    for marker in known_markers:
        matched, _ = marker.matches_payload(text)
        if matched:
            # Synthetic marker present: keep safe preview with marker highlighted
            if len(text) <= 120:
                return text
            return f"{text[:max_preview_len]}... [Synthetic Marker {marker.marker_id} Present]"

    if "DS-TEST-" in text or "BOI-TEST-" in text:
        if len(text) <= 120:
            return text
        return f"{text[:max_preview_len]}... [Synthetic Test Marker Present]"

    # If no synthetic marker, redact any tokens and truncate to bounded preview
    redacted = TOKEN_PATTERNS.sub("[REDACTED_CREDENTIAL]", text)
    if len(redacted) > max_preview_len:
        return f"{redacted[:max_preview_len]}... (length={len(text)})"
    return redacted
