from __future__ import annotations

import base64
import random
import urllib.parse
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class MarkerType(str, Enum):
    OTP = "OTP"
    USERNAME = "USERNAME"
    PASSWORD = "PASSWORD"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    CARD_REFERENCE = "CARD_REFERENCE"


class SyntheticMarker(BaseModel):
    """Represents an isolated, uniquely generated safe synthetic banking marker."""

    model_config = ConfigDict(extra="forbid")

    marker_id: str = Field(pattern=r"^M\d{3}$")
    marker_type: MarkerType
    value: str = Field(min_length=6, max_length=100)
    created_at_ms: int = Field(ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_transformations(self) -> dict[str, str]:
        """Calculates deterministic safe transformations for payload tracing."""
        raw_bytes = self.value.encode("utf-8")
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        hex_str = raw_bytes.hex()
        url_enc = urllib.parse.quote_plus(self.value)
        return {
            "raw": self.value,
            "utf8": self.value,
            "base64": b64,
            "base64_url": b64.rstrip("="),
            "hex": hex_str,
            "hex_upper": hex_str.upper(),
            "url_encoded": url_enc,
        }

    def matches_payload(self, text: str) -> tuple[bool, str | None]:
        """Checks if this marker or any of its deterministic transformations appear in text."""
        if not text or not isinstance(text, str):
            return False, None
        transforms = self.get_transformations()
        for transform_name, transform_val in transforms.items():
            if transform_val in text:
                return True, transform_name
        return False, None


class SyntheticMarkerManager:
    """Manages generation, cataloging, and retrieval of synthetic test markers."""

    def __init__(self) -> None:
        self._markers: dict[str, SyntheticMarker] = {}
        self._counter = 1

    def create_otp_marker(self, custom_value: str | None = None) -> SyntheticMarker:
        """Generates a clearly synthetic OTP marker safe for sandbox delivery."""
        marker_id = f"M{self._counter:03d}"
        self._counter += 1
        val = custom_value or f"DS-TEST-OTP-{random.randint(100000, 999999)}"
        marker = SyntheticMarker(
            marker_id=marker_id,
            marker_type=MarkerType.OTP,
            value=val,
            created_at_ms=0,
            metadata={"purpose": "synthetic_sms_otp_delivery"},
        )
        self._markers[marker_id] = marker
        return marker

    def create_marker(
        self,
        marker_type: MarkerType,
        custom_value: str | None = None,
    ) -> SyntheticMarker:
        marker_id = f"M{self._counter:03d}"
        self._counter += 1
        prefix = f"DS-TEST-{marker_type.value}"
        val = custom_value or f"{prefix}-{random.randint(100000, 999999)}"
        marker = SyntheticMarker(
            marker_id=marker_id,
            marker_type=marker_type,
            value=val,
            created_at_ms=0,
            metadata={"purpose": f"synthetic_{marker_type.value.lower()}_injection"},
        )
        self._markers[marker_id] = marker
        return marker

    def get_marker(self, marker_id: str) -> SyntheticMarker | None:
        return self._markers.get(marker_id)

    def all_markers(self) -> list[SyntheticMarker]:
        return list(self._markers.values())
