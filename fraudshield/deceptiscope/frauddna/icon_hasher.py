from __future__ import annotations

import io
import logging
from typing import BinaryIO

logger = logging.getLogger(__name__)


class IconHasher:
    """
    Computes deterministic perceptual hashes for APK launcher icons.
    
    Security Invariant:
    Icon similarity is a supporting signal only and must NEVER independently declare an app malicious
    or automatically merge unrelated campaigns.
    """

    @staticmethod
    def compute_dhash(image_data: bytes | BinaryIO) -> str | None:
        """
        Computes 64-bit difference hash (dHash) as a 16-character hexadecimal string.
        Resilient to minor icon compression, resizing, and color adjustments.
        """
        if not image_data:
            return None

        try:
            from PIL import Image

            if isinstance(image_data, bytes):
                img = Image.open(io.BytesIO(image_data))
            else:
                img = Image.open(image_data)

            # Convert to grayscale and resize to 9x8 (72 pixels)
            img = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
            pixels = list(img.getdata())

            # Compare adjacent pixels horizontally across each row
            diff: list[bool] = []
            for row in range(8):
                row_pixels = pixels[row * 9 : (row + 1) * 9]
                for col in range(8):
                    diff.append(row_pixels[col] > row_pixels[col + 1])

            # Convert 64 booleans into 16-character hex string
            decimal_value = 0
            for index, bit in enumerate(diff):
                if bit:
                    decimal_value |= 1 << index

            return f"{decimal_value:016x}"
        except Exception as exc:
            logger.debug("Failed to calculate icon dHash via PIL: %s", exc)
            return None

    @staticmethod
    def hamming_distance(hash1: str, hash2: str) -> int:
        """Calculates the bitwise Hamming distance between two 16-hex perceptual hashes."""
        if not hash1 or not hash2 or len(hash1) != 16 or len(hash2) != 16:
            return 64

        try:
            val1 = int(hash1, 16)
            val2 = int(hash2, 16)
            xor_val = val1 ^ val2
            return xor_val.bit_count()
        except ValueError:
            return 64

    @classmethod
    def similarity(cls, hash1: str | None, hash2: str | None) -> float | None:
        """
        Returns normalized similarity score in range [0.0, 1.0].
        Returns None if either hash is missing.
        """
        if not hash1 or not hash2:
            return None

        distance = cls.hamming_distance(hash1, hash2)
        # Distance <= 10 is considered visually very similar in 64-bit dHash
        return max(0.0, min(1.0, 1.0 - (distance / 64.0)))
