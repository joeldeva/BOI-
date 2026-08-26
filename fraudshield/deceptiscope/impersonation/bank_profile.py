from __future__ import annotations

import logging
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
import yaml


logger = logging.getLogger(__name__)


class BankProfile(BaseModel):
    """Reference profile for an official banking institution."""

    model_config = ConfigDict(extra="forbid")

    bank_id: str
    official_names: list[str]
    known_abbreviations: list[str] = Field(default_factory=list)
    official_domains: list[str] = Field(default_factory=list)
    official_packages: list[str] = Field(default_factory=list)
    trusted_signer_fingerprints: list[str] = Field(default_factory=list)
    reference_icon_assets: list[str] = Field(default_factory=list)
    reference_icon_phash: str | None = None


class BankProfileManager:
    """Manages loading and querying official bank reference profiles."""

    def __init__(self, profiles_dir: Path | None = None) -> None:
        self.profiles_dir = profiles_dir or Path(__file__).resolve().parent.parent.parent.parent / "config" / "bank_profiles"
        self._profiles: dict[str, BankProfile] = {}
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Loads all YAML profiles from directory."""
        if not self.profiles_dir.exists() or not self.profiles_dir.is_dir():
            # Fallback default Bank of India profile in code
            boi = BankProfile(
                bank_id="bank_of_india",
                official_names=["Bank of India", "BOI", "BOI Mobile", "BOI Omni Neo"],
                known_abbreviations=["BOI", "BKID"],
                official_domains=["bankofindia.co.in", "bankofindia.com", "boi.co.in"],
                official_packages=["com.boi.mobile", "com.bankofindia.omni", "com.boi.retail"],
                trusted_signer_fingerprints=[],
                reference_icon_phash=None,
            )
            self._profiles[boi.bank_id] = boi
            return

        for yaml_file in self.profiles_dir.glob("*.yaml"):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "bank_id" in data:
                    profile = BankProfile(**data)
                    self._profiles[profile.bank_id] = profile
            except Exception as exc:
                logger.warning("Failed to parse bank profile %s: %s", yaml_file, exc)

        if "bank_of_india" not in self._profiles:
            boi = BankProfile(
                bank_id="bank_of_india",
                official_names=["Bank of India", "BOI", "BOI Mobile", "BOI Omni Neo"],
                known_abbreviations=["BOI", "BKID"],
                official_domains=["bankofindia.co.in", "bankofindia.com", "boi.co.in"],
                official_packages=["com.boi.mobile", "com.bankofindia.omni", "com.boi.retail"],
                trusted_signer_fingerprints=[],
                reference_icon_phash=None,
            )
            self._profiles[boi.bank_id] = boi

    def get_profile(self, bank_id: str) -> BankProfile | None:
        return self._profiles.get(bank_id)

    def all_profiles(self) -> list[BankProfile]:
        return list(self._profiles.values())

    def register_profile(self, profile: BankProfile) -> None:
        self._profiles[profile.bank_id] = profile
