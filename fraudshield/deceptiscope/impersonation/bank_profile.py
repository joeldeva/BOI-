from __future__ import annotations

import logging
import re
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_SHA256_RE = re.compile(r"^[0-9a-fA-F:]{64,95}$")  # plain hex or colon-separated
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$")
_PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")


def _validate_signer_fingerprint(value: str) -> bool:
    """Accept SHA-256 in plain hex (64 chars) or colon-separated hex (95 chars)."""
    stripped = value.replace(":", "").replace(" ", "")
    return len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped)


def _validate_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value)) and "." in value


def _validate_package(value: str) -> bool:
    return bool(_PACKAGE_RE.match(value))


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Strict field validators — reject malformed authoritative values
    # ------------------------------------------------------------------

    @field_validator("trusted_signer_fingerprints")
    @classmethod
    def validate_signers(cls, v: list[str]) -> list[str]:
        for fp in v:
            if not _validate_signer_fingerprint(fp):
                raise ValueError(
                    f"Invalid signer fingerprint {fp!r}: must be a 64-char hex SHA-256 "
                    "(plain or colon-separated). Do not invent fingerprints."
                )
        return v

    @field_validator("official_domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        for d in v:
            if not _validate_domain(d):
                raise ValueError(
                    f"Invalid official domain {d!r}: must be a valid FQDN without scheme or path."
                )
        return v

    @field_validator("official_packages")
    @classmethod
    def validate_packages(cls, v: list[str]) -> list[str]:
        for p in v:
            if not _validate_package(p):
                raise ValueError(
                    f"Invalid official package {p!r}: must be a valid Android package name "
                    "(e.g. com.bank.app)."
                )
        return v

    # ------------------------------------------------------------------
    # Reference-quality status properties
    # ------------------------------------------------------------------

    @property
    def signer_reference_status(self) -> str:
        """NOT_CONFIGURED when no trusted fingerprints have been loaded."""
        return "CONFIGURED" if self.trusted_signer_fingerprints else "NOT_CONFIGURED"

    @property
    def icon_reference_status(self) -> str:
        """NOT_CONFIGURED when no reference icon phash has been loaded."""
        return "CONFIGURED" if self.reference_icon_phash else "NOT_CONFIGURED"


# ---------------------------------------------------------------------------
# Manager — no built-in fallback profiles
# ---------------------------------------------------------------------------

class BankProfileManager:
    """
    Manages loading and querying official bank reference profiles.

    Safety invariant: if the profiles directory is absent or empty this manager
    returns an empty profile list.  The caller must handle the NOT_CONFIGURED
    state explicitly — no synthetic profile is created in code.
    """

    def __init__(self, profiles_dir: Path | None = None) -> None:
        self.profiles_dir = (
            profiles_dir
            or Path(__file__).resolve().parent.parent.parent.parent / "config" / "bank_profiles"
        )
        self._profiles: dict[str, BankProfile] = {}
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Load all YAML profiles from the configured directory."""
        if not self.profiles_dir.exists() or not self.profiles_dir.is_dir():
            logger.warning(
                "Bank profile directory not found: %s — "
                "impersonation analysis will report NOT_CONFIGURED. "
                "Place YAML profiles in config/bank_profiles/ to enable.",
                self.profiles_dir,
            )
            return

        loaded = 0
        for yaml_file in self.profiles_dir.glob("*.yaml"):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    raise ValueError("YAML root must be a mapping")
                if "bank_id" not in raw:
                    raise ValueError("Missing required field 'bank_id'")
                profile = BankProfile(**raw)
                self._profiles[profile.bank_id] = profile
                loaded += 1
            except Exception as exc:
                # Surface every parse / validation error — do not silently swallow
                logger.error(
                    "CONFIGURATION ERROR: Failed to load bank profile %s: %s — "
                    "This profile will be skipped. Fix the YAML before deployment.",
                    yaml_file,
                    exc,
                )
                raise ValueError(
                    f"Bank profile {yaml_file.name} is invalid and cannot be loaded: {exc}"
                ) from exc

        if loaded == 0:
            logger.warning(
                "No bank profiles were loaded from %s — "
                "impersonation analysis will report NOT_CONFIGURED.",
                self.profiles_dir,
            )

    def get_profile(self, bank_id: str) -> BankProfile | None:
        return self._profiles.get(bank_id)

    def all_profiles(self) -> list[BankProfile]:
        return list(self._profiles.values())

    def is_configured(self) -> bool:
        """True only when at least one profile has been successfully loaded."""
        return bool(self._profiles)

    def register_profile(self, profile: BankProfile) -> None:
        self._profiles[profile.bank_id] = profile
