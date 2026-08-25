from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qs, urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(PROJECT_ROOT / ".env", override=False)
    except ImportError:
        return


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int, minimum: int = 1) -> int:
    if value is None or not value.strip():
        return default
    return max(minimum, int(value))


def _csv(value: str | None, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if not value:
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str = "FraudShield DeceptiScope"
    version: str = "3.0.0"
    environment: str = "development"
    debug: bool = False
    data_dir: Path = PROJECT_ROOT / "runtime"
    database_path: Path = PROJECT_ROOT / "runtime" / "fraudshield.db"
    database_url: str = ""
    database_pool_min_size: int = 2
    database_pool_max_size: int = 10
    upload_dir: Path = PROJECT_ROOT / "runtime" / "uploads"
    report_dir: Path = PROJECT_ROOT / "runtime" / "reports"
    storage_backend: str = "local"
    s3_bucket: str = ""
    s3_prefix: str = "fraudshield"
    s3_region: str = "ap-south-1"
    s3_endpoint_url: str = ""
    s3_kms_key_id: str = ""
    baseline_path: Path = PACKAGE_ROOT / "resources" / "category_baselines.json"
    yara_rules_path: Path = PACKAGE_ROOT / "resources" / "yara" / "deceptiscope_banking.yar"
    quark_rules_dir: Path = PROJECT_ROOT / "runtime" / "quark-rules"
    max_apk_bytes: int = 75 * 1024 * 1024
    max_zip_entries: int = 20_000
    max_zip_uncompressed_bytes: int = 500 * 1024 * 1024
    max_concurrent_apk_analyses: int = 2
    engine_timeout_seconds: int = 120
    max_engine_output_bytes: int = 2 * 1024 * 1024
    apkid_enabled: bool = True
    yara_enabled: bool = True
    signature_verification_enabled: bool = True
    similarity_enabled: bool = True
    quark_enabled: bool = False
    quark_max_rules: int = 300
    apksigner_path: str = "apksigner"
    mobsf_enabled: bool = False
    mobsf_url: str = ""
    mobsf_api_key: str = ""
    mobsf_allow_binary_transfer: bool = False
    reputation_enabled: bool = False
    allow_external_reputation_in_production: bool = False
    external_lookup_timeout_seconds: int = 20
    virustotal_api_key: str = ""
    virustotal_malicious_threshold: int = 5
    malwarebazaar_api_key: str = ""
    retain_uploads: bool = False
    trusted_bank_cert_sha256: tuple[str, ...] = ()
    auth_mode: str = "api_key"
    api_key: str = ""
    allow_legacy_api_key_in_production: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_algorithms: tuple[str, ...] = ("RS256",)
    oidc_roles_claim: str = "roles"
    oidc_subject_claim: str = "sub"
    oidc_clock_skew_seconds: int = 30
    trusted_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")
    forwarded_allow_ips: str = "127.0.0.1"
    cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    docs_enabled: bool = True
    demo_enabled: bool = True
    legacy_api_enabled: bool = True
    inline_analysis_enabled: bool = True
    audit_hmac_key: str = ""
    audit_hmac_key_id: str = "v1"
    audit_hmac_previous_keys: tuple[str, ...] = ()
    audit_retention_days: int = 180
    metrics_enabled: bool = False
    worker_poll_seconds: int = 2
    job_lease_seconds: int = 1800
    llm_provider: str = "disabled"
    allow_external_llm_in_production: bool = False
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_seconds: int = 20
    ai_experiment_plan_limit: int = 3
    max_investigation_rounds: int = 2
    max_experiments_per_round: int = 3
    dynamic_analysis_enabled: bool = False
    dynamic_network_policy: str = "observe-only"
    adb_path: str = "adb"
    adb_emulator_serial: str = ""
    dynamic_timeout_seconds: int = 90

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        _load_dotenv()
        source = os.environ if env is None else env
        environment = source.get("FRAUDSHIELD_ENV", "development").strip().lower()
        data_dir = Path(source.get("FRAUDSHIELD_DATA_DIR", PROJECT_ROOT / "runtime")).expanduser().resolve()
        return cls(
            environment=environment,
            debug=_bool(source.get("FRAUDSHIELD_DEBUG")),
            data_dir=data_dir,
            database_path=Path(source.get("FRAUDSHIELD_DATABASE_PATH", data_dir / "fraudshield.db")).expanduser().resolve(),
            database_url=source.get("FRAUDSHIELD_DATABASE_URL", "").strip(),
            database_pool_min_size=_int(source.get("FRAUDSHIELD_DATABASE_POOL_MIN_SIZE"), 2),
            database_pool_max_size=_int(source.get("FRAUDSHIELD_DATABASE_POOL_MAX_SIZE"), 10),
            upload_dir=Path(source.get("FRAUDSHIELD_UPLOAD_DIR", data_dir / "uploads")).expanduser().resolve(),
            report_dir=Path(source.get("FRAUDSHIELD_REPORT_DIR", data_dir / "reports")).expanduser().resolve(),
            storage_backend=source.get("FRAUDSHIELD_STORAGE_BACKEND", "local").strip().lower(),
            s3_bucket=source.get("FRAUDSHIELD_S3_BUCKET", "").strip(),
            s3_prefix=source.get("FRAUDSHIELD_S3_PREFIX", "fraudshield").strip().strip("/"),
            s3_region=source.get("FRAUDSHIELD_S3_REGION", "ap-south-1").strip(),
            s3_endpoint_url=source.get("FRAUDSHIELD_S3_ENDPOINT_URL", "").strip().rstrip("/"),
            s3_kms_key_id=source.get("FRAUDSHIELD_S3_KMS_KEY_ID", "").strip(),
            baseline_path=Path(
                source.get(
                    "FRAUDSHIELD_BASELINE_PATH",
                    PACKAGE_ROOT / "resources" / "category_baselines.json",
                )
            ).expanduser().resolve(),
            yara_rules_path=Path(
                source.get(
                    "FRAUDSHIELD_YARA_RULES_PATH",
                    PACKAGE_ROOT / "resources" / "yara" / "deceptiscope_banking.yar",
                )
            ).expanduser().resolve(),
            quark_rules_dir=Path(
                source.get("FRAUDSHIELD_QUARK_RULES_DIR", data_dir / "quark-rules")
            ).expanduser().resolve(),
            max_apk_bytes=_int(source.get("FRAUDSHIELD_MAX_APK_BYTES"), 75 * 1024 * 1024),
            max_zip_entries=_int(source.get("FRAUDSHIELD_MAX_ZIP_ENTRIES"), 20_000),
            max_zip_uncompressed_bytes=_int(
                source.get("FRAUDSHIELD_MAX_ZIP_UNCOMPRESSED_BYTES"), 500 * 1024 * 1024
            ),
            max_concurrent_apk_analyses=_int(
                source.get("FRAUDSHIELD_MAX_CONCURRENT_APK_ANALYSES"), 2
            ),
            engine_timeout_seconds=_int(source.get("FRAUDSHIELD_ENGINE_TIMEOUT_SECONDS"), 120),
            max_engine_output_bytes=_int(
                source.get("FRAUDSHIELD_MAX_ENGINE_OUTPUT_BYTES"), 2 * 1024 * 1024
            ),
            apkid_enabled=_bool(source.get("FRAUDSHIELD_APKID_ENABLED"), default=True),
            yara_enabled=_bool(source.get("FRAUDSHIELD_YARA_ENABLED"), default=True),
            signature_verification_enabled=_bool(
                source.get("FRAUDSHIELD_SIGNATURE_VERIFICATION_ENABLED"), default=True
            ),
            similarity_enabled=_bool(
                source.get("FRAUDSHIELD_SIMILARITY_ENABLED"), default=True
            ),
            quark_enabled=_bool(source.get("FRAUDSHIELD_QUARK_ENABLED")),
            quark_max_rules=_int(source.get("FRAUDSHIELD_QUARK_MAX_RULES"), 300),
            apksigner_path=source.get("FRAUDSHIELD_APKSIGNER_PATH", "apksigner").strip(),
            mobsf_enabled=_bool(source.get("FRAUDSHIELD_MOBSF_ENABLED")),
            mobsf_url=source.get("FRAUDSHIELD_MOBSF_URL", "").strip().rstrip("/"),
            mobsf_api_key=source.get("FRAUDSHIELD_MOBSF_API_KEY", ""),
            mobsf_allow_binary_transfer=_bool(
                source.get("FRAUDSHIELD_MOBSF_ALLOW_BINARY_TRANSFER")
            ),
            reputation_enabled=_bool(source.get("FRAUDSHIELD_REPUTATION_ENABLED")),
            allow_external_reputation_in_production=_bool(
                source.get("FRAUDSHIELD_ALLOW_EXTERNAL_REPUTATION_IN_PRODUCTION")
            ),
            external_lookup_timeout_seconds=_int(
                source.get("FRAUDSHIELD_EXTERNAL_LOOKUP_TIMEOUT_SECONDS"), 20
            ),
            virustotal_api_key=source.get("FRAUDSHIELD_VIRUSTOTAL_API_KEY", ""),
            virustotal_malicious_threshold=_int(
                source.get("FRAUDSHIELD_VIRUSTOTAL_MALICIOUS_THRESHOLD"), 5
            ),
            malwarebazaar_api_key=source.get("FRAUDSHIELD_MALWAREBAZAAR_API_KEY", ""),
            retain_uploads=_bool(source.get("FRAUDSHIELD_RETAIN_UPLOADS")),
            trusted_bank_cert_sha256=_csv(source.get("FRAUDSHIELD_TRUSTED_BANK_CERT_SHA256")),
            auth_mode=source.get(
                "FRAUDSHIELD_AUTH_MODE",
                "oidc" if environment == "production" else "api_key",
            ).strip().lower(),
            api_key=source.get("FRAUDSHIELD_API_KEY", ""),
            allow_legacy_api_key_in_production=_bool(
                source.get("FRAUDSHIELD_ALLOW_LEGACY_API_KEY_IN_PRODUCTION")
            ),
            oidc_issuer=source.get("FRAUDSHIELD_OIDC_ISSUER", "").strip().rstrip("/"),
            oidc_audience=source.get("FRAUDSHIELD_OIDC_AUDIENCE", "").strip(),
            oidc_jwks_url=source.get("FRAUDSHIELD_OIDC_JWKS_URL", "").strip(),
            oidc_algorithms=_csv(source.get("FRAUDSHIELD_OIDC_ALGORITHMS"), ("RS256",)),
            oidc_roles_claim=source.get("FRAUDSHIELD_OIDC_ROLES_CLAIM", "roles").strip(),
            oidc_subject_claim=source.get("FRAUDSHIELD_OIDC_SUBJECT_CLAIM", "sub").strip(),
            oidc_clock_skew_seconds=_int(
                source.get("FRAUDSHIELD_OIDC_CLOCK_SKEW_SECONDS"), 30, minimum=0
            ),
            trusted_hosts=_csv(
                source.get("FRAUDSHIELD_TRUSTED_HOSTS"),
                ("localhost", "127.0.0.1", "testserver"),
            ),
            forwarded_allow_ips=source.get(
                "FRAUDSHIELD_FORWARDED_ALLOW_IPS", "127.0.0.1"
            ).strip(),
            cors_origins=_csv(
                source.get("FRAUDSHIELD_CORS_ORIGINS"),
                ("http://localhost:5173", "http://127.0.0.1:5173"),
            ),
            docs_enabled=_bool(
                source.get("FRAUDSHIELD_DOCS_ENABLED"), default=environment != "production"
            ),
            demo_enabled=_bool(
                source.get("FRAUDSHIELD_DEMO_ENABLED"), default=environment != "production"
            ),
            legacy_api_enabled=_bool(
                source.get("FRAUDSHIELD_LEGACY_API_ENABLED"), default=environment != "production"
            ),
            inline_analysis_enabled=_bool(
                source.get("FRAUDSHIELD_INLINE_ANALYSIS_ENABLED"),
                default=environment != "production",
            ),
            audit_hmac_key=source.get("FRAUDSHIELD_AUDIT_HMAC_KEY", ""),
            audit_hmac_key_id=source.get("FRAUDSHIELD_AUDIT_HMAC_KEY_ID", "v1").strip(),
            audit_hmac_previous_keys=_csv(
                source.get("FRAUDSHIELD_AUDIT_HMAC_PREVIOUS_KEYS")
            ),
            audit_retention_days=_int(source.get("FRAUDSHIELD_AUDIT_RETENTION_DAYS"), 180),
            metrics_enabled=_bool(
                source.get("FRAUDSHIELD_METRICS_ENABLED"), default=environment == "production"
            ),
            worker_poll_seconds=_int(source.get("FRAUDSHIELD_WORKER_POLL_SECONDS"), 2),
            job_lease_seconds=_int(source.get("FRAUDSHIELD_JOB_LEASE_SECONDS"), 1800),
            llm_provider=source.get("FRAUDSHIELD_LLM_PROVIDER", "disabled").strip().lower(),
            allow_external_llm_in_production=_bool(
                source.get("FRAUDSHIELD_ALLOW_EXTERNAL_LLM_IN_PRODUCTION")
            ),
            llm_api_key=source.get("FRAUDSHIELD_LLM_API_KEY", ""),
            llm_model=source.get("FRAUDSHIELD_LLM_MODEL", ""),
            llm_timeout_seconds=_int(source.get("FRAUDSHIELD_LLM_TIMEOUT_SECONDS"), 20),
            ai_experiment_plan_limit=_int(source.get("FRAUDSHIELD_AI_EXPERIMENT_PLAN_LIMIT"), 3),
            max_investigation_rounds=_int(
                source.get("FRAUDSHIELD_MAX_INVESTIGATION_ROUNDS"), 2, minimum=0
            ),
            max_experiments_per_round=_int(source.get("FRAUDSHIELD_MAX_EXPERIMENTS_PER_ROUND"), 3),
            dynamic_analysis_enabled=_bool(source.get("FRAUDSHIELD_DYNAMIC_ANALYSIS_ENABLED")),
            dynamic_network_policy=source.get("FRAUDSHIELD_DYNAMIC_NETWORK_POLICY", "observe-only").strip().lower(),
            adb_path=source.get("FRAUDSHIELD_ADB_PATH", "adb"),
            adb_emulator_serial=source.get("FRAUDSHIELD_ADB_EMULATOR_SERIAL", ""),
            dynamic_timeout_seconds=_int(source.get("FRAUDSHIELD_DYNAMIC_TIMEOUT_SECONDS"), 90),
        )

    def with_overrides(self, **changes: object) -> "Settings":
        return replace(self, **changes)

    @property
    def effective_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        if str(self.database_path) == ":memory:":
            return "sqlite:///:memory:"
        return f"sqlite:///{self.database_path}"

    @property
    def is_postgresql(self) -> bool:
        return self.effective_database_url.startswith(("postgresql://", "postgres://"))

    @property
    def audit_keyring(self) -> dict[str, str]:
        keys = {self.audit_hmac_key_id: self.audit_hmac_key}
        for entry in self.audit_hmac_previous_keys:
            key_id, separator, secret = entry.partition("=")
            if separator:
                keys[key_id] = secret
        return keys

    def ensure_directories(self) -> None:
        for path in (self.data_dir, self.database_path.parent, self.upload_dir, self.report_dir):
            path.mkdir(parents=True, exist_ok=True)

    def validate(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise RuntimeError("FRAUDSHIELD_ENV must be development, test, or production")
        if self.auth_mode not in {"disabled", "api_key", "oidc"}:
            raise RuntimeError("FRAUDSHIELD_AUTH_MODE must be disabled, api_key, or oidc")
        if self.auth_mode == "disabled" and self.environment == "production":
            raise RuntimeError("FRAUDSHIELD_AUTH_MODE=disabled is forbidden in production")
        if self.auth_mode == "api_key" and self.environment == "production":
            if not self.api_key:
                raise RuntimeError("FRAUDSHIELD_API_KEY is required in production API-key mode")
            if len(self.api_key) < 32:
                raise RuntimeError("FRAUDSHIELD_API_KEY must contain at least 32 characters in production")
            if not self.allow_legacy_api_key_in_production:
                raise RuntimeError(
                    "Production requires OIDC; legacy API-key mode needs the explicit "
                    "FRAUDSHIELD_ALLOW_LEGACY_API_KEY_IN_PRODUCTION break-glass flag"
                )
        if self.auth_mode == "oidc":
            missing = [
                name
                for name, value in (
                    ("FRAUDSHIELD_OIDC_ISSUER", self.oidc_issuer),
                    ("FRAUDSHIELD_OIDC_AUDIENCE", self.oidc_audience),
                    ("FRAUDSHIELD_OIDC_JWKS_URL", self.oidc_jwks_url),
                )
                if not value
            ]
            if missing:
                raise RuntimeError(f"OIDC configuration is incomplete: {', '.join(missing)}")
            allowed_algorithms = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
            if not self.oidc_algorithms or any(
                algorithm not in allowed_algorithms for algorithm in self.oidc_algorithms
            ):
                raise RuntimeError("FRAUDSHIELD_OIDC_ALGORITHMS must contain only approved asymmetric algorithms")
            if self.environment == "production" and (
                not self.oidc_issuer.startswith("https://")
                or not self.oidc_jwks_url.startswith("https://")
            ):
                raise RuntimeError("Production OIDC issuer and JWKS URL must use HTTPS")
        if self.environment == "production" and not self.is_postgresql:
            raise RuntimeError("FRAUDSHIELD_DATABASE_URL must use PostgreSQL in production")
        parsed_database = urlsplit(self.effective_database_url)
        if parsed_database.scheme not in {"sqlite", "postgresql", "postgres"}:
            raise RuntimeError("FRAUDSHIELD_DATABASE_URL must use sqlite or postgresql")
        if self.database_pool_min_size > self.database_pool_max_size:
            raise RuntimeError("Database pool minimum cannot exceed maximum")
        if self.environment == "production":
            database_options = parse_qs(parsed_database.query)
            if database_options.get("sslmode", [""])[0] != "verify-full":
                raise RuntimeError(
                    "Production PostgreSQL requires sslmode=verify-full in FRAUDSHIELD_DATABASE_URL"
                )
        if self.storage_backend not in {"local", "s3"}:
            raise RuntimeError("FRAUDSHIELD_STORAGE_BACKEND must be local or s3")
        if self.storage_backend == "s3" and not self.s3_bucket:
            raise RuntimeError("FRAUDSHIELD_S3_BUCKET is required for S3 storage")
        if self.s3_endpoint_url and not self.s3_endpoint_url.startswith(("http://", "https://")):
            raise RuntimeError("FRAUDSHIELD_S3_ENDPOINT_URL must be an HTTP(S) URL")
        if self.environment == "production":
            if self.storage_backend != "s3":
                raise RuntimeError("FRAUDSHIELD_STORAGE_BACKEND must be s3 in production")
            if self.s3_endpoint_url and not self.s3_endpoint_url.startswith("https://"):
                raise RuntimeError("Production S3-compatible endpoints must use HTTPS")
            if not self.s3_kms_key_id:
                raise RuntimeError("FRAUDSHIELD_S3_KMS_KEY_ID is required in production")
        if self.environment == "production" and len(self.audit_hmac_key) < 32:
            raise RuntimeError("FRAUDSHIELD_AUDIT_HMAC_KEY must contain at least 32 characters in production")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", self.audit_hmac_key_id):
            raise RuntimeError("FRAUDSHIELD_AUDIT_HMAC_KEY_ID is invalid")
        invalid_previous_audit_keys = []
        for entry in self.audit_hmac_previous_keys:
            key_id, separator, secret = entry.partition("=")
            if (
                not separator
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id)
                or len(secret) < 32
                or key_id == self.audit_hmac_key_id
            ):
                invalid_previous_audit_keys.append(entry)
        if invalid_previous_audit_keys:
            raise RuntimeError("FRAUDSHIELD_AUDIT_HMAC_PREVIOUS_KEYS contains an invalid entry")
        if self.environment == "production" and self.audit_retention_days < 180:
            raise RuntimeError("FRAUDSHIELD_AUDIT_RETENTION_DAYS cannot be below 180 in production")
        if self.environment == "production" and not self.metrics_enabled:
            raise RuntimeError("FRAUDSHIELD_METRICS_ENABLED must be true in production")
        if not self.trusted_hosts or "*" in self.trusted_hosts:
            raise RuntimeError("FRAUDSHIELD_TRUSTED_HOSTS must be an explicit non-wildcard allowlist")
        if any("/" in host or "://" in host for host in self.trusted_hosts):
            raise RuntimeError("FRAUDSHIELD_TRUSTED_HOSTS must contain hostnames, not URLs")
        if self.environment == "production" and self.forwarded_allow_ips == "*":
            raise RuntimeError("FRAUDSHIELD_FORWARDED_ALLOW_IPS cannot be '*' in production")
        if self.llm_provider not in {"disabled", "openai", "gemini"}:
            raise RuntimeError("FRAUDSHIELD_LLM_PROVIDER must be disabled, openai, or gemini")
        if self.llm_provider != "disabled" and (not self.llm_api_key or not self.llm_model):
            raise RuntimeError(
                "FRAUDSHIELD_LLM_API_KEY and FRAUDSHIELD_LLM_MODEL are required when LLM is enabled"
            )
        if (
            self.environment == "production"
            and self.llm_provider != "disabled"
            and not self.allow_external_llm_in_production
        ):
            raise RuntimeError(
                "External LLM use in production requires explicit privacy/compliance approval and "
                "FRAUDSHIELD_ALLOW_EXTERNAL_LLM_IN_PRODUCTION=true"
            )
        if not 1 <= self.ai_experiment_plan_limit <= 10:
            raise RuntimeError("FRAUDSHIELD_AI_EXPERIMENT_PLAN_LIMIT must be between 1 and 10")
        if not 0 <= self.max_investigation_rounds <= 5:
            raise RuntimeError("FRAUDSHIELD_MAX_INVESTIGATION_ROUNDS must be between 0 and 5")
        if not 1 <= self.max_experiments_per_round <= 10:
            raise RuntimeError("FRAUDSHIELD_MAX_EXPERIMENTS_PER_ROUND must be between 1 and 10")
        if "*" in self.cors_origins:
            raise RuntimeError("Wildcard CORS origins are not supported")
        if any(not origin.startswith(("http://", "https://")) for origin in self.cors_origins):
            raise RuntimeError("FRAUDSHIELD_CORS_ORIGINS must contain only HTTP(S) origins")
        if self.environment == "production" and any(
            not origin.startswith("https://") for origin in self.cors_origins
        ):
            raise RuntimeError("Production CORS origins must use HTTPS")
        if self.environment == "production" and self.docs_enabled:
            raise RuntimeError("FRAUDSHIELD_DOCS_ENABLED must be false in production")
        if self.environment == "production" and self.demo_enabled:
            raise RuntimeError("FRAUDSHIELD_DEMO_ENABLED must be false in production")
        if self.environment == "production" and self.legacy_api_enabled:
            raise RuntimeError("FRAUDSHIELD_LEGACY_API_ENABLED must be false in production")
        if self.environment == "production" and self.inline_analysis_enabled:
            raise RuntimeError("FRAUDSHIELD_INLINE_ANALYSIS_ENABLED must be false in production")
        if self.yara_enabled and not self.yara_rules_path.is_file():
            raise RuntimeError("FRAUDSHIELD_YARA_RULES_PATH must identify a readable rule file")
        if self.mobsf_enabled:
            if not self.mobsf_url or not self.mobsf_api_key:
                raise RuntimeError(
                    "FRAUDSHIELD_MOBSF_URL and FRAUDSHIELD_MOBSF_API_KEY are required when MobSF is enabled"
                )
            if not self.mobsf_url.startswith(("http://", "https://")):
                raise RuntimeError("FRAUDSHIELD_MOBSF_URL must use HTTP(S)")
            if not self.mobsf_allow_binary_transfer:
                raise RuntimeError(
                    "MobSF analysis transfers the APK and requires FRAUDSHIELD_MOBSF_ALLOW_BINARY_TRANSFER=true"
                )
            if self.environment == "production" and not self.mobsf_url.startswith("https://"):
                raise RuntimeError("Production MobSF endpoints must use HTTPS")
        if (
            self.environment == "production"
            and self.reputation_enabled
            and not self.allow_external_reputation_in_production
        ):
            raise RuntimeError(
                "External hash reputation in production requires explicit privacy approval and "
                "FRAUDSHIELD_ALLOW_EXTERNAL_REPUTATION_IN_PRODUCTION=true"
            )
        invalid_hashes = [
            value
            for value in self.trusted_bank_cert_sha256
            if not re.fullmatch(r"[0-9a-fA-F]{64}", value.replace(":", ""))
        ]
        if invalid_hashes:
            raise RuntimeError("FRAUDSHIELD_TRUSTED_BANK_CERT_SHA256 contains an invalid SHA-256")
        if self.dynamic_analysis_enabled and not self.adb_emulator_serial.startswith("emulator-"):
            raise RuntimeError(
                "FRAUDSHIELD_ADB_EMULATOR_SERIAL must identify an emulator-* target when dynamic analysis is enabled"
            )
        if self.dynamic_network_policy not in {"observe-only", "disabled"}:
            raise RuntimeError("FRAUDSHIELD_DYNAMIC_NETWORK_POLICY must be observe-only or disabled")
