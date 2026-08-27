"""
FraudShield DeceptiScope — Independent Engine Orchestration
============================================================

Clean-room implementation of multi-engine APK analysis.  Each adapter
owns its own availability check, analysis workflow, timeout handling,
output bounding, and normalization.

Architecture:
    EngineAdapter (Protocol)       — contract for every analysis adapter
    EngineCoordinator              — runs adapters, collects results, enforces policy
    MultiEngineAnalyzer            — public API (backward-compatible)
    malware_assessment()           — standalone assessment from extraction+risk+engines

Privacy invariants:
    • No APK binary is ever uploaded to a public service.
    • VirusTotal and MalwareBazaar receive SHA-256 only.
    • MobSF binary transfer requires explicit opt-in flag.

Safety invariants:
    • An unavailable or failed engine is never evidence of safety.
    • Engine failure does not lower the static risk score.
    • No shell=True, os.system, eval, exec, or arbitrary command interpolation.
"""
from __future__ import annotations

import concurrent.futures
import importlib.util
import logging
import math
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx

from fraudshield.core.config import Settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_MAX_OUTPUT_TEXT = 500
_MAX_FINDINGS = 150
_TRACKER_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("Google Firebase Analytics", b"com/google/firebase/analytics"),
    ("Google Ads", b"com/google/android/gms/ads"),
    ("Meta SDK", b"com/facebook/appevents"),
    ("AppsFlyer", b"com/appsflyer"),
    ("Adjust", b"com/adjust/sdk"),
    ("Branch", b"io/branch/referral"),
)
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _module_available(name: str) -> bool:
    """Check whether a Python module is importable without importing it."""
    if name == "dexofuzzy":
        _ensure_dexofuzzy_compat()
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _ensure_dexofuzzy_compat() -> None:
    try:
        import sys, six  # noqa: E401
        if "pip._vendor.six" not in sys.modules:
            sys.modules["pip._vendor.six"] = six
    except ImportError:
        pass


def _safe_id(value: str) -> str:
    return _SAFE_ID_RE.sub("-", value).strip("-")[:100] or "finding"


def _bounded_text(value: Any, limit: int = _MAX_OUTPUT_TEXT) -> str:
    return str(value).replace("\x00", "").strip()[:limit]


# ---------------------------------------------------------------------------
# Engine status record builder
# ---------------------------------------------------------------------------

def _engine_status(
    engine_id: str,
    label: str,
    status: str,
    *,
    duration_ms: float,
    summary: dict[str, Any] | None = None,
    error: str | None = None,
    privacy: str = "local-only",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": engine_id,
        "label": label,
        "status": status,
        "duration_ms": round(duration_ms, 1),
        "privacy": privacy,
        "summary": summary or {},
    }
    if error:
        record["error"] = error[:300]
    return record


# ---------------------------------------------------------------------------
# Engine Adapter Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class EngineAdapter(Protocol):
    """Contract that every analysis adapter must satisfy."""

    engine_id: str
    label: str
    privacy: str

    def is_enabled(self, settings: Settings) -> bool: ...
    def is_available(self, settings: Settings) -> bool: ...
    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]: ...


# ---------------------------------------------------------------------------
# Archive Native Adapter
# ---------------------------------------------------------------------------

class ArchiveNativeAdapter:
    engine_id = "archive_native"
    label = "Native APK inventory"
    privacy = "local-only"

    def is_enabled(self, settings: Settings) -> bool:
        return True

    def is_available(self, settings: Settings) -> bool:
        return True

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        abis: set[str] = set()
        native_libs: list[str] = []
        dex_files: list[str] = []
        nested: list[str] = []
        trackers: set[str] = set()
        scanned = 0

        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                lower = entry.filename.lower()
                if lower.startswith("lib/") and lower.endswith(".so"):
                    native_libs.append(entry.filename)
                    parts = entry.filename.split("/")
                    if len(parts) > 2:
                        abis.add(parts[1])
                if lower.endswith(".dex"):
                    dex_files.append(entry.filename)
                if lower.startswith("assets/") and lower.endswith((".apk", ".dex", ".jar", ".so")):
                    nested.append(entry.filename)
                if lower.endswith((".dex", ".xml", ".json", ".txt")) and scanned < 32 * 1024 * 1024:
                    limit = min(entry.file_size, 8 * 1024 * 1024, 32 * 1024 * 1024 - scanned)
                    if limit <= 0:
                        continue
                    with archive.open(entry) as src:
                        data = src.read(limit)
                    scanned += len(data)
                    for tracker_name, marker in _TRACKER_MARKERS:
                        if marker in data:
                            trackers.add(tracker_name)

        findings: list[dict[str, Any]] = []
        if len(dex_files) > 1:
            findings.append({
                "id": "NATIVE:multidex",
                "engine": self.engine_id,
                "title": "Multiple DEX files present",
                "severity": "INFO",
                "confidence": 1.0,
                "risk_category": "evasion_resilience",
                "risk_points": 0,
                "evidence": dex_files[:20],
                "score_eligible": False,
            })

        summary = {
            "abis": sorted(abis),
            "native_library_count": len(native_libs),
            "native_libraries": native_libs[:100],
            "dex_files": dex_files[:30],
            "nested_payloads": nested[:50],
            "trackers": sorted(trackers),
            "tracker_notice": "Presence indicates an embedded SDK, not malware by itself.",
        }
        return summary, findings


# ---------------------------------------------------------------------------
# APKiD Adapter
# ---------------------------------------------------------------------------

class APKiDAdapter:
    engine_id = "apkid"
    label = "APKiD packer and anti-analysis detection"
    privacy = "local-only"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.apkid_enabled

    def is_available(self, settings: Settings) -> bool:
        return _module_available("apkid")

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        from apkid.apkid import Options, Scanner
        from apkid.output import OutputFormatter
        from apkid.rules import RulesManager

        options = Options(
            timeout=min(10, settings.engine_timeout_seconds),
            verbose=False,
            entry_max_scan_size=min(settings.max_apk_bytes, 64 * 1024 * 1024),
            recursive=True,
        )
        rules_mgr = RulesManager()
        formatter = OutputFormatter(
            json_output=True, output_dir=None,
            rules_manager=rules_mgr, include_types=False,
        )
        scanner = Scanner(options.rules_manager.load(), options)
        raw = formatter.build_json_output(scanner.scan_file(str(path))) or {}

        category_values: dict[str, set[str]] = {}
        for file_result in raw.get("files", []):
            matches = file_result.get("matches") or file_result.get("results") or {}
            if not isinstance(matches, dict):
                continue
            for category, values in matches.items():
                if isinstance(values, str):
                    values = [values]
                if isinstance(values, (list, tuple, set)):
                    category_values.setdefault(str(category), set()).update(
                        _bounded_text(v, 200) for v in values
                    )

        findings: list[dict[str, Any]] = []
        for category, values in sorted(category_values.items()):
            normalized = category.lower().replace("-", "_").replace(" ", "_")
            score_eligible = any(
                tok in normalized
                for tok in ("packer", "obfuscat", "anti_vm", "anti_debug", "anti_disassembly")
            )
            points = 16 if "packer" in normalized else 12 if score_eligible else 0
            findings.append({
                "id": f"APKID:{_safe_id(normalized)}",
                "engine": self.engine_id,
                "title": f"APKiD {category}",
                "severity": "HIGH" if points >= 16 else "MEDIUM" if points else "INFO",
                "confidence": 0.86,
                "risk_category": "evasion_resilience",
                "risk_points": points,
                "evidence": sorted(values)[:30],
                "score_eligible": score_eligible,
            })

        summary = {
            "match_categories": {k: sorted(v)[:30] for k, v in category_values.items()},
            "match_count": sum(len(v) for v in category_values.values()),
        }
        return summary, findings


# ---------------------------------------------------------------------------
# YARA Adapter
# ---------------------------------------------------------------------------

class YaraAdapter:
    engine_id = "yara"
    label = "YARA banking behavior rules"
    privacy = "local-only"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.yara_enabled

    def is_available(self, settings: Settings) -> bool:
        return _module_available("yara") and settings.yara_rules_path.is_file()

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        import yara

        rules = yara.compile(filepath=str(settings.yara_rules_path))
        matches: list[dict[str, Any]] = []
        scanned_entries = 0
        scanned_bytes = 0
        deadline = time.monotonic() + settings.engine_timeout_seconds

        def scan_target(target: str, data: bytes) -> None:
            nonlocal scanned_entries, scanned_bytes
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            scanned_entries += 1
            scanned_bytes += len(data)
            per_target_timeout = max(1, min(5, math.ceil(remaining)))
            for match in rules.match(data=data, timeout=per_target_timeout):
                metadata = dict(getattr(match, "meta", {}) or {})
                matches.append({
                    "rule": str(match.rule),
                    "target": target,
                    "namespace": str(getattr(match, "namespace", "default")),
                    "metadata": {str(k): _bounded_text(v, 300) for k, v in metadata.items()},
                })

        with path.open("rb") as src:
            scan_target(path.name, src.read(min(path.stat().st_size, 16 * 1024 * 1024)))

        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if scanned_entries >= 250 or scanned_bytes >= 64 * 1024 * 1024 or time.monotonic() >= deadline:
                    break
                if not entry.filename.lower().endswith((".dex", ".xml", ".json", ".txt", ".js", ".so")):
                    continue
                limit = min(entry.file_size, 8 * 1024 * 1024, 64 * 1024 * 1024 - scanned_bytes)
                if limit <= 0:
                    break
                with archive.open(entry) as src:
                    scan_target(entry.filename, src.read(limit))

        dedup: dict[tuple[str, str], dict[str, Any]] = {}
        for m in matches:
            dedup[(m["rule"], m["target"])] = m
        matches = list(dedup.values())[:100]

        findings: list[dict[str, Any]] = []
        for m in matches:
            meta = m["metadata"]
            category = meta.get("risk_category", "evasion_resilience")
            if category not in {"credential_theft", "payment_manipulation", "fraud_impersonation", "evasion_resilience"}:
                category = "evasion_resilience"
            try:
                points = max(0, min(30, int(meta.get("risk_points", "0"))))
            except ValueError:
                points = 0
            findings.append({
                "id": f"YARA:{_safe_id(m['rule'])}",
                "engine": self.engine_id,
                "title": meta.get("title", m["rule"]),
                "severity": meta.get("severity", "MEDIUM").upper(),
                "confidence": 0.9,
                "risk_category": category,
                "risk_points": points,
                "evidence": [f"rule={m['rule']}", f"target={m['target']}"],
                "score_eligible": points > 0,
            })

        summary = {
            "rule_file": settings.yara_rules_path.name,
            "matches": matches,
            "match_count": len(matches),
            "scanned_entries": scanned_entries,
            "scanned_bytes": scanned_bytes,
        }
        return summary, findings


# ---------------------------------------------------------------------------
# Signature Verification Adapter (apksigner)
# ---------------------------------------------------------------------------

class SignatureAdapter:
    engine_id = "apksigner"
    label = "Android signature verifier"
    privacy = "local-only"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.signature_verification_enabled

    def is_available(self, settings: Settings) -> bool:
        return bool(shutil.which(settings.apksigner_path))

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        executable = shutil.which(settings.apksigner_path)
        if not executable:
            raise RuntimeError("apksigner executable is unavailable")

        # Safe command construction — no shell=True, no string interpolation
        cmd = [executable, "verify", "--verbose", "--print-certs", str(path.resolve())]
        completed = subprocess.run(
            cmd, check=False, capture_output=True, text=True,
            timeout=settings.engine_timeout_seconds,
        )
        output = (completed.stdout + "\n" + completed.stderr)[:settings.max_engine_output_bytes]
        output = output.replace(str(path.resolve()), "<apk>").replace(str(path), "<apk>")

        cert_digests = sorted({
            v.replace(":", "").lower()
            for v in re.findall(
                r"certificate SHA-256 digest:\s*([0-9A-Fa-f:]{64,95})", output, re.IGNORECASE,
            )
        })
        verified = completed.returncode == 0

        findings: list[dict[str, Any]] = []
        if not verified:
            findings.append({
                "id": "APKSIGNER:verification-failed",
                "engine": self.engine_id,
                "title": "APK signature verification failed",
                "severity": "HIGH",
                "confidence": 0.95,
                "risk_category": "fraud_impersonation",
                "risk_points": 24,
                "evidence": [line[:300] for line in output.splitlines() if line.strip()][-8:],
                "score_eligible": True,
            })

        schemes: dict[str, bool] = {}
        for version in ("v1", "v2", "v3", "v4"):
            match = re.search(rf"Verified using {version} scheme.*?:\s*(true|false)", output, re.I)
            if match:
                schemes[version] = match.group(1).lower() == "true"

        summary = {
            "verified": verified,
            "certificate_sha256": cert_digests,
            "schemes": schemes,
            "tool_exit_code": completed.returncode,
        }
        return summary, findings


# ---------------------------------------------------------------------------
# Similarity Adapter (ssdeep / Dexofuzzy)
# ---------------------------------------------------------------------------

class SimilarityAdapter:
    engine_id = "similarity"
    label = "ssdeep and Dexofuzzy fingerprints"
    privacy = "local-only"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.similarity_enabled

    def is_available(self, settings: Settings) -> bool:
        return _module_available("ssdeep") or _module_available("dexofuzzy")

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        summary: dict[str, Any] = {"ssdeep": None, "dexofuzzy": None}

        if _module_available("ssdeep"):
            try:
                import ssdeep
                summary["ssdeep"] = _bounded_text(ssdeep.hash_from_file(str(path.resolve())), 500)
            except Exception as exc:
                logger.debug("ssdeep extraction failed: %s", exc)

        if _module_available("dexofuzzy"):
            try:
                import dexofuzzy
                summary["dexofuzzy"] = _bounded_text(dexofuzzy.hash_from_file(str(path.resolve())), 500)
            except Exception as exc:
                logger.debug("dexofuzzy extraction failed: %s", exc)

        summary["notice"] = "Fingerprints support later corpus comparison; similarity alone is not a malware verdict."
        return summary, []


# ---------------------------------------------------------------------------
# Quark Adapter
# ---------------------------------------------------------------------------

class QuarkAdapter:
    engine_id = "quark"
    label = "Quark behavior rules"
    privacy = "local-only"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.quark_enabled

    def is_available(self, settings: Settings) -> bool:
        if not _module_available("quark"):
            return False
        if not settings.quark_rules_dir.is_dir():
            return False
        return any(settings.quark_rules_dir.rglob("*.json"))

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        from quark.core.quark import Quark
        from quark.core.struct.ruleobject import RuleObject

        analyzer = Quark(str(path))
        rules = sorted(
            list(settings.quark_rules_dir.glob("*.json"))
            or list(settings.quark_rules_dir.rglob("*.json"))
        )[:settings.quark_max_rules]

        deadline = time.monotonic() + min(15, settings.engine_timeout_seconds)
        for rule_path in rules:
            if time.monotonic() >= deadline:
                logger.warning(
                    "Quark rule execution reached bounded timeout deadline (%ds)",
                    min(15, settings.engine_timeout_seconds),
                )
                break
            rule = RuleObject(str(rule_path))
            try:
                analyzer.run(rule)
                analyzer.generate_json_report(rule)
            except Exception:
                logger.debug("Quark rule failed: %s", rule_path.name, exc_info=True)

        raw = analyzer.get_json_report() or []
        if isinstance(raw, dict):
            raw = raw.get("report") or raw.get("rules") or [raw]
        reports: list[dict[str, Any]] = []
        if isinstance(raw, list):
            reports = [item for item in raw if isinstance(item, dict)][:200]

        findings: list[dict[str, Any]] = []
        report_summaries: list[dict[str, str]] = []
        for idx, report in enumerate(reports[:50]):
            desc = _bounded_text(
                report.get("crime") or report.get("description") or report.get("rule") or "Quark behavior", 300,
            )
            report_summaries.append({
                "rule": _bounded_text(report.get("rule") or report.get("rule_name") or "", 160),
                "description": desc,
            })
            lower = desc.lower()
            category = (
                "credential_theft" if any(t in lower for t in ("sms", "credential", "password", "otp"))
                else "payment_manipulation" if any(t in lower for t in ("accessibility", "overlay", "transaction"))
                else "evasion_resilience"
            )
            findings.append({
                "id": f"QUARK:{idx + 1}:{_safe_id(desc)}",
                "engine": self.engine_id,
                "title": desc,
                "severity": "MEDIUM",
                "confidence": 0.75,
                "risk_category": category,
                "risk_points": 8,
                "evidence": [desc],
                "score_eligible": True,
            })

        summary = {
            "rules_executed": len(rules),
            "report_count": len(reports),
            "report_summaries": report_summaries,
        }
        return summary, findings


# ---------------------------------------------------------------------------
# MobSF Adapter (private self-hosted only)
# ---------------------------------------------------------------------------

class MobSFAdapter:
    engine_id = "mobsf"
    label = "Self-hosted MobSF"
    privacy = "configured-private-service"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.mobsf_enabled

    def is_available(self, settings: Settings) -> bool:
        return bool(settings.mobsf_url and settings.mobsf_api_key)

    def is_transfer_allowed(self, settings: Settings) -> bool:
        """Binary transfer requires explicit operator opt-in."""
        return bool(settings.mobsf_allow_binary_transfer)

    def analyze(
        self, path: Path, *, settings: Settings, sha256: str, extraction: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        base = settings.mobsf_url.rstrip("/")
        headers = {"Authorization": settings.mobsf_api_key}
        scan_hash = ""
        report: dict[str, Any] = {}

        with httpx.Client(timeout=settings.engine_timeout_seconds, headers=headers) as client:
            try:
                with path.open("rb") as src:
                    upload = client.post(
                        f"{base}/api/v1/upload",
                        files={"file": (path.name, src, "application/vnd.android.package-archive")},
                    )
                upload.raise_for_status()
                uploaded = upload.json()
                scan_hash = str(uploaded.get("hash") or uploaded.get("scan_hash") or "")
                if not scan_hash:
                    raise RuntimeError("MobSF upload did not return a scan hash")
                scan = client.post(f"{base}/api/v1/scan", data={"hash": scan_hash})
                scan.raise_for_status()
                report_resp = client.post(f"{base}/api/v1/report_json", data={"hash": scan_hash})
                report_resp.raise_for_status()
                parsed = report_resp.json()
                if not isinstance(parsed, dict):
                    raise RuntimeError("MobSF returned an invalid report shape")
                report = parsed
            finally:
                if scan_hash:
                    try:
                        client.post(f"{base}/api/v1/delete_scan", data={"hash": scan_hash}).raise_for_status()
                    except Exception:
                        logger.warning("MobSF scan cleanup failed for %s", scan_hash[:12])

        manifest = report.get("manifest_analysis") or []
        code = report.get("code_analysis") or {}
        if isinstance(code, dict):
            code = list(code.values())

        high_items: list[str] = []
        for item in [*manifest, *(code if isinstance(code, list) else [])]:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or item.get("level") or "").lower()
            if sev in {"high", "critical"}:
                high_items.append(
                    _bounded_text(item.get("title") or item.get("description") or item.get("name"), 300)
                )

        findings = [
            {
                "id": f"MOBSF:{i + 1}:{_safe_id(title)}",
                "engine": self.engine_id,
                "title": title,
                "severity": "HIGH",
                "confidence": 0.8,
                "risk_category": "evasion_resilience",
                "risk_points": 6,
                "evidence": [title],
                "score_eligible": True,
            }
            for i, title in enumerate(high_items[:5])
            if title
        ]

        appsec = report.get("appsec")
        if not isinstance(appsec, dict):
            appsec = {}
        trackers = report.get("trackers")

        summary = {
            "scan_hash": scan_hash,
            "security_score": report.get("security_score") or appsec.get("security_score"),
            "high_severity_finding_count": len(high_items),
            "trackers": [_bounded_text(v, 160) for v in list(trackers.keys())[:100]]
            if isinstance(trackers, dict) else [],
        }
        return summary, findings


# ---------------------------------------------------------------------------
# VirusTotal Hash-Only Adapter
# ---------------------------------------------------------------------------

class VirusTotalHashAdapter:
    engine_id = "virustotal"
    label = "VirusTotal hash reputation"
    privacy = "hash-only-external"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.reputation_enabled

    def is_available(self, settings: Settings) -> bool:
        return bool(settings.virustotal_api_key)

    def lookup(self, sha256: str, settings: Settings) -> dict[str, Any]:
        """SHA-256 only lookup — no binary upload ever occurs."""
        with httpx.Client(timeout=settings.external_lookup_timeout_seconds) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
        if response.status_code == 404:
            return {"id": "virustotal", "status": "not-found", "malicious": 0, "suspicious": 0}
        response.raise_for_status()
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "id": "virustotal",
            "status": "found",
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }


# ---------------------------------------------------------------------------
# MalwareBazaar Hash-Only Adapter
# ---------------------------------------------------------------------------

class MalwareBazaarHashAdapter:
    engine_id = "malwarebazaar"
    label = "MalwareBazaar hash reputation"
    privacy = "hash-only-external"

    def is_enabled(self, settings: Settings) -> bool:
        return settings.reputation_enabled

    def is_available(self, settings: Settings) -> bool:
        return True  # MalwareBazaar is publicly accessible

    def lookup(self, sha256: str, settings: Settings) -> dict[str, Any]:
        """SHA-256 only lookup — no binary upload ever occurs."""
        headers = (
            {"Auth-Key": settings.malwarebazaar_api_key}
            if settings.malwarebazaar_api_key else {}
        )
        with httpx.Client(timeout=settings.external_lookup_timeout_seconds) as client:
            response = client.post(
                "https://mb-api.abuse.ch/api/v1/",
                headers=headers,
                data={"query": "get_info", "hash": sha256},
            )
        response.raise_for_status()
        body = response.json()
        entries = body.get("data") or []
        found = body.get("query_status") in {"ok", "success"} and bool(entries)
        first = entries[0] if found and isinstance(entries[0], dict) else {}
        return {
            "id": "malwarebazaar",
            "status": "found" if found else "not-found",
            "signature": _bounded_text(first.get("signature") or "", 200),
            "file_type": _bounded_text(first.get("file_type") or "", 50),
            "first_seen": first.get("first_seen"),
            "tags": [_bounded_text(v, 80) for v in (first.get("tags") or [])[:30]],
        }


# ---------------------------------------------------------------------------
# Engine Coordinator
# ---------------------------------------------------------------------------

class EngineCoordinator:
    """
    Runs engine adapters in a deterministic order, handles enable/available/
    blocked-by-policy states, catches failures, and builds the unified result.
    """

    # Deterministic adapter order
    LOCAL_ADAPTERS: list[type] = [
        APKiDAdapter,
        YaraAdapter,
        SignatureAdapter,
        SimilarityAdapter,
        QuarkAdapter,
    ]

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.archive_adapter = ArchiveNativeAdapter()
        self.local_adapters = [cls() for cls in self.LOCAL_ADAPTERS]
        self.mobsf_adapter = MobSFAdapter()
        self.vt_adapter = VirusTotalHashAdapter()
        self.mb_adapter = MalwareBazaarHashAdapter()

    def run_guarded(
        self,
        adapter: Any,
        path: Path,
        sha256: str,
        extraction: dict[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Execute an adapter with timing and failure isolation."""
        started = time.perf_counter()
        timeout_seconds = max(1, int(self.settings.engine_timeout_seconds))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    adapter.analyze,
                    path,
                    settings=self.settings,
                    sha256=sha256,
                    extraction=extraction,
                )
                summary, findings = future.result(timeout=timeout_seconds)
                return (
                    _engine_status(
                        adapter.engine_id,
                        adapter.label,
                        "completed",
                        duration_ms=(time.perf_counter() - started) * 1000,
                        summary=summary,
                        privacy=adapter.privacy,
                    ),
                    findings,
                )
        except concurrent.futures.TimeoutError:
            logger.warning(
                "Optional APK engine %s timed out after %ds",
                adapter.engine_id,
                timeout_seconds,
            )
            return (
                _engine_status(
                    adapter.engine_id,
                    adapter.label,
                    "timeout",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"Engine timed out after {timeout_seconds}s; analysis continued",
                    privacy=adapter.privacy,
                ),
                [],
            )
        except Exception as exc:
            logger.warning("Optional APK engine %s failed: %s", adapter.engine_id, type(exc).__name__)
            return (
                _engine_status(
                    adapter.engine_id, adapter.label, "failed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"{type(exc).__name__}: engine did not complete; inspect restricted worker logs",
                    privacy=adapter.privacy,
                ),
                [],
            )

    def run_all(
        self, path: Path, *, sha256: str, extraction: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        """Returns (engine_statuses, findings, reputation)."""
        engines: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        # 1. Archive native — always runs
        native_status, native_findings = self.run_guarded(self.archive_adapter, path, sha256, extraction)
        engines.append(native_status)
        findings.extend(native_findings)

        # 2. Androguard — reported from extraction metadata
        extractor_engine = str(extraction.get("engine") or "unknown")
        extraction_quality = str(extraction.get("analysis_quality") or "unknown")
        extractor_summary = {"extractor": extractor_engine, "analysis_quality": extraction_quality}
        if extractor_engine == "androguard+archive":
            engines.append(_engine_status("androguard", "Androguard", "completed", duration_ms=0, summary=extractor_summary))
        elif _module_available("androguard"):
            engines.append(_engine_status(
                "androguard", "Androguard", "failed", duration_ms=0,
                error="Structured extraction fell back to bounded archive evidence; inspect restricted worker logs",
                summary=extractor_summary,
            ))
        else:
            engines.append(_engine_status(
                "androguard", "Androguard", "unavailable", duration_ms=0,
                error="Androguard is not installed; bounded archive extraction was used",
                summary=extractor_summary,
            ))

        # 3. Local analysis adapters — deterministic order
        for adapter in self.local_adapters:
            if not adapter.is_enabled(self.settings):
                engines.append(_engine_status(adapter.engine_id, adapter.label, "disabled", duration_ms=0))
                continue
            if not adapter.is_available(self.settings):
                engines.append(_engine_status(
                    adapter.engine_id, adapter.label, "unavailable", duration_ms=0,
                    error="Optional engine or its offline rule data is not installed",
                ))
                continue
            status, adapter_findings = self.run_guarded(adapter, path, sha256, extraction)
            engines.append(status)
            findings.extend(adapter_findings)

        # 4. MobSF — policy gated
        if self.mobsf_adapter.is_enabled(self.settings):
            if not self.mobsf_adapter.is_transfer_allowed(self.settings):
                engines.append(_engine_status(
                    "mobsf", "Self-hosted MobSF", "blocked-by-policy", duration_ms=0,
                    error="Binary transfer requires FRAUDSHIELD_MOBSF_ALLOW_BINARY_TRANSFER=true",
                    privacy="configured-private-service",
                ))
            elif not self.mobsf_adapter.is_available(self.settings):
                engines.append(_engine_status(
                    "mobsf", "Self-hosted MobSF", "unavailable", duration_ms=0,
                    error="MobSF URL and API key are required",
                    privacy="configured-private-service",
                ))
            else:
                status, mobsf_findings = self.run_guarded(self.mobsf_adapter, path, sha256, extraction)
                engines.append(status)
                findings.extend(mobsf_findings)
        else:
            engines.append(_engine_status(
                "mobsf", "Self-hosted MobSF", "disabled", duration_ms=0,
                privacy="configured-private-service",
            ))

        # 5. Hash reputation
        reputation, rep_statuses = self._run_reputation(sha256)
        engines.extend(rep_statuses)

        return engines, findings, reputation

    def _run_reputation(self, sha256: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Hash-only reputation lookups."""
        if not self.settings.reputation_enabled:
            return (
                {
                    "verdict": "not-queried",
                    "known_malicious": False,
                    "providers": [],
                    "notice": "External reputation is disabled. This state is not evidence that the APK is safe.",
                },
                [
                    _engine_status("virustotal", "VirusTotal hash reputation", "disabled", duration_ms=0, privacy="hash-only-external"),
                    _engine_status("malwarebazaar", "MalwareBazaar hash reputation", "disabled", duration_ms=0, privacy="hash-only-external"),
                ],
            )

        providers: list[dict[str, Any]] = []
        statuses: list[dict[str, Any]] = []

        # VirusTotal
        if self.vt_adapter.is_available(self.settings):
            started = time.perf_counter()
            try:
                provider = self.vt_adapter.lookup(sha256, self.settings)
                providers.append(provider)
                statuses.append(_engine_status(
                    "virustotal", "VirusTotal hash reputation", "completed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    summary=provider, privacy="hash-only-external",
                ))
            except Exception as exc:
                logger.warning("VirusTotal hash lookup failed: %s", type(exc).__name__)
                statuses.append(_engine_status(
                    "virustotal", "VirusTotal hash reputation", "failed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"{type(exc).__name__}: lookup did not complete; inspect restricted worker logs",
                    privacy="hash-only-external",
                ))
        else:
            statuses.append(_engine_status(
                "virustotal", "VirusTotal hash reputation", "unavailable",
                duration_ms=0, error="API key is not configured", privacy="hash-only-external",
            ))

        # MalwareBazaar
        started = time.perf_counter()
        try:
            provider = self.mb_adapter.lookup(sha256, self.settings)
            providers.append(provider)
            statuses.append(_engine_status(
                "malwarebazaar", "MalwareBazaar hash reputation", "completed",
                duration_ms=(time.perf_counter() - started) * 1000,
                summary=provider, privacy="hash-only-external",
            ))
        except Exception as exc:
            logger.warning("MalwareBazaar hash lookup failed: %s", type(exc).__name__)
            statuses.append(_engine_status(
                "malwarebazaar", "MalwareBazaar hash reputation", "failed",
                duration_ms=(time.perf_counter() - started) * 1000,
                error=f"{type(exc).__name__}: lookup did not complete; inspect restricted worker logs",
                privacy="hash-only-external",
            ))

        vt_malicious = next((int(p.get("malicious", 0)) for p in providers if p["id"] == "virustotal"), 0)
        mb_found = any(p["id"] == "malwarebazaar" and p.get("status") == "found" for p in providers)
        known_malicious = mb_found or vt_malicious >= self.settings.virustotal_malicious_threshold
        found_any = any(p.get("status") == "found" for p in providers)

        reputation = {
            "verdict": "known-malicious" if known_malicious else "known-file" if found_any else "not-found",
            "known_malicious": known_malicious,
            "providers": providers,
            "notice": "Only the SHA-256 was transmitted. A not-found or zero-detection result is not proof of legitimacy.",
        }
        return reputation, statuses


# ---------------------------------------------------------------------------
# Public API — backward-compatible
# ---------------------------------------------------------------------------

class MultiEngineAnalyzer:
    """Run bounded, optional APK engines and normalize their evidence.

    Engine execution is isolated behind explicit adapter status so unavailable
    tools never become clean evidence and never prevent core extraction.
    """

    version = "deceptiscope-engines-2026.5"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._coordinator = EngineCoordinator(settings)

    def capabilities(self) -> dict[str, Any]:
        apksigner = shutil.which(self.settings.apksigner_path)
        engines = [
            {"id": "archive_native", "label": "Native APK inventory", "enabled": True, "available": True, "mode": "local-static"},
            {"id": "androguard", "label": "Androguard", "enabled": True, "available": _module_available("androguard"), "mode": "local-static"},
            {"id": "apkid", "label": "APKiD packer and anti-analysis detection", "enabled": self.settings.apkid_enabled, "available": _module_available("apkid"), "mode": "local-static"},
            {"id": "yara", "label": "YARA banking behavior rules", "enabled": self.settings.yara_enabled, "available": _module_available("yara") and self.settings.yara_rules_path.is_file(), "mode": "local-static"},
            {"id": "apksigner", "label": "Android signature verifier", "enabled": self.settings.signature_verification_enabled, "available": bool(apksigner), "mode": "local-static"},
            {"id": "similarity", "label": "ssdeep and Dexofuzzy fingerprints", "enabled": self.settings.similarity_enabled, "available": _module_available("ssdeep") or _module_available("dexofuzzy"), "mode": "local-static"},
            {"id": "quark", "label": "Quark behavior rules", "enabled": self.settings.quark_enabled, "available": self._coordinator.local_adapters[4].is_available(self.settings) if len(self._coordinator.local_adapters) > 4 else False, "mode": "local-static"},
            {"id": "mobsf", "label": "Self-hosted MobSF", "enabled": self.settings.mobsf_enabled, "available": bool(self.settings.mobsf_url and self.settings.mobsf_api_key), "mode": "configured-private-service"},
            {"id": "virustotal", "label": "VirusTotal hash reputation", "enabled": self.settings.reputation_enabled, "available": bool(self.settings.virustotal_api_key), "mode": "hash-only-external"},
            {"id": "malwarebazaar", "label": "MalwareBazaar hash reputation", "enabled": self.settings.reputation_enabled, "available": True, "mode": "hash-only-external"},
        ]
        return {
            "orchestrator_version": self.version,
            "engines": engines,
            "binary_upload_policy": "disabled-for-public-services",
            "external_hash_lookups": self.settings.reputation_enabled,
            "mobsf_binary_transfer": bool(self.settings.mobsf_enabled and self.settings.mobsf_allow_binary_transfer),
            "notice": "Unavailable optional engines are reported explicitly. Their absence is never treated as a clean result.",
        }

    def analyze(self, path: Path, *, sha256: str, extraction: dict[str, Any]) -> dict[str, Any]:
        engines, findings, reputation = self._coordinator.run_all(
            path, sha256=sha256, extraction=extraction,
        )

        deduplicated = self._deduplicate_findings(findings)
        completed = sum(e["status"] == "completed" for e in engines)
        unavailable = sum(e["status"] in {"unavailable", "failed", "blocked-by-policy"} for e in engines)

        native_engine = next((e for e in engines if e["id"] == "archive_native"), {})
        tracker_count = len(native_engine.get("summary", {}).get("trackers", []))

        return {
            "schema_version": "1.0",
            "orchestrator_version": self.version,
            "policy": {
                "public_binary_uploads": False,
                "external_hash_lookups": self.settings.reputation_enabled,
                "mobsf_binary_transfer": bool(
                    self.settings.mobsf_enabled and self.settings.mobsf_allow_binary_transfer
                ),
                "unknown_is_safe": False,
            },
            "summary": {
                "completed": completed,
                "unavailable_or_failed": unavailable,
                "normalized_finding_count": len(deduplicated),
                "tracker_count": tracker_count,
            },
            "engines": engines,
            "normalized_findings": deduplicated,
            "reputation": reputation,
            "coverage_note": "A missing or failed optional engine reduces coverage; it does not imply that the APK is legitimate.",
            "base_extractor": extraction.get("engine", "unknown"),
        }

    @staticmethod
    def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for f in findings:
            key = (str(f.get("engine")), str(f.get("id")))
            unique[key] = f
        return sorted(
            unique.values(),
            key=lambda item: (
                -_SEVERITY_ORDER.get(str(item.get("severity", "INFO")).upper(), 0),
                -int(item.get("risk_points", 0)),
                str(item.get("id")),
            ),
        )[:_MAX_FINDINGS]


# ---------------------------------------------------------------------------
# Standalone malware assessment
# ---------------------------------------------------------------------------

def malware_assessment(
    extraction: dict[str, Any],
    risk: dict[str, Any],
    engine_analysis: dict[str, Any],
) -> dict[str, Any]:
    reputation = engine_analysis.get("reputation", {})
    known_malicious = bool(reputation.get("known_malicious"))
    score = int(risk.get("overall_score", 0))
    quality = str(extraction.get("analysis_quality", "partial"))
    failed = int(engine_analysis.get("summary", {}).get("unavailable_or_failed", 0))

    if known_malicious:
        verdict = "KNOWN_MALICIOUS"
        explanation = "At least one configured hash-reputation policy identified the exact SHA-256 as malware."
    elif score >= 75:
        verdict = "HIGH_RISK"
        explanation = "Multiple high-impact behaviors produced a critical deterministic risk score."
    elif score >= 50:
        verdict = "SUSPICIOUS"
        explanation = "The visible evidence contains a high-risk combination requiring analyst review."
    elif quality == "partial":
        verdict = "INCONCLUSIVE"
        explanation = "Extraction was partial, so absence of findings cannot support a low-risk conclusion."
    elif score < 25:
        verdict = "LOW_RISK_OBSERVED"
        explanation = "No configured high-risk combination was observed within the completed static coverage."
    else:
        verdict = "REVIEW_REQUIRED"
        explanation = "Some suspicious evidence is present but does not meet the high-risk threshold."

    return {
        "verdict": verdict,
        "known_malware": known_malicious,
        "legitimacy": "not-established",
        "explanation": explanation,
        "optional_engine_gaps": failed,
        "safe_to_install": False,
        "limitations": [
            "Static analysis cannot prove that an APK is legitimate or safe to install.",
            "A clean or unknown reputation result can reflect a new, private, or modified sample.",
            "Validate package identity and signing certificate against an authoritative publisher inventory.",
        ],
    }
