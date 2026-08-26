from __future__ import annotations

import importlib.util
import logging
import math
import re
import shutil
import subprocess
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from fraudshield.core.config import Settings


logger = logging.getLogger(__name__)
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.:-]+")
_TRACKER_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("Google Firebase Analytics", b"com/google/firebase/analytics"),
    ("Google Ads", b"com/google/android/gms/ads"),
    ("Meta SDK", b"com/facebook/appevents"),
    ("AppsFlyer", b"com/appsflyer"),
    ("Adjust", b"com/adjust/sdk"),
    ("Branch", b"io/branch/referral"),
)


def _ensure_dexofuzzy_compat() -> None:
    try:
        import sys
        import six

        if "pip._vendor.six" not in sys.modules:
            sys.modules["pip._vendor.six"] = six
    except ImportError:
        pass


def _module_available(name: str) -> bool:
    if name == "dexofuzzy":
        _ensure_dexofuzzy_compat()
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _safe_id(value: str) -> str:
    return _SAFE_ID.sub("-", value).strip("-")[:100] or "finding"


def _quark_available(settings: Settings) -> bool:
    if not _module_available("quark"):
        return False
    if not settings.quark_rules_dir.is_dir():
        return False
    return any(settings.quark_rules_dir.rglob("*.json"))


def _bounded_text(value: Any, limit: int = 500) -> str:
    return str(value).replace("\x00", "").strip()[:limit]


def _status(
    engine_id: str,
    label: str,
    status: str,
    *,
    duration_ms: float,
    summary: dict[str, Any] | None = None,
    error: str | None = None,
    privacy: str = "local-only",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": engine_id,
        "label": label,
        "status": status,
        "duration_ms": round(duration_ms, 1),
        "privacy": privacy,
        "summary": summary or {},
    }
    if error:
        result["error"] = error[:300]
    return result


class MultiEngineAnalyzer:
    """Run bounded, optional APK engines and normalize their evidence.

    Engine execution is isolated behind explicit adapter status so unavailable
    tools never become clean evidence and never prevent core extraction.
    """

    version = "deceptiscope-engines-2026.4"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def capabilities(self) -> dict[str, Any]:
        apksigner = shutil.which(self.settings.apksigner_path)
        engines = [
            {
                "id": "archive_native",
                "label": "Native APK inventory",
                "enabled": True,
                "available": True,
                "mode": "local-static",
            },
            {
                "id": "androguard",
                "label": "Androguard",
                "enabled": True,
                "available": _module_available("androguard"),
                "mode": "local-static",
            },
            {
                "id": "apkid",
                "label": "APKiD packer and anti-analysis detection",
                "enabled": self.settings.apkid_enabled,
                "available": _module_available("apkid"),
                "mode": "local-static",
            },
            {
                "id": "yara",
                "label": "YARA banking behavior rules",
                "enabled": self.settings.yara_enabled,
                "available": _module_available("yara") and self.settings.yara_rules_path.is_file(),
                "mode": "local-static",
            },
            {
                "id": "apksigner",
                "label": "Android signature verifier",
                "enabled": self.settings.signature_verification_enabled,
                "available": bool(apksigner),
                "mode": "local-static",
            },
            {
                "id": "similarity",
                "label": "ssdeep and Dexofuzzy fingerprints",
                "enabled": self.settings.similarity_enabled,
                "available": _module_available("ssdeep") or _module_available("dexofuzzy"),
                "mode": "local-static",
            },
            {
                "id": "quark",
                "label": "Quark behavior rules",
                "enabled": self.settings.quark_enabled,
                "available": _quark_available(self.settings),
                "mode": "local-static",
            },
            {
                "id": "mobsf",
                "label": "Self-hosted MobSF",
                "enabled": self.settings.mobsf_enabled,
                "available": bool(self.settings.mobsf_url and self.settings.mobsf_api_key),
                "mode": "configured-private-service",
            },
            {
                "id": "virustotal",
                "label": "VirusTotal hash reputation",
                "enabled": self.settings.reputation_enabled,
                "available": bool(self.settings.virustotal_api_key),
                "mode": "hash-only-external",
            },
            {
                "id": "malwarebazaar",
                "label": "MalwareBazaar hash reputation",
                "enabled": self.settings.reputation_enabled,
                "available": True,
                "mode": "hash-only-external",
            },
        ]
        return {
            "orchestrator_version": self.version,
            "engines": engines,
            "binary_upload_policy": "disabled-for-public-services",
            "external_hash_lookups": self.settings.reputation_enabled,
            "mobsf_binary_transfer": bool(
                self.settings.mobsf_enabled and self.settings.mobsf_allow_binary_transfer
            ),
            "notice": (
                "Unavailable optional engines are reported explicitly. Their absence is never treated as a clean result."
            ),
        }

    def analyze(self, path: Path, *, sha256: str, extraction: dict[str, Any]) -> dict[str, Any]:
        engines: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        native, native_findings = self._guarded(
            "archive_native",
            "Native APK inventory",
            lambda: self._native_inventory(path),
        )
        engines.append(native)
        findings.extend(native_findings)

        extractor_engine = str(extraction.get("engine") or "unknown")
        extraction_quality = str(extraction.get("analysis_quality") or "unknown")
        extractor_summary = {
            "extractor": extractor_engine,
            "analysis_quality": extraction_quality,
        }
        if extractor_engine == "androguard+archive":
            engines.append(
                _status(
                    "androguard",
                    "Androguard",
                    "completed",
                    duration_ms=0,
                    summary=extractor_summary,
                )
            )
        elif _module_available("androguard"):
            engines.append(
                _status(
                    "androguard",
                    "Androguard",
                    "failed",
                    duration_ms=0,
                    error="Structured extraction fell back to bounded archive evidence; inspect restricted worker logs",
                    summary=extractor_summary,
                )
            )
        else:
            engines.append(
                _status(
                    "androguard",
                    "Androguard",
                    "unavailable",
                    duration_ms=0,
                    error="Androguard is not installed; bounded archive extraction was used",
                    summary=extractor_summary,
                )
            )

        for enabled, available, engine_id, label, runner in (
            (
                self.settings.apkid_enabled,
                _module_available("apkid"),
                "apkid",
                "APKiD packer and anti-analysis detection",
                lambda: self._apkid(path),
            ),
            (
                self.settings.yara_enabled,
                _module_available("yara") and self.settings.yara_rules_path.is_file(),
                "yara",
                "YARA banking behavior rules",
                lambda: self._yara(path),
            ),
            (
                self.settings.signature_verification_enabled,
                bool(shutil.which(self.settings.apksigner_path)),
                "apksigner",
                "Android signature verifier",
                lambda: self._apksigner(path),
            ),
            (
                self.settings.similarity_enabled,
                _module_available("ssdeep") or _module_available("dexofuzzy"),
                "similarity",
                "ssdeep and Dexofuzzy fingerprints",
                lambda: self._similarity(path),
            ),
            (
                self.settings.quark_enabled,
                _quark_available(self.settings),
                "quark",
                "Quark behavior rules",
                lambda: self._quark(path),
            ),
        ):
            if not enabled:
                engines.append(_status(engine_id, label, "disabled", duration_ms=0))
                continue
            if not available:
                engines.append(
                    _status(
                        engine_id,
                        label,
                        "unavailable",
                        duration_ms=0,
                        error="Optional engine or its offline rule data is not installed",
                    )
                )
                continue
            engine, normalized = self._guarded(engine_id, label, runner)
            engines.append(engine)
            findings.extend(normalized)

        if self.settings.mobsf_enabled:
            if not self.settings.mobsf_allow_binary_transfer:
                engines.append(
                    _status(
                        "mobsf",
                        "Self-hosted MobSF",
                        "blocked-by-policy",
                        duration_ms=0,
                        error="Binary transfer requires FRAUDSHIELD_MOBSF_ALLOW_BINARY_TRANSFER=true",
                        privacy="configured-private-service",
                    )
                )
            elif not self.settings.mobsf_url or not self.settings.mobsf_api_key:
                engines.append(
                    _status(
                        "mobsf",
                        "Self-hosted MobSF",
                        "unavailable",
                        duration_ms=0,
                        error="MobSF URL and API key are required",
                        privacy="configured-private-service",
                    )
                )
            else:
                engine, normalized = self._guarded(
                    "mobsf",
                    "Self-hosted MobSF",
                    lambda: self._mobsf(path),
                    privacy="configured-private-service",
                )
                engines.append(engine)
                findings.extend(normalized)
        else:
            engines.append(
                _status(
                    "mobsf",
                    "Self-hosted MobSF",
                    "disabled",
                    duration_ms=0,
                    privacy="configured-private-service",
                )
            )

        reputation, reputation_engines = self._reputation(sha256)
        engines.extend(reputation_engines)
        deduplicated = self._deduplicate_findings(findings)
        completed = sum(item["status"] == "completed" for item in engines)
        unavailable = sum(item["status"] in {"unavailable", "failed", "blocked-by-policy"} for item in engines)
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
                "tracker_count": len(native.get("summary", {}).get("trackers", [])),
            },
            "engines": engines,
            "normalized_findings": deduplicated,
            "reputation": reputation,
            "coverage_note": (
                "A missing or failed optional engine reduces coverage; it does not imply that the APK is legitimate."
            ),
            "base_extractor": extraction.get("engine", "unknown"),
        }

    def _guarded(
        self,
        engine_id: str,
        label: str,
        runner: Callable[[], tuple[dict[str, Any], list[dict[str, Any]]]],
        *,
        privacy: str = "local-only",
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        started = time.perf_counter()
        try:
            summary, findings = runner()
            return (
                _status(
                    engine_id,
                    label,
                    "completed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    summary=summary,
                    privacy=privacy,
                ),
                findings,
            )
        except Exception as exc:
            logger.warning("Optional APK engine %s failed: %s", engine_id, type(exc).__name__)
            return (
                _status(
                    engine_id,
                    label,
                    "failed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"{type(exc).__name__}: engine did not complete; inspect restricted worker logs",
                    privacy=privacy,
                ),
                [],
            )

    def _native_inventory(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        abis: set[str] = set()
        native_libraries: list[str] = []
        dex_files: list[str] = []
        nested_payloads: list[str] = []
        trackers: set[str] = set()
        scanned = 0
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                lower = entry.filename.lower()
                if lower.startswith("lib/") and lower.endswith(".so"):
                    native_libraries.append(entry.filename)
                    parts = entry.filename.split("/")
                    if len(parts) > 2:
                        abis.add(parts[1])
                if lower.endswith(".dex"):
                    dex_files.append(entry.filename)
                if lower.startswith("assets/") and lower.endswith((".apk", ".dex", ".jar", ".so")):
                    nested_payloads.append(entry.filename)
                if lower.endswith((".dex", ".xml", ".json", ".txt")) and scanned < 32 * 1024 * 1024:
                    limit = min(entry.file_size, 8 * 1024 * 1024, 32 * 1024 * 1024 - scanned)
                    if limit <= 0:
                        continue
                    with archive.open(entry) as source:
                        data = source.read(limit)
                    scanned += len(data)
                    for tracker, marker in _TRACKER_MARKERS:
                        if marker in data:
                            trackers.add(tracker)
        findings: list[dict[str, Any]] = []
        if len(dex_files) > 1:
            findings.append(
                {
                    "id": "NATIVE:multidex",
                    "engine": "archive_native",
                    "title": "Multiple DEX files present",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "risk_category": "evasion_resilience",
                    "risk_points": 0,
                    "evidence": dex_files[:20],
                    "score_eligible": False,
                }
            )
        return (
            {
                "abis": sorted(abis),
                "native_library_count": len(native_libraries),
                "native_libraries": native_libraries[:100],
                "dex_files": dex_files[:30],
                "nested_payloads": nested_payloads[:50],
                "trackers": sorted(trackers),
                "tracker_notice": "Presence indicates an embedded SDK, not malware by itself.",
            },
            findings,
        )

    def _apkid(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        from apkid.apkid import Options, Scanner
        from apkid.output import OutputFormatter
        from apkid.rules import RulesManager

        options = Options(
            timeout=min(10, self.settings.engine_timeout_seconds),
            verbose=False,
            entry_max_scan_size=min(self.settings.max_apk_bytes, 64 * 1024 * 1024),
            recursive=True,
        )
        formatter = OutputFormatter(
            json_output=True,
            output_dir=None,
            rules_manager=RulesManager(),
            include_types=False,
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
                        _bounded_text(value, 200) for value in values
                    )
        findings: list[dict[str, Any]] = []
        for category, values in sorted(category_values.items()):
            normalized = category.lower().replace("-", "_").replace(" ", "_")
            score_eligible = any(
                token in normalized
                for token in ("packer", "obfuscat", "anti_vm", "anti_debug", "anti_disassembly")
            )
            points = 16 if "packer" in normalized else 12 if score_eligible else 0
            findings.append(
                {
                    "id": f"APKID:{_safe_id(normalized)}",
                    "engine": "apkid",
                    "title": f"APKiD {category}",
                    "severity": "HIGH" if points >= 16 else "MEDIUM" if points else "INFO",
                    "confidence": 0.86,
                    "risk_category": "evasion_resilience",
                    "risk_points": points,
                    "evidence": sorted(values)[:30],
                    "score_eligible": score_eligible,
                }
            )
        return {
            "match_categories": {key: sorted(values)[:30] for key, values in category_values.items()},
            "match_count": sum(len(values) for values in category_values.values()),
        }, findings

    def _yara(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        import yara

        rules = yara.compile(filepath=str(self.settings.yara_rules_path))
        matches: list[dict[str, Any]] = []
        scanned_entries = 0
        scanned_bytes = 0
        deadline = time.monotonic() + self.settings.engine_timeout_seconds

        def add_matches(target: str, data: bytes) -> None:
            nonlocal scanned_entries, scanned_bytes
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            scanned_entries += 1
            scanned_bytes += len(data)
            per_target_timeout = max(1, min(5, math.ceil(remaining)))
            for match in rules.match(data=data, timeout=per_target_timeout):
                metadata = dict(getattr(match, "meta", {}) or {})
                matches.append(
                    {
                        "rule": str(match.rule),
                        "target": target,
                        "namespace": str(getattr(match, "namespace", "default")),
                        "metadata": {str(key): _bounded_text(value, 300) for key, value in metadata.items()},
                    }
                )

        with path.open("rb") as source:
            add_matches(path.name, source.read(min(path.stat().st_size, 16 * 1024 * 1024)))
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if (
                    scanned_entries >= 250
                    or scanned_bytes >= 64 * 1024 * 1024
                    or time.monotonic() >= deadline
                ):
                    break
                lower = entry.filename.lower()
                if not lower.endswith((".dex", ".xml", ".json", ".txt", ".js", ".so")):
                    continue
                limit = min(entry.file_size, 8 * 1024 * 1024, 64 * 1024 * 1024 - scanned_bytes)
                if limit <= 0:
                    break
                with archive.open(entry) as source:
                    add_matches(entry.filename, source.read(limit))

        dedup: dict[tuple[str, str], dict[str, Any]] = {}
        for match in matches:
            dedup[(match["rule"], match["target"])] = match
        matches = list(dedup.values())[:100]
        findings = []
        for match in matches:
            meta = match["metadata"]
            category = meta.get("risk_category", "evasion_resilience")
            if category not in {
                "credential_theft",
                "payment_manipulation",
                "fraud_impersonation",
                "evasion_resilience",
            }:
                category = "evasion_resilience"
            try:
                points = max(0, min(30, int(meta.get("risk_points", "0"))))
            except ValueError:
                points = 0
            findings.append(
                {
                    "id": f"YARA:{_safe_id(match['rule'])}",
                    "engine": "yara",
                    "title": meta.get("title", match["rule"]),
                    "severity": meta.get("severity", "MEDIUM").upper(),
                    "confidence": 0.9,
                    "risk_category": category,
                    "risk_points": points,
                    "evidence": [f"rule={match['rule']}", f"target={match['target']}"],
                    "score_eligible": points > 0,
                }
            )
        return {
            "rule_file": self.settings.yara_rules_path.name,
            "matches": matches,
            "match_count": len(matches),
            "scanned_entries": scanned_entries,
            "scanned_bytes": scanned_bytes,
        }, findings

    def _apksigner(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        executable = shutil.which(self.settings.apksigner_path)
        if not executable:
            raise RuntimeError("apksigner executable is unavailable")
        completed = subprocess.run(
            [executable, "verify", "--verbose", "--print-certs", str(path.resolve())],
            check=False,
            capture_output=True,
            text=True,
            timeout=self.settings.engine_timeout_seconds,
        )
        output = (completed.stdout + "\n" + completed.stderr)[: self.settings.max_engine_output_bytes]
        output = output.replace(str(path.resolve()), "<apk>").replace(str(path), "<apk>")
        certificate_digests = sorted(
            {
                value.replace(":", "").lower()
                for value in re.findall(
                    r"certificate SHA-256 digest:\s*([0-9A-Fa-f:]{64,95})",
                    output,
                    flags=re.IGNORECASE,
                )
            }
        )
        verified = completed.returncode == 0
        findings = []
        if not verified:
            findings.append(
                {
                    "id": "APKSIGNER:verification-failed",
                    "engine": "apksigner",
                    "title": "APK signature verification failed",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "risk_category": "fraud_impersonation",
                    "risk_points": 24,
                    "evidence": [line[:300] for line in output.splitlines() if line.strip()][-8:],
                    "score_eligible": True,
                }
            )
        schemes = {}
        for version in ("v1", "v2", "v3", "v4"):
            match = re.search(rf"Verified using {version} scheme.*?:\s*(true|false)", output, re.I)
            if match:
                schemes[version] = match.group(1).lower() == "true"
        return {
            "verified": verified,
            "certificate_sha256": certificate_digests,
            "schemes": schemes,
            "tool_exit_code": completed.returncode,
        }, findings

    def _similarity(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
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

    def _quark(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        from quark.core.quark import Quark
        from quark.core.struct.ruleobject import RuleObject

        analyzer = Quark(str(path))
        reports: list[dict[str, Any]] = []
        rules = sorted(
            list(self.settings.quark_rules_dir.glob("*.json"))
            or list(self.settings.quark_rules_dir.rglob("*.json"))
        )[: self.settings.quark_max_rules]
        for rule_path in rules:
            rule = RuleObject(str(rule_path))
            try:
                analyzer.run(rule)
                analyzer.generate_json_report(rule)
            except Exception:
                logger.debug("Quark rule failed: %s", rule_path.name, exc_info=True)
        raw = analyzer.get_json_report() or []
        if isinstance(raw, dict):
            raw = raw.get("report") or raw.get("rules") or [raw]
        if isinstance(raw, list):
            reports = [item for item in raw if isinstance(item, dict)][:200]
        findings = []
        report_summaries: list[dict[str, str]] = []
        for index, report in enumerate(reports[:50]):
            description = _bounded_text(
                report.get("crime") or report.get("description") or report.get("rule") or "Quark behavior",
                300,
            )
            report_summaries.append(
                {
                    "rule": _bounded_text(report.get("rule") or report.get("rule_name") or "", 160),
                    "description": description,
                }
            )
            lower = description.lower()
            category = (
                "credential_theft"
                if any(token in lower for token in ("sms", "credential", "password", "otp"))
                else "payment_manipulation"
                if any(token in lower for token in ("accessibility", "overlay", "transaction"))
                else "evasion_resilience"
            )
            findings.append(
                {
                    "id": f"QUARK:{index + 1}:{_safe_id(description)}",
                    "engine": "quark",
                    "title": description,
                    "severity": "MEDIUM",
                    "confidence": 0.75,
                    "risk_category": category,
                    "risk_points": 8,
                    "evidence": [description],
                    "score_eligible": True,
                }
            )
        return {
            "rules_executed": len(rules),
            "report_count": len(reports),
            "report_summaries": report_summaries,
        }, findings

    def _mobsf(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        base = self.settings.mobsf_url.rstrip("/")
        headers = {"Authorization": self.settings.mobsf_api_key}
        scan_hash = ""
        report: dict[str, Any] = {}
        with httpx.Client(timeout=self.settings.engine_timeout_seconds, headers=headers) as client:
            try:
                with path.open("rb") as source:
                    upload = client.post(
                        f"{base}/api/v1/upload",
                        files={"file": (path.name, source, "application/vnd.android.package-archive")},
                    )
                upload.raise_for_status()
                uploaded = upload.json()
                scan_hash = str(uploaded.get("hash") or uploaded.get("scan_hash") or "")
                if not scan_hash:
                    raise RuntimeError("MobSF upload did not return a scan hash")
                scan = client.post(f"{base}/api/v1/scan", data={"hash": scan_hash})
                scan.raise_for_status()
                report_response = client.post(
                    f"{base}/api/v1/report_json", data={"hash": scan_hash}
                )
                report_response.raise_for_status()
                parsed_report = report_response.json()
                if not isinstance(parsed_report, dict):
                    raise RuntimeError("MobSF returned an invalid report shape")
                report = parsed_report
            finally:
                if scan_hash:
                    try:
                        cleanup = client.post(
                            f"{base}/api/v1/delete_scan", data={"hash": scan_hash}
                        )
                        cleanup.raise_for_status()
                    except Exception:
                        logger.warning("MobSF scan cleanup failed for %s", scan_hash[:12])
        manifest_findings = report.get("manifest_analysis") or []
        code_findings = report.get("code_analysis") or {}
        if isinstance(code_findings, dict):
            code_findings = list(code_findings.values())
        high_items: list[str] = []
        for item in [*manifest_findings, *(code_findings if isinstance(code_findings, list) else [])]:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity") or item.get("level") or "").lower()
            if severity in {"high", "critical"}:
                high_items.append(
                    _bounded_text(item.get("title") or item.get("description") or item.get("name"), 300)
                )
        findings = [
            {
                "id": f"MOBSF:{index + 1}:{_safe_id(title)}",
                "engine": "mobsf",
                "title": title,
                "severity": "HIGH",
                "confidence": 0.8,
                "risk_category": "evasion_resilience",
                "risk_points": 6,
                "evidence": [title],
                "score_eligible": True,
            }
            for index, title in enumerate(high_items[:5])
            if title
        ]
        appsec = report.get("appsec")
        if not isinstance(appsec, dict):
            appsec = {}
        trackers = report.get("trackers")
        return {
            "scan_hash": scan_hash,
            "security_score": report.get("security_score") or appsec.get("security_score"),
            "high_severity_finding_count": len(high_items),
            "trackers": [_bounded_text(value, 160) for value in list(trackers.keys())[:100]]
            if isinstance(trackers, dict)
            else [],
        }, findings

    def _reputation(self, sha256: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if not self.settings.reputation_enabled:
            return (
                {
                    "verdict": "not-queried",
                    "known_malicious": False,
                    "providers": [],
                    "notice": "External reputation is disabled. This state is not evidence that the APK is safe.",
                },
                [
                    _status(
                        "virustotal",
                        "VirusTotal hash reputation",
                        "disabled",
                        duration_ms=0,
                        privacy="hash-only-external",
                    ),
                    _status(
                        "malwarebazaar",
                        "MalwareBazaar hash reputation",
                        "disabled",
                        duration_ms=0,
                        privacy="hash-only-external",
                    ),
                ],
            )

        providers: list[dict[str, Any]] = []
        statuses: list[dict[str, Any]] = []
        if self.settings.virustotal_api_key:
            started = time.perf_counter()
            try:
                with httpx.Client(timeout=self.settings.external_lookup_timeout_seconds) as client:
                    response = client.get(
                        f"https://www.virustotal.com/api/v3/files/{sha256}",
                        headers={"x-apikey": self.settings.virustotal_api_key},
                    )
                if response.status_code == 404:
                    provider = {"id": "virustotal", "status": "not-found", "malicious": 0, "suspicious": 0}
                else:
                    response.raise_for_status()
                    attributes = response.json().get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats") or {}
                    provider = {
                        "id": "virustotal",
                        "status": "found",
                        "malicious": int(stats.get("malicious", 0)),
                        "suspicious": int(stats.get("suspicious", 0)),
                        "harmless": int(stats.get("harmless", 0)),
                        "undetected": int(stats.get("undetected", 0)),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                    }
                providers.append(provider)
                statuses.append(
                    _status(
                        "virustotal",
                        "VirusTotal hash reputation",
                        "completed",
                        duration_ms=(time.perf_counter() - started) * 1000,
                        summary=provider,
                        privacy="hash-only-external",
                    )
                )
            except Exception as exc:
                logger.warning("VirusTotal hash lookup failed: %s", type(exc).__name__)
                statuses.append(
                    _status(
                        "virustotal",
                        "VirusTotal hash reputation",
                        "failed",
                        duration_ms=(time.perf_counter() - started) * 1000,
                        error=f"{type(exc).__name__}: lookup did not complete; inspect restricted worker logs",
                        privacy="hash-only-external",
                    )
                )
        else:
            statuses.append(
                _status(
                    "virustotal",
                    "VirusTotal hash reputation",
                    "unavailable",
                    duration_ms=0,
                    error="API key is not configured",
                    privacy="hash-only-external",
                )
            )

        started = time.perf_counter()
        try:
            headers = (
                {"Auth-Key": self.settings.malwarebazaar_api_key}
                if self.settings.malwarebazaar_api_key
                else {}
            )
            with httpx.Client(timeout=self.settings.external_lookup_timeout_seconds) as client:
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
            provider = {
                "id": "malwarebazaar",
                "status": "found" if found else "not-found",
                "signature": _bounded_text(first.get("signature") or "", 200),
                "file_type": _bounded_text(first.get("file_type") or "", 50),
                "first_seen": first.get("first_seen"),
                "tags": [_bounded_text(value, 80) for value in (first.get("tags") or [])[:30]],
            }
            providers.append(provider)
            statuses.append(
                _status(
                    "malwarebazaar",
                    "MalwareBazaar hash reputation",
                    "completed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    summary=provider,
                    privacy="hash-only-external",
                )
            )
        except Exception as exc:
            logger.warning("MalwareBazaar hash lookup failed: %s", type(exc).__name__)
            statuses.append(
                _status(
                    "malwarebazaar",
                    "MalwareBazaar hash reputation",
                    "failed",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"{type(exc).__name__}: lookup did not complete; inspect restricted worker logs",
                    privacy="hash-only-external",
                )
            )

        vt_malicious = next(
            (int(item.get("malicious", 0)) for item in providers if item["id"] == "virustotal"),
            0,
        )
        mb_found = any(
            item["id"] == "malwarebazaar" and item.get("status") == "found" for item in providers
        )
        known_malicious = mb_found or vt_malicious >= self.settings.virustotal_malicious_threshold
        found_any = any(item.get("status") == "found" for item in providers)
        return {
            "verdict": "known-malicious" if known_malicious else "known-file" if found_any else "not-found",
            "known_malicious": known_malicious,
            "providers": providers,
            "notice": (
                "Only the SHA-256 was transmitted. A not-found or zero-detection result is not proof of legitimacy."
            ),
        }, statuses

    @staticmethod
    def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in findings:
            key = (str(finding.get("engine")), str(finding.get("id")))
            unique[key] = finding
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        return sorted(
            unique.values(),
            key=lambda item: (
                -severity_order.get(str(item.get("severity", "INFO")).upper(), 0),
                -int(item.get("risk_points", 0)),
                str(item.get("id")),
            ),
        )[:150]


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
