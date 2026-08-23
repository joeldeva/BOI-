from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from fraudshield.core.config import Settings
from fraudshield.core.security import sha256_file
from fraudshield.deceptiscope.validator import validate_apk_archive


logger = logging.getLogger(__name__)
ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.PACKAGE_USAGE_STATS",
}

BANKING_BRAND_TERMS = {
    "bank",
    "banking",
    "boi",
    "bankofindia",
    "sbi",
    "hdfc",
    "icici",
    "axisbank",
    "pnb",
    "kotak",
}

CODE_PATTERNS: dict[str, tuple[bytes, ...]] = {
    "dynamic_code_loading": (b"DexClassLoader", b"PathClassLoader", b"InMemoryDexClassLoader"),
    "reflection": (b"java/lang/reflect", b"getDeclaredMethod", b"getMethod"),
    "sms_api": (b"SmsManager", b"sendTextMessage", b"Telephony$Sms"),
    "installed_app_enumeration": (b"getInstalledApplications", b"getInstalledPackages", b"queryIntentActivities"),
    "crypto_api": (b"javax/crypto", b"MessageDigest", b"SecretKeySpec"),
    "command_execution": (b"Runtime;->exec", b"ProcessBuilder", b"/system/bin/sh"),
    "accessibility_api": (b"AccessibilityService", b"onAccessibilityEvent"),
    "input_injection": (b"performGlobalAction", b"dispatchGesture", b"ACTION_SET_TEXT"),
    "webview_bridge": (b"addJavascriptInterface", b"setJavaScriptEnabled"),
    "device_admin": (b"DevicePolicyManager", b"DeviceAdminReceiver"),
}

URL_RE = re.compile(r"https?://[^\s\x00\"'<>\[\]{}()]{4,2048}", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:[a-z]{2,24})(?![\w.-])",
    re.IGNORECASE,
)
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,4096}")
CLASS_DESCRIPTOR_RE = re.compile(rb"L(?:[A-Za-z0-9_$]+/)+([A-Za-z0-9_$]{1,80});")
MAX_STATIC_SCAN_BYTES = 64 * 1024 * 1024
MAX_STATIC_ENTRY_BYTES = 24 * 1024 * 1024
MAX_SIGNATURE_ENTRY_BYTES = 10 * 1024 * 1024
NON_INDICATOR_HOSTS = {
    "schemas.android.com",
    "www.w3.org",
    "xml.org",
}
# URL hosts are accepted even with an unusual TLD. Bare strings use this
# deliberately broad set to avoid treating Java packages and Android
# permission names as threat infrastructure.
COMMON_OR_RESERVED_TLDS = {
    "ai",
    "app",
    "au",
    "bank",
    "bd",
    "biz",
    "br",
    "ca",
    "cc",
    "click",
    "cloud",
    "cn",
    "co",
    "com",
    "de",
    "dev",
    "digital",
    "email",
    "example",
    "finance",
    "fr",
    "fun",
    "hk",
    "id",
    "in",
    "info",
    "invalid",
    "io",
    "ir",
    "jp",
    "kr",
    "link",
    "live",
    "me",
    "mobi",
    "money",
    "net",
    "network",
    "nl",
    "np",
    "online",
    "one",
    "org",
    "pk",
    "pro",
    "pw",
    "ru",
    "security",
    "services",
    "sg",
    "shop",
    "site",
    "solutions",
    "space",
    "store",
    "support",
    "systems",
    "tech",
    "test",
    "today",
    "top",
    "tr",
    "tv",
    "uk",
    "us",
    "vip",
    "website",
    "win",
    "work",
    "world",
    "xyz",
    "za",
}


def _android_attr(element: ET.Element, name: str, default: str = "") -> str:
    return element.attrib.get(f"{{{ANDROID_NS}}}{name}", default)


def _clean_evidence(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore")[:240]


def _unique(items: Iterable[str], limit: int = 100) -> list[str]:
    return sorted({item for item in items if item})[:limit]


class StaticAPKExtractor:
    """Static-only APK feature extraction. The target file is never executed."""

    extractor_version = "deceptiscope-static-2026.4"

    def __init__(self, path: Path, settings: Settings, *, original_name: str | None = None) -> None:
        self.path = path
        self.settings = settings
        self.original_name = original_name or path.name

    def extract(self) -> dict[str, Any]:
        archive_facts = validate_apk_archive(self.path, self.settings)
        fallback = self._extract_archive_features(archive_facts)
        warnings = list(archive_facts["warnings"])
        try:
            androguard_features = self._extract_with_androguard()
            result = self._merge(fallback, androguard_features)
            quality = "full"
            engine = "androguard+archive"
        except Exception as exc:  # Androguard is optional; partial result stays explicit.
            logger.warning("Androguard extraction unavailable: %s", type(exc).__name__)
            warnings.append(
                "Androguard could not complete manifest/DEX parsing; archive-level evidence is reported as partial."
            )
            result = fallback
            quality = "partial"
            engine = "archive-fallback"

        result.update(
            {
                "schema_version": "3.0",
                "extractor_version": self.extractor_version,
                "analysis_mode": "static",
                "analysis_quality": quality,
                "engine": engine,
                "warnings": _unique([*result.get("warnings", []), *warnings], 50),
                "file": {
                    **result.get("file", {}),
                    "name": self.original_name,
                    "size_bytes": self.path.stat().st_size,
                    "sha256": sha256_file(self.path),
                },
                "coverage": {
                    "archive": True,
                    "manifest": result.get("app", {}).get("package_name") not in {None, "", "unknown"},
                    "dex": bool(archive_facts["dex_files"]),
                    "certificate": bool(result.get("certificate", {}).get("sha256")),
                    "dynamic": False,
                },
            }
        )
        return result

    def _extract_archive_features(self, archive_facts: dict[str, Any]) -> dict[str, Any]:
        raw_chunks: list[bytes] = []
        manifest_bytes = b""
        signature_entries: list[dict[str, Any]] = []
        payload_entries: list[str] = []
        native_libraries: list[str] = []
        truncated_entries: list[str] = []
        scan_bytes = 0

        def read_for_scan(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, entry_limit: int) -> bytes:
            nonlocal scan_bytes
            remaining = max(0, MAX_STATIC_SCAN_BYTES - scan_bytes)
            limit = min(entry_limit, remaining)
            if limit <= 0:
                truncated_entries.append(entry.filename)
                return b""
            with archive.open(entry) as source:
                data = source.read(limit + 1)
            if len(data) > limit or entry.file_size > limit:
                truncated_entries.append(entry.filename)
            bounded = data[:limit]
            scan_bytes += len(bounded)
            return bounded

        with zipfile.ZipFile(self.path) as archive:
            for entry in archive.infolist():
                lower = entry.filename.lower()
                if entry.filename == "AndroidManifest.xml":
                    manifest_bytes = read_for_scan(archive, entry, 5 * 1024 * 1024)
                    raw_chunks.append(manifest_bytes)
                elif lower.endswith(".dex"):
                    raw_chunks.append(read_for_scan(archive, entry, MAX_STATIC_ENTRY_BYTES))
                elif lower.startswith("assets/") and lower.endswith((".dex", ".apk", ".jar", ".so")):
                    payload_entries.append(entry.filename)
                    raw_chunks.append(read_for_scan(archive, entry, 10 * 1024 * 1024))
                elif lower.endswith((".xml", ".json", ".txt", ".properties", ".html", ".js", ".conf")):
                    raw_chunks.append(read_for_scan(archive, entry, 2 * 1024 * 1024))
                elif lower.startswith("lib/") and lower.endswith(".so"):
                    native_libraries.append(entry.filename)
                if lower.startswith("meta-inf/") and lower.endswith((".rsa", ".dsa", ".ec")):
                    if entry.file_size > MAX_SIGNATURE_ENTRY_BYTES:
                        truncated_entries.append(entry.filename)
                        signature_entries.append(
                            {"entry": entry.filename, "sha256": "", "status": "size_limit_exceeded"}
                        )
                        continue
                    data = archive.read(entry)
                    signature_entries.append(
                        {
                            "entry": entry.filename,
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "status": "hashed_signature_block",
                        }
                    )

        raw = b"\n".join(raw_chunks)
        strings = [_clean_evidence(match) for match in ASCII_RE.findall(raw)]
        manifest = self._parse_plain_manifest(manifest_bytes)
        network = self._network_indicators(
            strings,
            excluded={
                manifest["app"].get("package_name", ""),
                *manifest["permissions"].get("requested", []),
            },
        )
        signals = self._code_signals(raw)
        obfuscation = self._obfuscation(raw)
        return {
            "file": {
                "archive_entry_count": archive_facts["entry_count"],
                "uncompressed_bytes": archive_facts["uncompressed_bytes"],
                "compression_ratio": archive_facts["compression_ratio"],
                "dex_files": archive_facts["dex_files"],
                "native_library_count": len(native_libraries),
                "embedded_payloads": _unique(payload_entries, 100),
                "static_scan_bytes": scan_bytes,
                "scan_truncated_entries": _unique(truncated_entries, 100),
            },
            "app": manifest["app"],
            "permissions": manifest["permissions"],
            "components": manifest["components"],
            "certificate": {
                "issuer": "",
                "subject": "",
                "is_self_signed": None,
                # A JAR signature block hash is useful provenance, but is not
                # the signing certificate hash. Only Androguard-populated
                # certificate bytes are emitted as certificate_sha256 IOCs.
                "sha256": "",
                "signature_entries": signature_entries[:20],
                "trust_evaluation": "certificate_unavailable",
                "bank_impersonation_flag": False,
            },
            "network_indicators": network,
            "code_signals": signals,
            "obfuscation": obfuscation,
            "warnings": [
                *manifest["warnings"],
                *(
                    [
                        "Static string scanning reached a per-entry or total byte limit; findings may be incomplete."
                    ]
                    if truncated_entries
                    else []
                ),
            ],
        }

    def _parse_plain_manifest(self, data: bytes) -> dict[str, Any]:
        empty = {
            "app": {
                "package_name": "unknown",
                "app_label": "Unknown",
                "version_name": "",
                "version_code": "",
                "min_sdk": "",
                "target_sdk": "",
            },
            "permissions": {"requested": [], "flagged_dangerous": []},
            "components": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
                "exported": [],
                "sms_receiver": False,
                "boot_receiver": False,
                "accessibility_service": False,
            },
            "warnings": [],
        }
        if not data.lstrip().startswith(b"<"):
            empty["warnings"].append("Binary AndroidManifest.xml requires Androguard for semantic parsing.")
            return empty
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            empty["warnings"].append("Plain-text AndroidManifest.xml could not be parsed.")
            return empty

        uses_sdk = root.find("uses-sdk")
        app_el = root.find("application")
        requested = _unique(_android_attr(el, "name") for el in root.findall("uses-permission"))
        app = {
            "package_name": root.attrib.get("package", "unknown"),
            "app_label": _android_attr(app_el, "label", "Unknown") if app_el is not None else "Unknown",
            "version_name": _android_attr(root, "versionName"),
            "version_code": _android_attr(root, "versionCode"),
            "min_sdk": _android_attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else "",
            "target_sdk": _android_attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else "",
        }
        components: dict[str, Any] = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported": [],
            "sms_receiver": False,
            "boot_receiver": False,
            "accessibility_service": False,
        }
        if app_el is not None:
            for tag, key in (("activity", "activities"), ("service", "services"), ("receiver", "receivers"), ("provider", "providers")):
                for element in app_el.findall(tag):
                    name = _android_attr(element, "name")
                    if name:
                        components[key].append(name)
                    actions = {
                        _android_attr(action, "name")
                        for action in element.findall("./intent-filter/action")
                    }
                    explicit = _android_attr(element, "exported").lower()
                    exported = explicit == "true" or (not explicit and bool(actions))
                    if exported and name:
                        components["exported"].append({"type": tag, "name": name})
                    if "android.provider.Telephony.SMS_RECEIVED" in actions:
                        components["sms_receiver"] = True
                    if "android.intent.action.BOOT_COMPLETED" in actions:
                        components["boot_receiver"] = True
                    if tag == "service" and (
                        _android_attr(element, "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE"
                        or "android.accessibilityservice.AccessibilityService" in actions
                    ):
                        components["accessibility_service"] = True
        for key in ("activities", "services", "receivers", "providers"):
            components[key] = _unique(components[key], 500)
        return {
            "app": app,
            "permissions": {
                "requested": requested,
                "flagged_dangerous": sorted(set(requested) & DANGEROUS_PERMISSIONS),
            },
            "components": components,
            "warnings": [],
        }

    def _network_indicators(
        self,
        strings: list[str],
        *,
        excluded: set[str] | None = None,
    ) -> dict[str, list[str]]:
        urls: set[str] = set()
        domains: set[str] = set()
        ips: set[str] = set()
        excluded_values = {value.lower().rstrip(".") for value in (excluded or set()) if value}
        for text in strings:
            for url in URL_RE.findall(text):
                candidate = url.rstrip(".,;:!?)\"]'")
                host = urlsplit(candidate).hostname
                if host:
                    try:
                        address = ipaddress.ip_address(host)
                        if not (address.is_loopback or address.is_unspecified or address.is_multicast):
                            ips.add(str(address))
                            urls.add(candidate)
                    except ValueError:
                        normalized = host.lower().rstrip(".")
                        if self._is_domain_candidate(normalized, excluded_values, require_known_tld=False):
                            urls.add(candidate)
                            domains.add(normalized)
            for raw_ip in IP_RE.findall(text):
                try:
                    address = ipaddress.ip_address(raw_ip)
                    if not (address.is_loopback or address.is_unspecified or address.is_multicast):
                        ips.add(str(address))
                except ValueError:
                    continue
            for item in DOMAIN_RE.findall(text):
                normalized = item.lower().rstrip(".")
                if self._is_domain_candidate(normalized, excluded_values, require_known_tld=True):
                    domains.add(normalized)
        return {
            "urls": sorted(urls)[:100],
            "domains": sorted(domains)[:100],
            "ips": sorted(ips)[:100],
        }

    @staticmethod
    def _is_domain_candidate(
        host: str,
        excluded: set[str],
        *,
        require_known_tld: bool,
    ) -> bool:
        if not host or host in excluded or host in NON_INDICATOR_HOSTS:
            return False
        if host.endswith(".android.com") or host.endswith(".w3.org"):
            return False
        labels = host.split(".")
        if len(labels) < 2 or any(not label for label in labels):
            return False
        return not require_known_tld or labels[-1] in COMMON_OR_RESERVED_TLDS

    def _code_signals(self, raw: bytes) -> dict[str, Any]:
        evidence: dict[str, list[str]] = {}
        for name, patterns in CODE_PATTERNS.items():
            matches: list[str] = []
            for pattern in patterns:
                if pattern.lower() in raw.lower():
                    matches.append(pattern.decode("ascii", errors="ignore"))
            evidence[name] = matches
        return {
            name: {"detected": bool(matches), "evidence": matches}
            for name, matches in evidence.items()
        }

    def _obfuscation(self, raw: bytes) -> dict[str, Any]:
        names = [match.decode("ascii", errors="ignore") for match in CLASS_DESCRIPTOR_RE.findall(raw)]
        unique_names = set(names)
        short = {name for name in unique_names if len(name.replace("$", "")) <= 2}
        ratio = len(short) / len(unique_names) if unique_names else 0.0
        base64_candidates = {
            value.decode("ascii", errors="ignore")
            for value in re.findall(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])", raw)
        }
        return {
            "class_count_observed": len(unique_names),
            "short_class_count": len(short),
            "short_class_ratio": round(ratio, 4),
            "base64_blob_count": len(base64_candidates),
            "likely_name_obfuscation": len(unique_names) >= 20 and ratio >= 0.35,
        }

    def _extract_with_androguard(self) -> dict[str, Any]:
        try:
            from loguru import logger as loguru_logger
            loguru_logger.disable("androguard")
        except Exception:
            pass

        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        apk = APK(str(self.path))
        requested = sorted(set(apk.get_permissions() or []))
        app = {
            "package_name": str(apk.get_package() or "unknown"),
            "app_label": str(apk.get_app_name() or "Unknown"),
            "version_name": str(apk.get_androidversion_name() or ""),
            "version_code": str(apk.get_androidversion_code() or ""),
            "min_sdk": str(apk.get_min_sdk_version() or ""),
            "target_sdk": str(apk.get_target_sdk_version() or ""),
        }
        components = self._components_from_androguard(apk)
        certificate = self._certificate_from_androguard(apk, app)
        class_names: list[str] = []
        try:
            dex_objects = [
                DEX(dex_bytes, using_api=apk.get_target_sdk_version())
                for dex_bytes in apk.get_all_dex()
            ]
            for dex in dex_objects:
                class_names.extend(str(cls.get_name()) for cls in dex.get_classes())
        except Exception:
            pass
        if class_names:
            short = [name for name in class_names if len(name.rstrip(";").rsplit("/", 1)[-1]) <= 2]
            obfuscation = {
                "class_count_observed": len(class_names),
                "short_class_count": len(short),
                "short_class_ratio": round(len(short) / len(class_names), 4),
                "likely_name_obfuscation": len(class_names) >= 20 and len(short) / len(class_names) >= 0.35,
            }
        else:
            obfuscation = {}
        return {
            "app": app,
            "permissions": {
                "requested": requested,
                "flagged_dangerous": sorted(set(requested) & DANGEROUS_PERMISSIONS),
            },
            "components": components,
            "certificate": certificate,
            "obfuscation": obfuscation,
        }

    def _components_from_androguard(self, apk: Any) -> dict[str, Any]:
        activities = sorted(set(apk.get_activities() or []))
        services = sorted(set(apk.get_services() or []))
        receivers = sorted(set(apk.get_receivers() or []))
        providers = sorted(set(apk.get_providers() or []))
        exported: list[dict[str, str]] = []
        sms_receiver = False
        boot_receiver = False
        accessibility = False
        try:
            root = apk.get_android_manifest_xml()
            parsed = self._parse_manifest_element(root)
            exported = parsed["exported"]
            sms_receiver = parsed["sms_receiver"]
            boot_receiver = parsed["boot_receiver"]
            accessibility = parsed["accessibility_service"]
        except Exception:
            pass
        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "exported": exported,
            "sms_receiver": sms_receiver,
            "boot_receiver": boot_receiver,
            "accessibility_service": accessibility,
        }

    def _parse_manifest_element(self, root: Any) -> dict[str, Any]:
        result: dict[str, Any] = {
            "exported": [],
            "sms_receiver": False,
            "boot_receiver": False,
            "accessibility_service": False,
        }
        for tag in ("activity", "service", "receiver", "provider"):
            for element in root.findall(f".//{tag}"):
                name = _android_attr(element, "name")
                actions = {_android_attr(action, "name") for action in element.findall("./intent-filter/action")}
                explicit = _android_attr(element, "exported").lower()
                if name and (explicit == "true" or (not explicit and bool(actions))):
                    result["exported"].append({"type": tag, "name": name})
                result["sms_receiver"] |= "android.provider.Telephony.SMS_RECEIVED" in actions
                result["boot_receiver"] |= "android.intent.action.BOOT_COMPLETED" in actions
                if tag == "service":
                    result["accessibility_service"] |= (
                        _android_attr(element, "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE"
                        or "android.accessibilityservice.AccessibilityService" in actions
                    )
        return result

    def _certificate_from_androguard(self, apk: Any, app: dict[str, Any]) -> dict[str, Any]:
        issuer = ""
        subject = ""
        cert_sha256 = ""
        is_self_signed: bool | None = None
        try:
            certs = apk.get_certificates() or []
            if certs:
                cert = certs[0]
                issuer = str(getattr(getattr(cert, "issuer", None), "human_friendly", getattr(cert, "issuer", "")))
                subject = str(getattr(getattr(cert, "subject", None), "human_friendly", getattr(cert, "subject", "")))
                is_self_signed = issuer == subject if issuer and subject else None
                try:
                    cert_sha256 = hashlib.sha256(cert.dump()).hexdigest()
                except Exception:
                    pass
        except Exception:
            pass
        brand_text = f"{app.get('package_name', '')} {app.get('app_label', '')}".lower()
        claims_bank = any(term in brand_text for term in BANKING_BRAND_TERMS)
        trusted_hashes = {
            value.lower().replace(":", "") for value in self.settings.trusted_bank_cert_sha256
        }
        if not cert_sha256:
            trust_evaluation = "certificate_unavailable"
        elif not trusted_hashes:
            trust_evaluation = "trusted_inventory_not_configured"
        elif cert_sha256.lower() in trusted_hashes:
            trust_evaluation = "trusted"
        else:
            trust_evaluation = "not_in_trusted_inventory"
        return {
            "issuer": issuer,
            "subject": subject,
            "is_self_signed": is_self_signed,
            "sha256": cert_sha256,
            "signature_entries": [],
            "trust_evaluation": trust_evaluation,
            "bank_impersonation_flag": bool(
                claims_bank and trust_evaluation == "not_in_trusted_inventory"
            ),
        }

    @staticmethod
    def _merge(base: dict[str, Any], preferred: dict[str, Any]) -> dict[str, Any]:
        result = dict(base)
        for key, value in preferred.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = {**result[key], **{k: v for k, v in value.items() if v not in (None, "", [], {})}}
            elif value not in (None, "", [], {}):
                result[key] = value
        return result
