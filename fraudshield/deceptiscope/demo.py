from __future__ import annotations

from typing import Any


def hero_apk_profile() -> dict[str, Any]:
    """Explicit synthetic fixture. It is never used as an error fallback."""
    return {
        "schema_version": "3.0",
        "extractor_version": "demo-fixture-2026.4",
        "analysis_mode": "static",
        "analysis_quality": "synthetic",
        "engine": "explicit-demo-fixture",
        "warnings": ["Synthetic demonstration evidence; not derived from a submitted APK."],
        "file": {
            "name": "BOI-Rewards-DEMO.apk",
            "size_bytes": 0,
            "sha256": "0" * 64,
            "archive_entry_count": 0,
            "dex_files": ["classes.dex"],
            "native_library_count": 0,
            "embedded_payloads": ["assets/update.dex"],
        },
        "app": {
            "package_name": "com.fraudshield.demo.fakebank",
            "app_label": "BOI Rewards Secure",
            "version_name": "2.4.1-demo",
            "version_code": "241",
            "min_sdk": "24",
            "target_sdk": "35",
        },
        "permissions": {
            "requested": [
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.QUERY_ALL_PACKAGES",
            ],
            "flagged_dangerous": [
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.QUERY_ALL_PACKAGES",
            ],
        },
        "components": {
            "activities": ["com.fraudshield.demo.fakebank.MainActivity"],
            "services": ["com.fraudshield.demo.fakebank.CaptureService"],
            "receivers": ["com.fraudshield.demo.fakebank.SmsReceiver"],
            "providers": [],
            "exported": [{"type": "receiver", "name": "com.fraudshield.demo.fakebank.SmsReceiver"}],
            "sms_receiver": True,
            "boot_receiver": True,
            "accessibility_service": True,
        },
        "certificate": {
            "issuer": "CN=FraudShield Demo Debug",
            "subject": "CN=FraudShield Demo Debug",
            "is_self_signed": True,
            "sha256": "1" * 64,
            "signature_entries": [],
            "trust_evaluation": "not_in_trusted_inventory",
            "bank_impersonation_flag": True,
        },
        "network_indicators": {
            "urls": ["https://c2-demo.fraudshield.invalid/gate"],
            "domains": ["c2-demo.fraudshield.invalid"],
            "ips": ["198.51.100.42"],
        },
        "code_signals": {
            "dynamic_code_loading": {"detected": True, "evidence": ["DexClassLoader"]},
            "reflection": {"detected": True, "evidence": ["java/lang/reflect"]},
            "sms_api": {"detected": True, "evidence": ["SmsManager"]},
            "installed_app_enumeration": {"detected": True, "evidence": ["getInstalledApplications"]},
            "crypto_api": {"detected": True, "evidence": ["javax/crypto"]},
            "command_execution": {"detected": False, "evidence": []},
            "accessibility_api": {"detected": True, "evidence": ["AccessibilityService"]},
            "input_injection": {"detected": True, "evidence": ["dispatchGesture"]},
            "webview_bridge": {"detected": False, "evidence": []},
            "device_admin": {"detected": False, "evidence": []},
        },
        "obfuscation": {
            "class_count_observed": 120,
            "short_class_count": 65,
            "short_class_ratio": 0.5417,
            "base64_blob_count": 3,
            "likely_name_obfuscation": True,
        },
        "coverage": {"archive": True, "manifest": True, "dex": True, "certificate": True, "dynamic": False},
    }
