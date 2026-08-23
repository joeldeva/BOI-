from __future__ import annotations

from typing import Any


MITRE_BASE = "https://attack.mitre.org/techniques"


def map_mitre_mobile(extracted: dict[str, Any]) -> list[dict[str, Any]]:
    permissions = set(extracted.get("permissions", {}).get("requested", []))
    components = extracted.get("components", {})
    signals = extracted.get("code_signals", {})
    obfuscation = extracted.get("obfuscation", {})
    certificate = extracted.get("certificate", {})
    mappings: list[dict[str, Any]] = []

    def add(technique_id: str, name: str, evidence: list[str]) -> None:
        cleaned = sorted({item for item in evidence if item})
        if not cleaned:
            return
        mappings.append(
            {
                "technique_id": technique_id,
                "name": name,
                "evidence": cleaned,
                "source": f"{MITRE_BASE}/{technique_id.replace('.', '/')}/",
            }
        )

    sms = [permission for permission in ("android.permission.READ_SMS", "android.permission.RECEIVE_SMS") if permission in permissions]
    if components.get("sms_receiver"):
        sms.append("SMS_RECEIVED broadcast receiver")
    add("T1636.004", "Protected User Data: SMS Messages", sms)

    overlay = []
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        overlay.append("android.permission.SYSTEM_ALERT_WINDOW")
    if components.get("accessibility_service"):
        overlay.append("AccessibilityService can observe foreground application state")
    add("T1417.002", "Input Capture: GUI Input Capture", overlay)

    keylogging = []
    if components.get("accessibility_service"):
        keylogging.append("Declared AccessibilityService")
    if signals.get("accessibility_api", {}).get("detected"):
        keylogging.extend(signals["accessibility_api"].get("evidence", []))
    add("T1417.001", "Input Capture: Keylogging", keylogging)

    add(
        "T1516",
        "Input Injection",
        list(signals.get("input_injection", {}).get("evidence", [])),
    )
    add(
        "T1407",
        "Download New Code at Runtime",
        list(signals.get("dynamic_code_loading", {}).get("evidence", [])),
    )
    obfuscation_evidence: list[str] = []
    if obfuscation.get("likely_name_obfuscation"):
        obfuscation_evidence.append(f"short_class_ratio={obfuscation.get('short_class_ratio')}")
    if obfuscation.get("base64_blob_count", 0):
        obfuscation_evidence.append(f"base64_blob_count={obfuscation.get('base64_blob_count')}")
    add("T1406", "Obfuscated Files or Information", obfuscation_evidence)
    add(
        "T1418",
        "Software Discovery",
        list(signals.get("installed_app_enumeration", {}).get("evidence", [])),
    )
    if certificate.get("bank_impersonation_flag"):
        add(
            "T1655.001",
            "Masquerading: Match Legitimate Name or Location",
            ["Bank-branded application identity with a signer absent from the configured trusted inventory"],
        )
    if components.get("boot_receiver"):
        add(
            "T1624.001",
            "Event Triggered Execution: Broadcast Receivers",
            ["BOOT_COMPLETED broadcast receiver"],
        )
    if "android.permission.READ_CONTACTS" in permissions:
        add("T1636.003", "Protected User Data: Contact List", ["android.permission.READ_CONTACTS"])
    if "android.permission.READ_CALL_LOG" in permissions:
        add("T1636.002", "Protected User Data: Call Log", ["android.permission.READ_CALL_LOG"])
    return mappings
