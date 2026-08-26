from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class BankingImpactItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    title: str
    description: str
    status: str  # CONFIRMED | SUPPORTED | POSSIBLE | NOT_OBSERVED
    deterministic_basis: str
    evidence_ids: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)


class BankingImpact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[BankingImpactItem] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


def derive_banking_impact(result: dict[str, Any] | None) -> dict[str, Any]:
    """Deterministically derives banking fraud impact items from exact findings/verifications.

    Rules:
    - CONFIRMED: Requires deterministic verifier status of CONFIRMED or equivalent explicit trusted evidence rule.
    - SUPPORTED: Requires static or lower-trust evidence supporting that exact behavior.
    - NOT_OBSERVED: No qualifying evidence.
    - POSSIBLE: Used for derived banking impact (e.g. ATO / ATS risk) where evidence supports prerequisite risk but not actual execution.
    """
    res = result or {}
    extraction = res.get("extraction") if isinstance(res.get("extraction"), dict) else res
    permissions = set(extraction.get("permissions", {}).get("requested", []))
    components = extraction.get("components", {})
    code_signals = extraction.get("code_signals", {})
    urls = extraction.get("urls", [])

    ai_investigation = res.get("ai_investigation", {})
    verifications = ai_investigation.get("hypothesis_verifications", [])
    if not isinstance(verifications, list):
        verifications = []

    runtime_evidence = res.get("runtime_evidence", [])
    if not isinstance(runtime_evidence, list):
        runtime_evidence = []

    recovered_payloads = res.get("recovered_payloads", [])
    if not isinstance(recovered_payloads, list):
        recovered_payloads = []

    v_by_category = {str(v.get("category")): v for v in verifications if isinstance(v, dict)}

    # 1. OTP INTERCEPTION
    v_otp = v_by_category.get("OTP_INTERCEPTION")
    otp_status = "NOT_OBSERVED"
    otp_basis = "No SMS read/receive capabilities or runtime interception observed."
    otp_ids: list[str] = []
    otp_signals: list[str] = []

    has_static_sms = (
        "android.permission.RECEIVE_SMS" in permissions
        or "android.permission.READ_SMS" in permissions
        or bool(components.get("sms_receiver"))
        or bool(code_signals.get("sms_api", {}).get("detected"))
    )

    if v_otp and v_otp.get("verified_status") == "CONFIRMED":
        otp_status = "CONFIRMED"
        otp_basis = "Verified runtime SMS OTP interception via instrumented synthetic marker correlation."
        otp_ids = [*v_otp.get("runtime_evidence_ids", []), *v_otp.get("static_evidence_ids", [])]
        otp_signals = v_otp.get("observed_signals", [])
    elif (v_otp and v_otp.get("verified_status") == "SUPPORTED") or has_static_sms:
        otp_status = "SUPPORTED"
        otp_basis = "Statically supported by declared SMS permissions/APIs, but runtime interception was not confirmed."
        otp_ids = v_otp.get("static_evidence_ids", []) if v_otp else []
        otp_signals = [p for p in ["RECEIVE_SMS", "READ_SMS"] if f"android.permission.{p}" in permissions]
        if components.get("sms_receiver"):
            otp_signals.append("sms_receiver")
        if code_signals.get("sms_api", {}).get("detected"):
            otp_signals.append("SmsManager")
    else:
        otp_status = "NOT_OBSERVED"

    # 2. CREDENTIAL EXFILTRATION
    v_cred = v_by_category.get("DATA_EXFILTRATION")
    cred_status = "NOT_OBSERVED"
    cred_basis = "No credential theft signals or outbound exfiltration observed."
    cred_ids: list[str] = []
    cred_signals: list[str] = []

    has_static_cred = (
        bool(code_signals.get("credential_theft", {}).get("detected"))
        or bool(code_signals.get("phishing_indicators", {}).get("detected"))
        or ("android.permission.SYSTEM_ALERT_WINDOW" in permissions and ("android.permission.INTERNET" in permissions or bool(urls)))
    )

    if v_cred and v_cred.get("verified_status") == "CONFIRMED":
        cred_status = "CONFIRMED"
        cred_basis = "Verified outbound network exfiltration correlated with sensitive data payload."
        cred_ids = [*v_cred.get("runtime_evidence_ids", []), *v_cred.get("static_evidence_ids", [])]
        cred_signals = v_cred.get("observed_signals", [])
    elif (v_cred and v_cred.get("verified_status") == "SUPPORTED") or has_static_cred:
        cred_status = "SUPPORTED"
        cred_basis = "Statically supported by phishing layout strings or credential harvesting indicators, but runtime exfiltration was not confirmed."
        cred_ids = v_cred.get("static_evidence_ids", []) if v_cred else []
        cred_signals = [k for k in ["credential_theft", "phishing_indicators"] if code_signals.get(k, {}).get("detected")]
        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
            cred_signals.append("overlay_permission")
    else:
        cred_status = "NOT_OBSERVED"

    # 3. ACCESSIBILITY ABUSE
    v_acc = v_by_category.get("ACCESSIBILITY_ABUSE")
    acc_status = "NOT_OBSERVED"
    acc_basis = "No accessibility service or interaction capabilities observed."
    acc_ids: list[str] = []
    acc_signals: list[str] = []

    has_static_acc = (
        bool(components.get("accessibility_service"))
        or bool(code_signals.get("input_injection", {}).get("detected"))
    )

    if v_acc and v_acc.get("verified_status") == "CONFIRMED":
        acc_status = "CONFIRMED"
        acc_basis = "Active AccessibilityService abuse confirmed by system-level service binding."
        acc_ids = [*v_acc.get("runtime_evidence_ids", []), *v_acc.get("static_evidence_ids", [])]
        acc_signals = v_acc.get("observed_signals", [])
    elif (v_acc and v_acc.get("verified_status") == "SUPPORTED") or has_static_acc:
        acc_status = "SUPPORTED"
        acc_basis = "Accessibility service declared in manifest/code, but system-level runtime binding was not confirmed."
        acc_ids = v_acc.get("static_evidence_ids", []) if v_acc else []
        if components.get("accessibility_service"):
            acc_signals.append("accessibility_service")
        if code_signals.get("input_injection", {}).get("detected"):
            acc_signals.append("input_injection")
    else:
        acc_status = "NOT_OBSERVED"

    # 4. DYNAMIC CODE LOADING
    v_dcl = v_by_category.get("DYNAMIC_CODE_LOADING")
    dcl_status = "NOT_OBSERVED"
    dcl_basis = "No dynamic class loading APIs or runtime execution observed."
    dcl_ids: list[str] = []
    dcl_signals: list[str] = []

    has_static_dcl = bool(code_signals.get("dynamic_code_loading", {}).get("detected"))
    has_trusted_dcl_runtime = any(
        ev.get("evidence_type") in {"dynamic_code_load", "classloader_event"}
        and str(ev.get("trust_level")) in {"INSTRUMENTED", "PAYLOAD_CORRELATED", "SYSTEM_OBSERVED"}
        for ev in runtime_evidence
    )

    if (v_dcl and v_dcl.get("verified_status") == "CONFIRMED") or has_trusted_dcl_runtime:
        dcl_status = "CONFIRMED"
        dcl_basis = "Verified dynamic bytecode / classloading execution in memory."
        dcl_ids = [str(ev.get("evidence_id")) for ev in runtime_evidence if ev.get("evidence_type") in {"dynamic_code_load", "classloader_event"} and ev.get("evidence_id")]
        dcl_signals = ["dynamic_classloading_verified"]
    elif (v_dcl and v_dcl.get("verified_status") == "SUPPORTED") or has_static_dcl:
        dcl_status = "SUPPORTED"
        dcl_basis = "DEX contains dynamic class loading APIs, but runtime invocation was not observed."
        dcl_ids = v_dcl.get("static_evidence_ids", []) if v_dcl else []
        dcl_signals = ["dynamic_code_loading_apis"]
    else:
        dcl_status = "NOT_OBSERVED"

    # 5. SECOND STAGE PAYLOAD
    payload_status = "NOT_OBSERVED"
    payload_basis = "No secondary payloads were dropped or recovered."
    payload_ids: list[str] = []
    payload_signals: list[str] = []

    if recovered_payloads:
        payload_status = "CONFIRMED"
        payload_basis = f"{len(recovered_payloads)} dynamic bytecode payload(s) successfully recovered and analyzed."
        payload_ids = [str(p.get("payload_id", f"PAYLOAD-{i+1}")) for i, p in enumerate(recovered_payloads)]
        payload_signals = [f"{p.get('payload_type', 'payload')}:{str(p.get('sha256', ''))[:8]}" for p in recovered_payloads]

    # 6. ACCOUNT TAKEOVER RISK (Derived Risk)
    if otp_status == "CONFIRMED" and cred_status == "CONFIRMED":
        ato_status = "CONFIRMED"
        ato_basis = "HIGH/CRITICAL ATO RISK: Prerequisite combination of confirmed credential harvesting and confirmed OTP interception establishes complete account takeover capability."
        ato_ids = [*otp_ids, *cred_ids]
        ato_signals = ["confirmed_credential_harvesting", "confirmed_otp_interception"]
    elif otp_status in ("CONFIRMED", "SUPPORTED") or cred_status in ("CONFIRMED", "SUPPORTED"):
        ato_status = "POSSIBLE"
        ato_basis = "Partial prerequisite signals present (credential or OTP capability), posing potential account takeover risk."
        ato_ids = [*otp_ids, *cred_ids]
        ato_signals = ([f"otp_{otp_status.lower()}"] if otp_status != "NOT_OBSERVED" else []) + ([f"cred_{cred_status.lower()}"] if cred_status != "NOT_OBSERVED" else [])
    else:
        ato_status = "NOT_OBSERVED"
        ato_basis = "No prerequisite credential harvesting or OTP interception capabilities observed."
        ato_ids = []
        ato_signals = []

    # 7. AUTOMATED TRANSACTION RISK (Derived Risk)
    if acc_status == "CONFIRMED":
        tx_status = "CONFIRMED"
        tx_basis = "Confirmed Accessibility API abuse creates immediate risk of automated unauthorized fund transfers (ATS)."
        tx_ids = list(acc_ids)
        tx_signals = ["confirmed_accessibility_abuse"]
    elif acc_status == "SUPPORTED":
        tx_status = "POSSIBLE"
        tx_basis = "Declared accessibility service creates structural capability for automated transactions, but active execution was not observed."
        tx_ids = list(acc_ids)
        tx_signals = ["supported_accessibility_service"]
    else:
        tx_status = "NOT_OBSERVED"
        tx_basis = "No automated UI control or accessibility service observed."
        tx_ids = []
        tx_signals = []

    items = [
        BankingImpactItem(
            id="otp_interception",
            category="OTP_INTERCEPTION",
            title="SMS OTP Interception & Bypass",
            description="Intercepts multi-factor banking OTP authentication codes to bypass step-up transaction challenges.",
            status=otp_status,
            deterministic_basis=otp_basis,
            evidence_ids=_unique(otp_ids),
            signals=_unique(otp_signals),
        ),
        BankingImpactItem(
            id="credential_exfiltration",
            category="CREDENTIAL_EXFILTRATION",
            title="Banking Credential Harvesting & Exfiltration",
            description="Captures internet banking usernames, passwords, and MPINs through fake overlay screens or keylogging.",
            status=cred_status,
            deterministic_basis=cred_basis,
            evidence_ids=_unique(cred_ids),
            signals=_unique(cred_signals),
        ),
        BankingImpactItem(
            id="account_takeover_risk",
            category="ACCOUNT_TAKEOVER_RISK",
            title="Account Takeover (ATO) Risk",
            description="Combines harvested credentials with intercepted OTPs to seize unauthorized control of victim bank accounts.",
            status=ato_status,
            deterministic_basis=ato_basis,
            evidence_ids=_unique(ato_ids),
            signals=_unique(ato_signals),
        ),
        BankingImpactItem(
            id="accessibility_abuse",
            category="ACCESSIBILITY_ABUSE",
            title="Accessibility Service Exploitation",
            description="Abuses Android Accessibility APIs to observe user credentials, inject gestures, and bypass user interaction.",
            status=acc_status,
            deterministic_basis=acc_basis,
            evidence_ids=_unique(acc_ids),
            signals=_unique(acc_signals),
        ),
        BankingImpactItem(
            id="automated_transaction_risk",
            category="AUTOMATED_TRANSACTION_RISK",
            title="Automated Fraudulent Transaction (ATS) Risk",
            description="Automates unauthorized fund transfers using compromised accessibility services without explicit victim consent.",
            status=tx_status,
            deterministic_basis=tx_basis,
            evidence_ids=_unique(tx_ids),
            signals=_unique(tx_signals),
        ),
        BankingImpactItem(
            id="dynamic_code_loading",
            category="DYNAMIC_CODE_LOADING",
            title="Dynamic Remote Payload Execution",
            description="Loads hidden second-stage banking malware payloads dynamically from memory, DEX files, or remote servers.",
            status=dcl_status,
            deterministic_basis=dcl_basis,
            evidence_ids=_unique(dcl_ids),
            signals=_unique(dcl_signals),
        ),
        BankingImpactItem(
            id="second_stage_payload",
            category="SECOND_STAGE_PAYLOAD",
            title="Secondary Payload Dropper",
            description="Drops and unpacks secondary executable payload files to conceal malicious behaviors from static scanners.",
            status=payload_status,
            deterministic_basis=payload_basis,
            evidence_ids=_unique(payload_ids),
            signals=_unique(payload_signals),
        ),
    ]

    summary = {
        "CONFIRMED": sum(1 for it in items if it.status == "CONFIRMED"),
        "SUPPORTED": sum(1 for it in items if it.status == "SUPPORTED"),
        "POSSIBLE": sum(1 for it in items if it.status == "POSSIBLE"),
        "NOT_OBSERVED": sum(1 for it in items if it.status == "NOT_OBSERVED"),
    }

    return BankingImpact(items=items, summary=summary).model_dump(mode="json")


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for it in items:
        cleaned = str(it).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result
