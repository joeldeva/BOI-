from __future__ import annotations

import re
from enum import Enum
from typing import NamedTuple, Pattern


class BehaviorCategory(str, Enum):
    SMS_CREDENTIAL_THEFT = "SMS_CREDENTIAL_THEFT"
    NOTIFICATION_INTERCEPTION = "NOTIFICATION_INTERCEPTION"
    ACCESSIBILITY_ABUSE = "ACCESSIBILITY_ABUSE"
    DYNAMIC_CODE_LOADING = "DYNAMIC_CODE_LOADING"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    WEBVIEW_BRIDGE = "WEBVIEW_BRIDGE"
    DEVICE_RECONNAISSANCE = "DEVICE_RECONNAISSANCE"
    EVASION_ANTI_ANALYSIS = "EVASION_ANTI_ANALYSIS"
    SUSPICIOUS_NETWORKING = "SUSPICIOUS_NETWORKING"
    NATIVE_CODE_LOADING = "NATIVE_CODE_LOADING"
    OVERLAY_UI_HIJACKING = "OVERLAY_UI_HIJACKING"


class BehaviorSignature(NamedTuple):
    id: str
    title: str
    category: BehaviorCategory
    severity: str
    patterns: tuple[str, ...]
    compiled_regex: Pattern[str]
    description: str
    rationale: str
    risk_weight: float


def _make_sig(
    sig_id: str,
    title: str,
    category: BehaviorCategory,
    severity: str,
    patterns: tuple[str, ...],
    description: str,
    rationale: str,
    risk_weight: float = 1.0,
) -> BehaviorSignature:
    escaped = [re.escape(p) for p in patterns]
    regex = re.compile(r"(" + "|".join(escaped) + r")", re.IGNORECASE)
    return BehaviorSignature(
        id=sig_id,
        title=title,
        category=category,
        severity=severity,
        patterns=patterns,
        compiled_regex=regex,
        description=description,
        rationale=rationale,
        risk_weight=risk_weight,
    )


# DroidLysis-inspired Android Method-Level Behavior Signatures
BEHAVIOR_SIGNATURES: tuple[BehaviorSignature, ...] = (
    # --- 1. SMS / CREDENTIAL THEFT ---
    _make_sig(
        "MTH-SMS-001",
        "SMS Message Ingestion & PDU Parsing",
        BehaviorCategory.SMS_CREDENTIAL_THEFT,
        "CRITICAL",
        (
            "Landroid/telephony/SmsMessage;->createFromPdu",
            "Landroid/telephony/SmsMessage;->getMessageBody",
            "Landroid/telephony/SmsMessage;->getOriginatingAddress",
            "Landroid/provider/Telephony$Sms$Intents;->getMessagesFromIntent",
        ),
        "Method parses raw SMS PDU bytes to extract incoming message body or sender address.",
        "Commonly used by banking trojans to intercept 2FA OTP tokens.",
        risk_weight=1.0,
    ),
    _make_sig(
        "MTH-SMS-002",
        "SMS Programmatic Outbound Transmission",
        BehaviorCategory.SMS_CREDENTIAL_THEFT,
        "HIGH",
        (
            "Landroid/telephony/SmsManager;->sendTextMessage",
            "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
            "Landroid/telephony/SmsManager;->sendDataMessage",
        ),
        "Method directly transmits SMS messages via SmsManager without user interaction.",
        "Can be used for SMS exfiltration or subscribing victim to premium rate SMS services.",
        risk_weight=0.9,
    ),
    _make_sig(
        "MTH-SMS-003",
        "SMS Broadcast Suppression",
        BehaviorCategory.SMS_CREDENTIAL_THEFT,
        "CRITICAL",
        (
            "->abortBroadcast()V",
            "Landroid/content/BroadcastReceiver;->abortBroadcast",
        ),
        "Method aborts broadcast propagation to prevent the default SMS app from receiving incoming SMS.",
        "Primary technique used by SMS stealers to conceal OTP arrival from the device user.",
        risk_weight=1.0,
    ),
    _make_sig(
        "MTH-SMS-004",
        "SMS Content Provider Database Query",
        BehaviorCategory.SMS_CREDENTIAL_THEFT,
        "HIGH",
        (
            "content://sms",
            "content://sms/inbox",
            "content://sms/sent",
            "Landroid/provider/Telephony$Sms;",
        ),
        "Method directly queries the device SMS database through content://sms provider URI.",
        "Allows full exfiltration of user SMS message history.",
        risk_weight=0.85,
    ),

    # --- 2. NOTIFICATION INTERCEPTION ---
    _make_sig(
        "MTH-NOTIF-001",
        "Notification Listener & Text Extraction",
        BehaviorCategory.NOTIFICATION_INTERCEPTION,
        "HIGH",
        (
            "Landroid/service/notification/NotificationListenerService;->onNotificationPosted",
            "Landroid/service/notification/NotificationListenerService;->getActiveNotifications",
            "Landroid/app/Notification;->extras",
            "android.title",
            "android.text",
        ),
        "Method implements NotificationListenerService or accesses notification text content.",
        "Used to harvest WhatsApp/Telegram/Banking notification previews containing verification codes.",
        risk_weight=0.85,
    ),

    # --- 3. ACCESSIBILITY ABUSE ---
    _make_sig(
        "MTH-ACC-001",
        "Accessibility Node Traversal & Text Harvesting",
        BehaviorCategory.ACCESSIBILITY_ABUSE,
        "CRITICAL",
        (
            "Landroid/view/accessibility/AccessibilityNodeInfo;->getText",
            "Landroid/view/accessibility/AccessibilityNodeInfo;->getContentDescription",
            "Landroid/view/accessibility/AccessibilityNodeInfo;->getViewIdResourceName",
            "Landroid/view/accessibility/AccessibilityNodeInfo;->findAccessibilityNodeInfosByViewId",
            "Landroid/view/accessibility/AccessibilityNodeInfo;->findAccessibilityNodeInfosByText",
        ),
        "Method reads on-screen UI text and view IDs via AccessibilityNodeInfo.",
        "Used by banking ATS (Automated Transfer System) bots to read account balances and pin inputs.",
        risk_weight=1.0,
    ),
    _make_sig(
        "MTH-ACC-002",
        "Accessibility Input Automation & Gesture Dispatch",
        BehaviorCategory.ACCESSIBILITY_ABUSE,
        "CRITICAL",
        (
            "Landroid/accessibilityservice/AccessibilityService;->dispatchGesture",
            "Landroid/view/accessibility/AccessibilityNodeInfo;->performAction",
            "Landroid/accessibilityservice/AccessibilityService;->performGlobalAction",
            "ACTION_CLICK",
            "ACTION_SET_TEXT",
            "GLOBAL_ACTION_HOME",
            "GLOBAL_ACTION_BACK",
        ),
        "Method programmatically injects gestures, clicks, and keystrokes into other apps.",
        "Allows autonomous completion of unauthorized banking transfers without victim consent.",
        risk_weight=1.0,
    ),

    # --- 4. DYNAMIC CODE LOADING ---
    _make_sig(
        "MTH-DCL-001",
        "Dynamic Dalvik / DEX Class Loading",
        BehaviorCategory.DYNAMIC_CODE_LOADING,
        "CRITICAL",
        (
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/PathClassLoader;-><init>",
            "Ldalvik/system/InMemoryDexClassLoader;-><init>",
            "Ldalvik/system/DelegateLastClassLoader;-><init>",
            "Ldalvik/system/BaseDexClassLoader;-><init>",
            "Ldalvik/system/DexFile;->loadDex",
            "Ldalvik/system/DexFile;->loadClass",
        ),
        "Method dynamically instantiates a ClassLoader to execute code from external or encrypted DEX files.",
        "Primary dropper/loader evasion technique used to bypass static package inspection.",
        risk_weight=1.0,
    ),

    # --- 5. COMMAND EXECUTION ---
    _make_sig(
        "MTH-EXEC-001",
        "Native Process & Shell Execution",
        BehaviorCategory.COMMAND_EXECUTION,
        "HIGH",
        (
            "Ljava/lang/Runtime;->exec",
            "Ljava/lang/ProcessBuilder;->start",
            "/system/bin/sh",
            "/system/xbin/su",
            "/bin/sh",
        ),
        "Method spawns native OS processes or invokes shell interpreters.",
        "Enables post-exploitation privilege escalation and native payload execution.",
        risk_weight=0.85,
    ),

    # --- 6. WEBVIEW BRIDGE ---
    _make_sig(
        "MTH-WEB-001",
        "WebView JavaScript Interface Bridge",
        BehaviorCategory.WEBVIEW_BRIDGE,
        "MEDIUM",
        (
            "Landroid/webkit/WebView;->addJavascriptInterface",
            "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
            "Landroid/webkit/WebView;->evaluateJavascript",
            "Landroid/webkit/WebViewClient;->shouldOverrideUrlLoading",
        ),
        "Method binds native Java objects into WebView JavaScript context or enables JavaScript execution.",
        "Can facilitate phishing overlays and bidirectional bridge compromise.",
        risk_weight=0.65,
    ),

    # --- 7. DEVICE RECONNAISSANCE ---
    _make_sig(
        "MTH-REC-001",
        "Installed Application & Task Enumeration",
        BehaviorCategory.DEVICE_RECONNAISSANCE,
        "HIGH",
        (
            "Landroid/content/pm/PackageManager;->getInstalledApplications",
            "Landroid/content/pm/PackageManager;->getInstalledPackages",
            "Landroid/content/pm/PackageManager;->queryIntentActivities",
            "Landroid/app/ActivityManager;->getRunningAppProcesses",
            "Landroid/app/ActivityManager;->getRunningTasks",
        ),
        "Method queries package manager or activity manager to enumerate installed banking/payment apps.",
        "Used for target reconnaissance to select corresponding phishing overlay templates.",
        risk_weight=0.8,
    ),
    _make_sig(
        "MTH-REC-002",
        "Hardware Identifiers & Geolocation Harvesting",
        BehaviorCategory.DEVICE_RECONNAISSANCE,
        "HIGH",
        (
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getImei",
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
            "Landroid/location/LocationManager;->getLastKnownLocation",
        ),
        "Method accesses device unique hardware IDs (IMEI, IMSI, SIM serial) or GPS coordinates.",
        "Used for victim fingerprinting and location tracking.",
        risk_weight=0.75,
    ),

    # --- 8. ANTI-ANALYSIS & EVASION ---
    _make_sig(
        "MTH-EVA-001",
        "Debugger & Emulator Detection",
        BehaviorCategory.EVASION_ANTI_ANALYSIS,
        "HIGH",
        (
            "Landroid/os/Debug;->isDebuggerConnected",
            "Landroid/os/Debug;->waitingForDebugger",
            "ro.kernel.qemu",
            "goldfish",
            "generic_x86",
            "/dev/socket/qemud",
            "vbox86",
            "nox",
        ),
        "Method checks debug flags or QEMU/VirtualBox emulator hardware artifacts.",
        "Employed by sophisticated malware to stay dormant in analysis sandboxes.",
        risk_weight=0.8,
    ),
    _make_sig(
        "MTH-EVA-002",
        "Root & Anti-Hooking Checks",
        BehaviorCategory.EVASION_ANTI_ANALYSIS,
        "MEDIUM",
        (
            "Superuser.apk",
            "/system/app/Superuser",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "frida-server",
            "gum-js-loop",
            "frida:rpc",
        ),
        "Method scans filesystem for root binaries or Frida/Xposed hooking artifacts.",
        "Used to evade dynamic instrumentation or enforce defensive anti-tamper.",
        risk_weight=0.7,
    ),

    # --- 9. SUSPICIOUS NETWORKING ---
    _make_sig(
        "MTH-NET-001",
        "Direct Socket & HTTP Egress",
        BehaviorCategory.SUSPICIOUS_NETWORKING,
        "MEDIUM",
        (
            "Ljava/net/Socket;-><init>",
            "Ljava/net/HttpURLConnection;->connect",
            "Lorg/apache/http/client/HttpClient;->execute",
            "Lokhttp3/OkHttpClient;->newCall",
        ),
        "Method establishes raw network socket or HTTP transmission.",
        "Required for Command & Control (C2) communication and credential exfiltration.",
        risk_weight=0.5,
    ),

    # --- 10. NATIVE CODE LOADING ---
    _make_sig(
        "MTH-NAT-001",
        "Dynamic Native Library Loading",
        BehaviorCategory.NATIVE_CODE_LOADING,
        "MEDIUM",
        (
            "Ljava/lang/System;->loadLibrary",
            "Ljava/lang/System;->load",
            "Ljava/lang/Runtime;->loadLibrary",
            "Ljava/lang/Runtime;->load",
        ),
        "Method loads native compiled C/C++ shared libraries (.so).",
        "Often hides core malicious routines in obfuscated ELF binaries.",
        risk_weight=0.6,
    ),

    # --- 11. OVERLAY / UI HIJACKING ---
    _make_sig(
        "MTH-UI-001",
        "System Window Overlay Creation",
        BehaviorCategory.OVERLAY_UI_HIJACKING,
        "HIGH",
        (
            "TYPE_APPLICATION_OVERLAY",
            "TYPE_SYSTEM_ALERT",
            "TYPE_SYSTEM_OVERLAY",
            "Landroid/view/WindowManager$LayoutParams;->type",
        ),
        "Method configures system-level window overlay parameters.",
        "Enables overlay phishing dialogs drawn over legitimate banking applications.",
        risk_weight=0.85,
    ),
    _make_sig(
        "MTH-UI-002",
        "Screen Capture & MediaProjection",
        BehaviorCategory.OVERLAY_UI_HIJACKING,
        "HIGH",
        (
            "Landroid/media/projection/MediaProjection;->createVirtualDisplay",
            "Landroid/media/projection/MediaProjectionManager;->getMediaProjection",
        ),
        "Method initializes real-time screen capture and virtual display recording.",
        "Allows continuous visual surveillance of victim banking sessions.",
        risk_weight=0.9,
    ),
)


class BehaviorRegistry:
    """Registry of Android method-level behavioral signatures."""

    def __init__(self, signatures: tuple[BehaviorSignature, ...] = BEHAVIOR_SIGNATURES) -> None:
        self.signatures = signatures

    def match_line(self, line: str) -> list[BehaviorSignature]:
        """Matches a single disassembled line or instruction against all signatures."""
        matches: list[BehaviorSignature] = []
        for sig in self.signatures:
            if sig.compiled_regex.search(line):
                matches.append(sig)
        return matches
