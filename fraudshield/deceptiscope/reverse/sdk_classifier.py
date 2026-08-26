from __future__ import annotations

from enum import Enum
from typing import NamedTuple


class CodeOwnership(str, Enum):
    APPLICATION_CODE = "APPLICATION_CODE"
    KNOWN_SDK = "KNOWN_SDK"
    SYSTEM_LIBRARY = "SYSTEM_LIBRARY"
    UNKNOWN_LIBRARY = "UNKNOWN_LIBRARY"


class SDKRule(NamedTuple):
    prefix: str
    name: str
    category: str


# Curated Android SDK & 3rd-party Library Taxonomy
KNOWN_SDK_REGISTRY: tuple[SDKRule, ...] = (
    # Google & Firebase
    SDKRule("com.google.android.gms", "Google Play Services", "Framework"),
    SDKRule("com.google.firebase", "Firebase", "Analytics/Backend"),
    SDKRule("com.google.android.play", "Google Play Core", "Framework"),
    SDKRule("com.google.android.datatransport", "Google DataTransport", "Telemetry"),
    SDKRule("com.google.ads", "Google Ads", "Advertising"),
    SDKRule("com.google.android.ads", "Google Mobile Ads", "Advertising"),
    SDKRule("com.google.gson", "Google Gson", "Utility"),
    SDKRule("com.google.protobuf", "Protocol Buffers", "Utility"),
    SDKRule("com.google.guava", "Google Guava", "Utility"),
    
    # Meta / Facebook
    SDKRule("com.facebook.ads", "Facebook Audience Network", "Advertising"),
    SDKRule("com.facebook.appevents", "Facebook Analytics", "Analytics"),
    SDKRule("com.facebook.react", "React Native", "Framework"),
    SDKRule("com.facebook", "Facebook SDK", "Social/Analytics"),

    # Attribution & Mobile Analytics
    SDKRule("com.adjust.sdk", "Adjust", "Attribution/Analytics"),
    SDKRule("com.appsflyer", "AppsFlyer", "Attribution/Analytics"),
    SDKRule("com.branch.io", "Branch Metrics", "Attribution/DeepLink"),
    SDKRule("io.branch", "Branch Metrics", "Attribution/DeepLink"),
    SDKRule("com.mixpanel", "Mixpanel", "Analytics"),
    SDKRule("com.amplitude", "Amplitude", "Analytics"),
    SDKRule("com.segment", "Segment", "Analytics"),
    SDKRule("com.flurry", "Flurry", "Analytics"),
    SDKRule("com.singular", "Singular", "Attribution/Analytics"),

    # Push Notifications & Messaging
    SDKRule("com.onesignal", "OneSignal", "Push Notifications"),
    SDKRule("com.clevertap", "CleverTap", "Push/Analytics"),
    SDKRule("com.moengage", "MoEngage", "Push/Analytics"),
    SDKRule("com.braze", "Braze", "Push/Analytics"),
    SDKRule("com.appboy", "Appboy/Braze", "Push/Analytics"),

    # Cross-Platform Frameworks
    SDKRule("io.flutter", "Flutter Engine", "Framework"),
    SDKRule("flutter", "Flutter", "Framework"),
    SDKRule("com.unity3d", "Unity Engine", "Gaming Framework"),
    SDKRule("org.apache.cordova", "Apache Cordova", "Hybrid Framework"),
    SDKRule("io.ionic", "Ionic Framework", "Hybrid Framework"),

    # Networking & Utilities
    SDKRule("okhttp3", "OkHttp", "Networking"),
    SDKRule("retrofit2", "Retrofit", "Networking"),
    SDKRule("com.squareup.picasso", "Picasso", "Image Loading"),
    SDKRule("com.bumptech.glide", "Glide", "Image Loading"),
    SDKRule("org.apache.http", "Apache HTTP", "Networking"),
    SDKRule("org.apache.commons", "Apache Commons", "Utility"),
    SDKRule("io.reactivex", "RxJava", "Reactive Framework"),
    SDKRule("org.bouncycastle", "BouncyCastle", "Cryptography"),

    # Payment & FinTech SDKs
    SDKRule("com.razorpay", "Razorpay", "Payment Gateway"),
    SDKRule("com.stripe", "Stripe", "Payment Gateway"),
    SDKRule("com.paytm", "Paytm SDK", "Payment Gateway"),
    SDKRule("com.phonepe", "PhonePe SDK", "Payment Gateway"),
)

SYSTEM_PREFIXES: tuple[str, ...] = (
    "android.",
    "androidx.",
    "android.support.",
    "java.",
    "javax.",
    "dalvik.",
    "kotlin.",
    "kotlinx.",
    "sun.",
    "com.android.",
)


class SDKClassifier:
    """Lightweight classifier distinguishing Application Code vs Known SDKs vs System Libraries."""

    def __init__(self, custom_rules: tuple[SDKRule, ...] = KNOWN_SDK_REGISTRY) -> None:
        self.rules = custom_rules

    def classify(
        self,
        class_name: str,
        app_package: str | None = None,
    ) -> tuple[CodeOwnership, str, str | None]:
        """
        Classifies a class into (ownership, label, sdk_name).
        
        Examples:
        - "com.boi.mobilebanking.MainActivity" -> (CodeOwnership.APPLICATION_CODE, "Application Code", None)
        - "com.adjust.sdk.AdjustSession" -> (CodeOwnership.KNOWN_SDK, "Known SDK", "Adjust")
        - "android.telephony.SmsManager" -> (CodeOwnership.SYSTEM_LIBRARY, "System Library", "Android Framework")
        """
        normalized = self._normalize_class_name(class_name)
        if not normalized:
            return CodeOwnership.UNKNOWN_LIBRARY, "Unknown", None

        # 1. Check if matches application package namespace
        if app_package and (normalized == app_package or normalized.startswith(f"{app_package}.")):
            return CodeOwnership.APPLICATION_CODE, "Application Code", None

        # 2. Check system prefixes
        for sys_prefix in SYSTEM_PREFIXES:
            if normalized.startswith(sys_prefix):
                return CodeOwnership.SYSTEM_LIBRARY, "System Library", "Android / Java Framework"

        # 3. Check known SDK prefixes
        for rule in self.rules:
            if normalized.startswith(f"{rule.prefix}.") or normalized == rule.prefix:
                return CodeOwnership.KNOWN_SDK, f"Known SDK: {rule.name}", rule.name

        # 4. If class namespace has at least 2 segments and does not match known SDKs
        if app_package and "." in normalized:
            app_root = app_package.split(".")[0]
            class_root = normalized.split(".")[0]
            if app_root == class_root and len(app_root) >= 3:
                return CodeOwnership.APPLICATION_CODE, "Application Code", None

        return CodeOwnership.APPLICATION_CODE if not app_package else CodeOwnership.UNKNOWN_LIBRARY, "Application Code", None

    @staticmethod
    def _normalize_class_name(class_name: str) -> str:
        """Converts Dalvik descriptor `Lcom/example/Test;` or `com/example/Test` to `com.example.Test`."""
        name = class_name.strip()
        if name.startswith("L") and name.endswith(";"):
            name = name[1:-1]
        name = name.replace("/", ".")
        return name
