from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fraudshield.core.config import PACKAGE_ROOT, Settings
from fraudshield.main import create_app


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    runtime = tmp_path / "runtime"
    return Settings(
        environment="test",
        data_dir=runtime,
        database_path=runtime / "fraudshield.db",
        upload_dir=runtime / "uploads",
        report_dir=runtime / "reports",
        baseline_path=PACKAGE_ROOT / "resources" / "category_baselines.json",
        llm_provider="disabled",
        cors_origins=("http://localhost:5173",),
        max_apk_bytes=5 * 1024 * 1024,
    )


@pytest.fixture()
def client(settings: Settings) -> TestClient:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def apk_bytes(*, malicious: bool = True) -> bytes:
    permissions = ["android.permission.INTERNET"]
    services = ""
    receivers = ""
    dex_tokens = b"ordinary application code"
    label = "Notes Demo"
    package = "org.example.notes"
    if malicious:
        permissions.extend(
            [
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.QUERY_ALL_PACKAGES",
            ]
        )
        services = """
        <service android:name=".CaptureService"
                 android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
                 android:exported="true">
          <intent-filter><action android:name="android.accessibilityservice.AccessibilityService"/></intent-filter>
        </service>
        """
        receivers = """
        <receiver android:name=".SmsReceiver" android:exported="true">
          <intent-filter><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter>
        </receiver>
        """
        dex_tokens = b"DexClassLoader java/lang/reflect SmsManager getInstalledApplications AccessibilityService dispatchGesture"
        label = "Demo Bank Secure"
        package = "com.example.demobank"
    permission_xml = "\n".join(
        f'<uses-permission android:name="{permission}"/>' for permission in permissions
    )
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="{package}" android:versionName="1.0" android:versionCode="1">
      {permission_xml}
      <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
      <application android:label="{label}">
        <activity android:name=".MainActivity" android:exported="true"/>
        {services}
        {receivers}
      </application>
    </manifest>"""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex\n035\x00" + dex_tokens)
        archive.writestr("META-INF/DEMO.RSA", b"synthetic signer bytes")
        if malicious:
            archive.writestr("assets/update.dex", b"secondary demo payload")
            archive.writestr("assets/config.txt", b"https://c2-demo.fraudshield.invalid/gate 198.51.100.42")
    return output.getvalue()


@pytest.fixture()
def malicious_apk() -> bytes:
    return apk_bytes(malicious=True)


@pytest.fixture()
def benign_apk() -> bytes:
    return apk_bytes(malicious=False)
