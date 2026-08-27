#!/usr/bin/env python3
"""API smoke and upload contract verification script for FraudShield DeceptiScope.

NOTE: This script performs HTTP/API contract and static extraction smoke testing.
It does NOT substitute for physical Android emulator / Frida runtime E2E validation.
"""

import io
import zipfile
import httpx

BASE_URL = "http://127.0.0.1:8000"
client = httpx.Client(base_url=BASE_URL, timeout=30.0)

print("================ API SMOKE & UPLOAD CONTRACT VERIFICATION ================")

# 1. Health checks
r_live = client.get("/health/live")
print(f"1. Liveness (/health/live): {r_live.status_code} -> {r_live.json()}")
assert r_live.status_code == 200

r_ready = client.get("/health/ready")
print(f"2. Readiness (/health/ready): {r_ready.status_code} -> {r_ready.json()}")
assert r_ready.status_code == 200

# 2. Capabilities
r_cap = client.get("/api/v1/system/capabilities")
print(f"\n3. Capabilities Status: {r_cap.status_code}")
cap = r_cap.json()
engines = cap.get("multi_engine", {}).get("engines", [])
print(f"   Engine Capabilities ({len(engines)} registered):")
for e in engines:
    status_str = "READY" if (e.get("enabled") and e.get("available")) else "DISABLED" if not e.get("enabled") else "UNAVAILABLE"
    print(f"   [{status_str:<11}] {e.get('id'):<16} : {e.get('label')}")

# 3. Input Validation Rejections
print("\n4. Security Input Validation Guards:")
r_magic = client.post(
    "/api/v1/apk-analyses",
    files={"file": ("test.apk", b"not-a-zip", "application/vnd.android.package-archive")},
    data={"category": "banking"},
)
print(f"   Non-ZIP rejection: {r_magic.status_code} (Code: {r_magic.json()['error']['code']})")
assert r_magic.status_code == 422

# 4. Minimal APK Upload Contract Verification (Smoke Test)
print("\n5. Minimal APK Upload Contract Verification (Smoke Test):")
apk_buf = io.BytesIO()
with zipfile.ZipFile(apk_buf, "w") as z:
    z.writestr("AndroidManifest.xml", "<manifest package='com.example.verify'/>")
    z.writestr("classes.dex", b"dex\n035\x00test")
apk_bytes = apk_buf.getvalue()

r_upload = client.post(
    "/api/v1/apk-analyses",
    files={"file": ("verify.apk", apk_bytes, "application/vnd.android.package-archive")},
    data={"category": "banking"},
)
print(f"   API Upload Submission: {r_upload.status_code}")
assert r_upload.status_code in (200, 201)
upload_data = r_upload.json()
apk_id = upload_data.get("id") or upload_data.get("analysis_id")

# 5. Analysis Retrieval & PDF Download
r_analysis = client.get(f"/api/v1/apk-analyses/{apk_id}")
print(f"   Analysis Record Retrieval: {r_analysis.status_code}")
res = r_analysis.json().get("result", {})
print(f"   Verdict: {res.get('malware_assessment', {}).get('verdict')}")
print(f"   Risk Score: {res.get('risk', {}).get('overall_score')}/100")

r_pdf = client.get(f"/api/v1/apk-analyses/{apk_id}/report.pdf")
print(f"   PDF Report Download: {r_pdf.status_code} (Size: {len(r_pdf.content)} bytes)")
assert r_pdf.status_code == 200
assert r_pdf.content.startswith(b"%PDF-")

print("\n[NOTE] API smoke / contract verification completed successfully.")
print("[NOTE] Real Android emulator / Frida E2E requires a physical/emulated device pool.")
print(">>> ALL API SMOKE CHECKS PASSED <<<")
