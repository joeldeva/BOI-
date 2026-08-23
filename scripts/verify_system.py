#!/usr/bin/env python3
"""End-to-end verification script for running FraudShield DeceptiScope instance."""

import io
import time
import zipfile
import httpx

BASE_URL = "http://127.0.0.1:8000"
client = httpx.Client(base_url=BASE_URL, timeout=30.0)

print("================ SYSTEM VERIFICATION ================")

# 1. Health checks
r_live = client.get("/health/live")
print(f"1. Liveness (/health/live): {r_live.status_code} -> {r_live.json()}")
assert r_live.status_code == 200

r_ready = client.get("/health/ready")
print(f"2. Readiness (/health/ready): {r_ready.status_code} -> {r_ready.json()}")
assert r_ready.status_code == 200

# 2. Capabilities
r_cap = client.get("/api/v1/system/capabilities")
cap = r_cap.json()
engines = cap.get("multi_engine", {}).get("engines", [])
print(f"\n3. Engine Capabilities ({len(engines)} registered):")
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

# 4. Synthetic Demo Seed
print("\n5. Synthetic Demo Workflow:")
r_demo = client.post("/api/v1/demo/seed", json={"category": "banking"})
print(f"   Demo Seed: {r_demo.status_code}")
assert r_demo.status_code == 201
demo_data = r_demo.json()
apk_id = demo_data["apk_analysis_id"]

# 5. Analysis Retrieval & PDF Download
r_analysis = client.get(f"/api/v1/apk-analyses/{apk_id}")
print(f"   Analysis Record: {r_analysis.status_code}")
res = r_analysis.json().get("result", {})
print(f"   Verdict: {res.get('malware_assessment', {}).get('verdict')}")
print(f"   Risk Score: {res.get('risk', {}).get('overall_score')}/100")

r_pdf = client.get(f"/api/v1/apk-analyses/{apk_id}/report.pdf")
print(f"   PDF Report: {r_pdf.status_code} (Size: {len(r_pdf.content)} bytes, Header: {r_pdf.content[:5]})")
assert r_pdf.status_code == 200
assert r_pdf.content.startswith(b"%PDF-")

print("\n>>> ALL SYSTEM CHECKS PASSED SUCCESSFULLY! <<<")
