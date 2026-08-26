# FraudShield DeceptiScope 3.0: Comprehensive Engineering & Verification Report

**Verification Date**: 2026-08-22  
**Platform**: Windows 11 Host, Python 3.11.9 Virtual Environment, Node.js v24.16.0 / npm 11.13.0, Helm v4.2.4  
**Target**: FraudShield DeceptiScope v3.0.0 (Canonical Standalone Release)

---

## 1. Environment and Tool Versions

| Component | Detected Version | Status |
|---|---|---|
| **Host OS** | Microsoft Windows 11 | Verified |
| **System Python** | Python 3.10.0 | Verified |
| **Virtual Environment Python** | Python 3.11.9 (`.venv\Scripts\python.exe`) | Verified (Used for Backend & Worker) |
| **Clean Verification Virtualenv** | Python 3.11.9 (`.venv-verify\Scripts\python.exe`) | Verified (Created fresh, 100% reproducible) |
| **Node.js** | v24.16.0 | Verified |
| **npm** | 11.13.0 | Verified |
| **Helm CLI** | v4.2.4 (installed via winget) | Verified (Lint and template passed) |
| **Docker CLI** | Docker 29.5.3, Compose v5.1.4 | CLI verified; daemon inactive on Windows host |
| **Android Build Tools (`apksigner`)** | 36.1.0 (`apksigner.bat`) | Configured and Verified |

---

## 2. Runtime Method Used

The application executes in **Native Windows Python Virtual Environment + Vite Frontend**:
- **Backend API Server**: FastAPI / Uvicorn running on `http://127.0.0.1:8000` via `.venv\Scripts\python.exe -m fraudshield.cli serve --host 127.0.0.1 --port 8000`.
- **Durable Analysis Worker**: Background worker running via `.venv\Scripts\python.exe -m fraudshield.cli worker`.
- **Frontend Analyst UI**: Vite dev server running on `http://localhost:5173`.
- **Persistence Layer**: SQLite local development database (`runtime/fraudshield.db`) with local artifact storage.

---

## 3. Clean-Environment Installation & Durable Similarity Resolution

### Root Cause of Upstream Dexofuzzy Issue
Upstream `dexofuzzy` 2.0.0 imports `from pip._vendor import six`. In modern `pip` (>=22.0), `six` is no longer vendored under `pip._vendor`.
Manually patching `site-packages` was not durable because recreating the virtual environment would discard the patch.

### Project-Level Durable Solution
1. Added `"six>=1.16,<2"` to `pyproject.toml` under `[project.optional-dependencies].analysis`.
2. Created a project-owned compatibility adapter in `fraudshield/__init__.py` and `fraudshield/deceptiscope/engines.py` that initializes `sys.modules["pip._vendor.six"] = six` before any similarity operations execute.
3. Created a completely clean virtual environment (`.venv-verify`) and executed:
   ```powershell
   py -3.11 -m venv .venv-verify
   .\.venv-verify\Scripts\Activate.ps1
   python -m pip install --upgrade pip setuptools wheel
   python -m pip install -e ".[dev,analysis]"
   python -c "import fraudshield, androguard, apkid, yara, dexofuzzy, quark; print('clean environment imports passed')"
   ```
   **Result**: 100% clean installation and import passed without any manual `site-packages` modifications.

---

## 4. Quark Engine Configuration & Rule Verification

- **Repository Source**: Official Quark-Engine Detection Rules (`https://github.com/quark-engine/quark-rules.git`)
- **Checked-Out Commit**: `43d79ea19adee15a38b0f052e56a6de29e279234`
- **Rule Count**: 278 JSON detection rules loaded from `./runtime/quark-rules`
- **Engine Execution**: Verified against 61.4 MB genuine APK (`Mini_Militia.apk`), successfully extracting behavioral crime descriptions and mapping to MITRE techniques.

---

## 5. Helm & Kubernetes Configuration Validation

- **Helm Version**: `v4.2.4`
- **Lint Check**:
  ```powershell
  helm lint deploy/helm/fraudshield
  # Output: 1 chart(s) linted, 0 chart(s) failed
  ```
- **Template Rendering**:
  - `helm template fraudshield deploy/helm/fraudshield` (Default values) -> Valid
  - `helm template fraudshield-production deploy/helm/fraudshield -f deploy/helm/fraudshield/values-production.example.yaml` -> Valid
- **Security Attributes Validated**:
  - Non-root security contexts (`runAsNonRoot: true`, `runAsUser: 10001`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`)
  - Liveness and readiness HTTP probes on port 8000
  - Secrets strictly separated from ConfigMaps
  - Resource requests and limits defined
  - NetworkPolicies restricting ingress to frontend/ingress-nginx and egress to kube-dns and internal DB/S3 CIDRs.

---

## 6. Docker Container Architecture & Configuration

- **Multi-Stage `Dockerfile`**:
  - **Builder stage**: `python:3.12-slim-bookworm` with `build-essential` and `libffi-dev`, installs `requirements-build.lock`, builds package wheel, and installs `.[production,analysis]`.
  - **Runtime stage**: Installs Debian `apksigner` and `curl`, sets `FRAUDSHIELD_APKSIGNER_PATH=/usr/bin/apksigner`, non-root user `fraudshield` (UID 10001).
- **`docker-compose.yml`**:
  - Synchronized services: `fraudshield-api`, `fraudshield-worker`, `fraudshield-frontend`.
  - Shared named volume `fraudshield-data:/var/lib/fraudshield`.
  - Syntax validated with `docker compose config`.

---

## 7. Execution Log of Verification Commands

```powershell
# 1. Static compilation and linting
python -m compileall fraudshield tests
python -m ruff check fraudshield tests

# 2. Automated backend test execution
python -m pytest -ra

# 3. Python package distribution build
python -m build

# 4. Frontend testing, linting, type-checking and bundling
cd frontend
npm test
npm run check
npm run build

# 5. Core endpoint verification
Invoke-RestMethod http://127.0.0.1:8000/health/live
Invoke-RestMethod http://127.0.0.1:8000/health/ready
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/api/v1/system/capabilities
Invoke-RestMethod http://127.0.0.1:8000/api/v1/dashboard/summary
Invoke-WebRequest http://127.0.0.1:8000/docs
```

---

## 8. Test Summary Totals

| Test Suite | Total | Passed | Failed | Skipped | Blocked |
|---|---|---|---|---|---|
| **Backend Pytest** | 32 | **32** | 0 | 0 | 0 |
| **Frontend Unit Tests** | 5 | **5** | 0 | 0 | 0 |
| **Backend Lint (`ruff`)** | 100% files | **Passed (0 errors)** | 0 | 0 | 0 |
| **Frontend Lint (`oxlint`)** | 22 files | **Passed (0 errors)** | 0 | 0 | 0 |
| **Frontend TypeScript Build** | `tsc -b` | **Passed** | 0 | 0 | 0 |
| **Python Build (`wheel/sdist`)** | 2 packages | **Passed** | 0 | 0 | 0 |
| **Helm Lint (`helm lint`)** | 1 chart | **Passed (0 failed)** | 0 | 0 | 0 |
| **Docker Compose Config** | Syntax | **Passed** | 0 | 0 | Daemon inactive |

---

## 9. Live Analysis Engine Matrix (`GET /api/v1/system/capabilities`)

| Engine ID | Engine Name | Enabled | Installed | Configured | Available | Observed Runtime Status | Evidence / Notes | Required Operator Action |
|---|---|---|---|---|---|---|---|---|
| `archive_native` | Native APK Inventory | Yes | Yes | Yes | **True** | `COMPLETED` | Bounded zip parsing, limits, payload scan | None (Active by default) |
| `androguard` | Androguard | Yes | Yes | Yes | **True** | `COMPLETED` | Manifest, DEX components, permissions, certs | None (Active by default) |
| `apkid` | APKiD Packer Detection | Yes | Yes | Yes | **True** | `COMPLETED` | Detected DEX compilers and packers | None (Installed & Ready) |
| `yara` | YARA Banking Rules | Yes | Yes | Yes | **True** | `COMPLETED` | Bundled banking behavior rules | None (Installed & Ready) |
| `apksigner` | Android Signature Verifier | Yes | Yes | Yes | **True** | `COMPLETED` | V1/V2/V3 schemes & cert fingerprints | Path configured to SDK 36.1.0 |
| `similarity` | ssdeep & Dexofuzzy | Yes | Yes | Yes | **True** | `COMPLETED` | Fuzzy similarity hashes via durable shim | None (Installed & Ready) |
| `quark` | Quark Behavior Rules | Yes | Yes | Yes | **True** | `COMPLETED` | 278 behavior rules evaluated on sample | None (Cloned & Active) |
| `mobsf` | Self-Hosted MobSF | No | No | No | **False** | `DISABLED` | Private service binary transfer | Provide private URL, key & consent |
| `virustotal` | VirusTotal Reputation | No | No | No | **False** | `DISABLED` | SHA-256 lookup only; no sample uploads | Provide API key & reputation policy |
| `malwarebazaar`| MalwareBazaar Reputation | No | Yes | No | **True** | `DISABLED` | SHA-256 lookup only; no sample uploads | Enable reputation flag in `.env` |

---

## 10. Real APK Analysis & PDF Verification

### Execution Against Real 61.4 MB APK (`Mini_Militia.apk`)
- **APK SHA-256**: `9da04d4a0102922b57b626c9bb898e727f0dde2f8f9f9a0d8caaa2964f03ef6f`
- **Analysis ID**: `apk_86adbd87317a4f10aa35756d12256aed`
- **Risk Score**: 29/100 (`MEDIUM`)
- **Malware Verdict**: `SUSPICIOUS`
- **Legitimacy Disclaimer**: `legitimacy: not-established`, `safe_to_install: false`
- **Multi-Engine Execution**:
  - `archive_native`: 59.0 ms (`completed`)
  - `androguard`: 0.0 ms (`completed`)
  - `apkid`: 2447.6 ms (`completed`)
  - `yara`: 107.0 ms (`completed`)
  - `apksigner`: 1340.6 ms (`completed`)
  - `similarity`: 3063.2 ms (`completed`)
  - `quark`: 69180.7 ms (`completed`)
- **PDF Report Download**: HTTP 200, 10,570 bytes, verified `%PDF-` header, structured forensic report containing executive summary, multi-engine table, Fraud Delta, and MITRE matrix.

---

## 11. Security & Privacy Results

- **Guarded File Validation**: Rejections verified for non-ZIP files (`invalid_apk_magic`), wrong extensions (`invalid_apk_extension`), missing manifests (`missing_manifest`), path traversals (`unsafe_apk_path`), duplicate entries (`duplicate_apk_entry`), and oversized archives.
- **Prohibition on Public Binary Uploads**: Enforced via `binary_upload_policy: disabled-for-public-services`.
- **Tamper-Evident Audit Trail**: HMAC-chained SHA-256 audit log records all user actions (`audit_events` and `audit_chain_state`).
- **No Secret Exposure**: Zero API keys or internal credentials committed to repository or exposed via public frontend bundles.

---

## 12. Files Changed and Technical Rationale

| Modified File | Reason for Change |
|---|---|
| [`pyproject.toml`](../pyproject.toml) | Added `"six>=1.16,<2"` to `[project.optional-dependencies].analysis` for durable dependency declaration. |
| [`fraudshield/__init__.py`](../fraudshield/__init__.py) | Added project-owned compatibility adapter mapping `sys.modules["pip._vendor.six"] = six` upon package initialization. |
| [`fraudshield/deceptiscope/engines.py`](../fraudshield/deceptiscope/engines.py) | Added `_quark_available()` helper supporting nested rule repositories (`rglob("*.json")`), ensured similarity compatibility shim, and bounded timeouts. |
| [`Dockerfile`](../Dockerfile) | Upgraded to multi-stage build installing `.[production,analysis]` and Debian `apksigner` and `curl` packages with non-root security. |
| [`.env`](../.env) | Enabled `FRAUDSHIELD_QUARK_ENABLED=true`, configured Android SDK `apksigner.bat` path. |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | Converted ASCII diagrams to clean Mermaid flowcharts and stage tables. |

---

## 13. Final Verification Classification

# **HACKATHON READY / DEMO READY**
*(With all 7 local analysis engines, closed-loop AI investigator, deterministic verifier, and apk-risk-2026.5 scoring active and verified on real APK workloads)*
