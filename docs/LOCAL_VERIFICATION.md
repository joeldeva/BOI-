# Local release verification

Verification date: 2026-08-22  
Target: FraudShield DeceptiScope 3.0.0 source package  
Host: Windows, Python 3.11.9, Node.js 24.16.0, npm 11.13.0

## Passed locally

- Backend production dependencies: `pip install --require-hashes -r requirements-production.lock` passed in a clean Python 3.11 virtual environment.
- Backend package smoke: wheel install/import reported version `3.0.0`.
- Backend tests: `32 passed`, with one Starlette deprecation warning from FastAPI's test client.
- Backend lint: `python -m ruff check fraudshield tests` passed.
- Backend build: `python -m build --no-isolation` produced the sdist and wheel.
- Frontend dependencies: `npm ci --ignore-scripts --no-audit --no-fund` passed from `package-lock.json`.
- Frontend: `5 passed`; Oxlint, TypeScript build and Vite production build completed successfully.
- OpenAPI frontend contract: required APK routes are present and removed v2 non-APK routes are absent.
- Compose syntax: `docker compose config` rendered successfully.

## Local fixes made during verification

- Added Windows-only production lock entries for `win32-setctime==1.2.0` and `tzdata==2026.3`, both with hashes, so hash-checked production installs work on Windows.
- Removed stale production-deployment diagram and old non-APK wording from active APK-only documentation.
- Removed unused imports reported by Ruff.

## Capability status on this machine

- Ready: guarded archive/native inventory, Androguard.
- Enabled but unavailable: APKiD, YARA, Android `apksigner`, ssdeep/Dexofuzzy similarity.
- Disabled by policy/configuration: Quark, private MobSF, VirusTotal, MalwareBazaar, dynamic-lite ADB, optional LLM.
- External hash lookups: disabled.
- Public binary uploads: disabled for public services.

Unavailable or disabled optional engines are expected to appear explicitly in analysis output; their absence is never treated as a clean or safe result.

## Environment-limited checks

- Helm is not installed locally, so `helm lint deploy/helm/fraudshield -f deploy/helm/fraudshield/values-production.example.yaml` could not be run.
- Docker CLI and Compose are installed, but the Docker Desktop Linux engine was not running; `docker compose build` could not connect to the daemon.
- Production PostgreSQL, OIDC/JWKS, S3/KMS, private MobSF, Android SDK `apksigner`, Quark rules, reputation-provider keys and a dynamic-analysis emulator were not provisioned here.
- No public provider received an APK or hash during verification.
- Independent SAST/SCA/secret/container scans, SBOM generation, image signing, VA/PT, disaster-recovery evidence and bank approvals remain release gates in `docs/RELEASE_GATES.md`.

This record is build evidence, not a claim of bank production certification or malware-detection completeness.
