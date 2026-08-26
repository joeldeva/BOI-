# FraudShield DeceptiScope

FraudShield DeceptiScope is an evidence-grounded Android APK investigation platform for fraudulent applications used in banking fraud. It validates uploaded APKs, extracts static evidence, plans constrained runtime experiments, collects typed runtime evidence, verifies hypotheses deterministically, and produces analyst-facing risk, lineage, campaign and report outputs.

DeceptiScope is APK-only. Removed non-APK workflows are not part of the current API, worker, database schema, CLI, frontend, dependency set, tests or documentation.

## Result Semantics

DeceptiScope returns one of these assessment labels:

- `KNOWN_MALICIOUS`: configured hash reputation identifies the exact SHA-256 under the local threshold policy.
- `HIGH_RISK`: the APK has a critical deterministic combination of observed behaviors.
- `SUSPICIOUS`: visible evidence crosses the high-risk review threshold.
- `REVIEW_REQUIRED`: suspicious evidence exists below that threshold.
- `LOW_RISK_OBSERVED`: no configured high-risk combination was observed within completed static coverage.
- `INCONCLUSIVE`: coverage is partial, so absence of findings cannot support a low-risk conclusion.

None of these labels proves that an APK is legitimate. The API always returns `legitimacy: not-established` and `safe_to_install: false`; publisher identity must be verified against an authoritative package and signing-certificate inventory.

## Core Workflow

```text
APK ingestion
-> static reverse engineering
-> normalized evidence
-> AI investigation
-> approved experiments
-> isolated runtime observation
-> deterministic verification
-> runtime-aware risk
-> FraudDNA/campaign intelligence
-> banking impact/report
```

## Architecture

1. Stream the upload to a private temporary file with a hard byte limit and SHA-256 calculation.
2. Reject non-ZIP data, path traversal, duplicate entries, excessive entry counts and zip-bomb expansion.
3. Extract bounded archive, Android manifest, DEX, component, permission, certificate, string, network and obfuscation evidence.
4. Run the multi-engine analyzer. Every optional engine records `completed`, `disabled`, `unavailable`, `failed` or `blocked-by-policy`; a missing engine never becomes a clean signal.
5. Calculate category-relative Fraud Delta and deterministic static baseline risk (`static_score`) under `apk-risk-2026.5`.
6. Run the evidence-grounded AI Investigator to plan safe sandbox experiments; execute verified injections in an isolated emulator, collect runtime observations with explicit trust levels (`PAYLOAD_CORRELATED`, `INSTRUMENTED`, `SYSTEM_OBSERVED`, `LOG_OBSERVED`, `INFERRED`), verify hypotheses with deterministic rules, and compute capped runtime adjustments.
7. Map supported evidence to MITRE ATT&CK for Mobile, generate the malware assessment, persist the result and emit indicators only for high/critical analyses.
8. Generate analyst narrative and forensic report. Two separate AI concepts are strictly maintained:
   - **AI Investigator**: proposes evidence-grounded hypotheses and constrained experiment plans; results are verified deterministically by code and AI cannot modify scores.
   - **Narrative Generator**: generates human-readable summaries and explanations from verified structured JSON; cannot alter verdicts, scores or indicators.

Third-party attribution and dependency notices are maintained in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [LICENSE](LICENSE).

## Engine Matrix

| Engine | Default | Data path | Purpose |
|---|---:|---|---|
| Guarded archive + native inventory | on | local | Archive structure, DEX/native libraries, embedded payloads and common SDK markers |
| Androguard | on | local | Manifest, components, permissions, DEX and signing-certificate extraction |
| APKiD | on when installed | local | Packers, obfuscators and anti-analysis markers |
| Bundled YARA rules | on when installed | local | Banking-risk capability combinations with bounded scoring metadata |
| Android `apksigner` | on when installed | local | Signature and scheme verification |
| ssdeep / Dexofuzzy | on when installed | local | Similarity fingerprints; not a verdict by themselves |
| Quark Engine | opt-in | local offline rules | Behavior-rule analysis; rule downloads are never automatic |
| MobSF | opt-in | configured private service | Broader self-hosted static analysis; APK transfer requires an explicit flag |
| VirusTotal | opt-in | external SHA-256 only | Exact-hash reputation; no sample upload |
| MalwareBazaar | opt-in | external SHA-256 only | Exact-hash reputation; no sample upload |
| Dynamic-lite ADB | opt-in | isolated emulator only | Bounded runtime observations with trust provenance; raw logs do not score directly, but trusted deterministically verified evidence contributes capped runtime adjustments under `apk-risk-2026.5` |

## Local Quick Start

Requirements: Python 3.11-3.13 and Node.js 20.19+ or 22.12+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e '.[dev]'
cp .env.example .env
fraudshield serve --host 127.0.0.1 --port 8000
```

The core product works with Androguard. To enable the heavier local adapters:

```bash
python -m pip install -e '.[analysis]'
```

Some optional packages need platform build libraries. Android signature verification also requires Android SDK Build Tools (`apksigner`). Quark additionally needs an operator-reviewed offline rules directory. Check actual runtime state at `GET /api/v1/system/capabilities` rather than assuming an installed package is usable.

Start a durable worker in another terminal:

```bash
source .venv/bin/activate
fraudshield worker
```

Start the frontend:

```bash
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
```

Open `http://127.0.0.1:5173`. API documentation is available at `http://127.0.0.1:8000/docs` in the development profile.

## Submit an APK

For the durable production-shaped path:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/jobs/apk-analysis \
  -H "X-API-Key: $FRAUDSHIELD_API_KEY" \
  -H "Idempotency-Key: apk-example-0001" \
  -F "file=@sample.apk;type=application/vnd.android.package-archive" \
  -F "category=banking" \
  -F "dynamic=false"
```

Poll `GET /api/v1/jobs/{job_id}`, then follow `result.resource`. Development can also enable the synchronous `POST /api/v1/apk-analyses` route.

## Analysis Verification

Analyses can be submitted asynchronously via `POST /api/v1/jobs/apk-analysis` or synchronously in development via `POST /api/v1/apk-analyses`. Generated findings and reports are deterministic and verifiable against technical evidence.

## Privacy Defaults

- Submitted APK bytes stay local unless an operator explicitly enables a configured private MobSF transfer.
- Public reputation providers receive only SHA-256 and are disabled by default.
- DeceptiScope never uploads an unknown sample to VirusTotal or MalwareBazaar.
- Quark rule downloads are not automatic.
- Uploaded files are deleted after processing unless retention is explicitly enabled; durable object artifacts are integrity-checked before analysis.
- Optional LLM use is disabled by default and separately gated in production.

## Verification

```bash
python -m compileall fraudshield tests
ruff check .
pytest -ra
python -m build
cd frontend
npm ci
npm test
npm run check
npm run build
```

Regenerate the checked-in OpenAPI contract after API changes:

```bash
make openapi
```

## Deployment Boundary

The repository provides production-oriented software controls: PostgreSQL pooling, S3/KMS artifact storage, durable leased jobs, OIDC/JWKS RBAC, HMAC-chained audit events, metrics, container hardening and Helm resources. It is not itself a certified bank deployment or a substitute for independent malware-lab isolation.

Before go-live, the bank still needs approved infrastructure and data residency, named service owners, secrets/KMS, egress allowlists, isolated analysis workers, a reviewed APK/rule corpus, signing-certificate inventory, independent VA/PT, SOC/SIEM integration, backup/restore evidence, incident response, rule/model governance and formal change/risk approval. Start with [production deployment](docs/PRODUCTION_DEPLOYMENT.md), [architecture](docs/ARCHITECTURE.md), [security controls](docs/SECURITY_CONTROLS.md), [threat model](docs/THREAT_MODEL.md), [API](docs/API.md), and [release gates](docs/RELEASE_GATES.md).
