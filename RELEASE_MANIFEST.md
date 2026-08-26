# FraudShield DeceptiScope Release Manifest

## Product

- FastAPI APK API and durable worker.
- React/Vite analyst dashboard.
- Guarded APK ingestion, Androguard extraction and deterministic risk/Fraud Delta.
- Multi-engine analyzer for native inventory, APKiD, YARA, `apksigner`, similarity, Quark, private MobSF and hash-only reputation.
- Careful malware-assessment verdict with explicit limitations and no legitimacy/safety claim.
- Evidence-grounded AI investigation, constrained experiment planning, typed runtime evidence and deterministic hypothesis verification.
- MITRE ATT&CK Mobile mapping, indicator registry, FraudDNA/campaign intelligence, banking-impact assessment, PDF reports and grounded optional narrative.
- PostgreSQL/S3/OIDC/audit/metrics/container/Helm production foundation.

## Source and Legal

- `LICENSE`: AGPL-3.0-only text.
- `THIRD_PARTY_NOTICES.md`: required third-party attribution and optional-tool notices.
- `docs/ENGINE_SETUP.md`: optional analysis-engine installation and operating guidance.
- `docs/FRONTEND.md`: frontend operation and verification guidance.
- Complete preferred-form source is included.

## Required Checks

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
docker build .
docker build frontend
docker compose config
helm lint deploy/helm/fraudshield
helm template fraudshield deploy/helm/fraudshield
```

Regenerate `docs/openapi.json`, production lock files and CycloneDX SBOM in the approved release environment. Record dependency, container and infrastructure scan evidence in the release ticket.

## Packaging Exclusions

Do not distribute runtime databases, uploaded APKs, generated reports, `.env`, credentials, virtual environments, `node_modules`, build caches, coverage data or developer-only output.
