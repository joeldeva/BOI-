# FraudShield DeceptiScope 3.0 release manifest

## Product

- FastAPI APK API and durable worker.
- React/Vite analyst dashboard.
- Guarded APK ingestion, Androguard extraction and deterministic risk/Fraud Delta.
- Multi-engine orchestrator for native inventory, APKiD, YARA, `apksigner`, similarity, Quark, private MobSF and hash-only reputation.
- Careful malware-assessment verdict with explicit limitations and no legitimacy/safety claim.
- MITRE ATT&CK Mobile mapping, indicator registry, PDF reports and grounded optional narrative.
- PostgreSQL/S3/OIDC/audit/metrics/container/Helm production foundation.

## Source and legal

- `LICENSE`: AGPL-3.0-only text.
- `THIRD_PARTY_NOTICES.md`: Pithus attribution and optional-tool notices.
- `docs/PITHUS_INTEGRATION.md`: adopted architecture and privacy deviations.
- `docs/LOCAL_VERIFICATION.md`: packaging-workspace evidence and explicit environment limits.
- Complete preferred-form source is included.

## Required checks

```bash
python -m pytest
python -m ruff check fraudshield tests
python -m build --no-isolation
cd frontend && npm run check
helm lint deploy/helm/fraudshield -f deploy/helm/fraudshield/values-production.example.yaml
```

Regenerate `docs/openapi.json`, production lock files and CycloneDX SBOM in the approved release environment. Record dependency, container and infrastructure scan evidence in the release ticket.

## Packaging exclusions

Do not distribute runtime databases, uploaded APKs, generated reports, `.env`, credentials, virtual environments, `node_modules`, build caches, coverage data or developer-only output.
