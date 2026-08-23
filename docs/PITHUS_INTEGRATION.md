# Pithus integration and modernization

## Design choice

Pithus is a capable Android malware-analysis portal, but its application architecture is Django + Elasticsearch + Django-Q. FraudShield already had a hardened FastAPI API, PostgreSQL persistence, durable workers, S3/KMS storage, OIDC, audit chaining and a React analyst UI. Embedding both complete web stacks would create duplicate identities, queues, persistence and security policy.

DeceptiScope therefore adopts Pithus at the analysis-engine boundary. One orchestrator normalizes results from compatible tools while the existing platform remains the system of record.

## Adopted capabilities

| Pithus capability | DeceptiScope 3 implementation |
|---|---|
| Androguard | Core manifest, component, DEX and certificate extraction |
| APKiD | Optional in-process adapter with packer/anti-analysis normalization |
| Quark | Optional offline-rule adapter with per-run rule cap |
| YARA | Bundled banking-capability rules plus configurable rule path |
| ssdeep / Dexofuzzy | Optional local fingerprint generation |
| MobSF | Optional configured private API with explicit APK-transfer consent |
| VirusTotal | SHA-256 lookup only; no sample upload |
| MalwareBazaar | SHA-256 lookup only; no sample upload or retry submission |
| Tracker discovery | Bounded offline SDK marker inventory; informational only |

## Modernized controls

- Every adapter has an explicit status and duration. Missing dependencies and engine failures are visible in the result.
- Archive reads, YARA entry scans, persisted engine output, network/subprocess timeouts, Quark rule counts and upload sizes are bounded. Quark remains opt-in and must also run inside the worker's CPU/memory/time limits.
- Public binary upload is hard-disabled. Unknown hashes are never submitted to a public repository.
- Quark rules are operator-managed offline data; the worker never downloads rules automatically.
- Optional findings use a normalized schema. Only high-confidence local evidence can affect the deterministic score, and contributions are capped per engine and risk dimension.
- Reputation affects the `KNOWN_MALICIOUS` assessment policy but a not-found or zero-detection response never reduces the behavioral score or establishes legitimacy.
- Dynamic-lite evidence remains separate from the deterministic score.
- Full raw MobSF/Quark reports are not persisted by default; bounded summaries and normalized evidence are stored.

## Installation profiles

Core:

```bash
python -m pip install -e .
```

Optional local analysis tools:

```bash
python -m pip install -e '.[analysis]'
```

Install Android SDK Build Tools separately for `apksigner`. Place reviewed Quark JSON rules under `FRAUDSHIELD_QUARK_RULES_DIR` and enable Quark only after validating their provenance.

## Licensing

Pithus is AGPL-3.0. This source distribution uses AGPL-3.0-only and includes the complete source and notices. See `LICENSE` and `THIRD_PARTY_NOTICES.md`. Operators offering a modified version over a network must satisfy the AGPL source-availability requirements. Obtain legal review for organizational deployment; this document is not legal advice.
