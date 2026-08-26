# Changelog

## 3.0.0 - DeceptiScope multi-engine APK product

- Removed the transaction-graph product, endpoints, worker path, repositories, fresh-schema tables, UI, tests and direct dependency.
- Added bounded APKiD, YARA, `apksigner`, similarity, Quark and private MobSF adapters with explicit per-engine status.
- Added opt-in SHA-256-only VirusTotal and MalwareBazaar reputation; public APK submission is prohibited.
- Added an explicit malware-assessment contract that never equates unknown/low-risk evidence with legitimacy or installation safety.
- Added third-party notices, AGPL-3.0 source licensing, engine setup, migration guidance and an APK-only OpenAPI/UI contract.

## 2.1.0 — 2026-08-17

- Combined the verified v2.1 API/worker with the React analyst application in a single release.
- Reconciled every frontend request, response, durable-job and evidence field with the checked-in v2.1 OpenAPI contract.
- Added abortable bounded job polling, correct cancel/retry flows, durable graph jobs, authenticated PDF retrieval and error-boundary handling.
- Replaced invented or stale UI values with live health, capability, dashboard, analysis, graph and demo evidence.
- Added same-origin UI/API routing, hardened non-root frontend container, three-service Compose and frontend Helm deployment resources.
- Added frontend contract tests, TypeScript/lint/build CI, a container-build gate and full-stack deployment documentation.
- Verified the live UI proxy, synthetic hero demo and independently processed durable graph job end to end.
- Removed bundled development secrets, generated state, external font dependencies and obsolete v2.0 frontend assets.

### Backend production foundation

- Added PostgreSQL connection pooling and cross-replica serialized migrations while retaining SQLite for local tests.
- Added KMS-configured S3/MinIO artifact storage and SHA-256 verification after materialization.
- Added durable jobs, idempotency keys, PostgreSQL `SKIP LOCKED` claiming, leases, heartbeats, retries and worker CLI.
- Added OIDC/JWKS token validation, five-role RBAC and production rejection of API-key-only operation by default.
- Added HMAC-chained security audits, key rotation, chain verification, hashed client metadata and structured SIEM logs.
- Added Prometheus request, queue and audit-failure metrics plus fail-closed audit readiness.
- Added strict production configuration gates, disabled production demo/docs/legacy/inline analysis, and trusted-proxy/host controls.
- Added a multi-stage non-root container and production Helm chart with restricted pods, sandbox workers, HPA, PDB, probes, TLS ingress and NetworkPolicy.
- Added a hash-locked production dependency set and conflict-safe idempotency semantics.
- Added a threat model, regulatory control map, production/release guide and incident, DR, key-rotation and operations runbooks.

## 2.0.0 — 2026-08-16

- Rebuilt the recovered demo into a persisted, versioned FastAPI backend.
- Removed synthetic-on-error APK behavior and invented LLM fallback evidence.
- Added bounded APK/CSV ingestion and archive safety checks.
- Added evidence-preserving archive fallback when Androguard cannot complete.
- Corrected MITRE ATT&CK for Mobile mappings and source links.
- Added deterministic scoring with rule contributions and confidence/coverage.
- Added normalized IOC sightings and historical transaction-signal matching.
- Added the legacy CSV/graph workflow that was removed from the v3 APK-only product.
- Added account investigation, next-hop ranking, non-executing action ladder, and PDF export.
- Added API-key protection, CORS allowlist, request IDs, security headers, Docker, CI, and tests.
- Filtered Android namespaces/package names from network IOCs and distinguished signature-block hashes from certificate hashes.
- Prevented rapid-outflow double counting and restricted next-hop IOC bonuses to verified indicator-store matches.
