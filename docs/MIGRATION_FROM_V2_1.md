# Migration from FraudShield 2.1

## Recommended path: clean v3 folder

Do not unzip v3 over the old project. Keep the old folder as a read-only backup and place this ZIP in a new directory. Copy only reviewed configuration and deployment values.

1. Stop the old API, worker and frontend.
2. Back up the old database, object-storage prefix, secrets references and `.env`.
3. Extract `FraudShield_DeceptiScope_v3.0.0.zip` into a new empty folder.
4. Copy approved database, OIDC, S3/KMS, audit, host/CORS and retention values from the old `.env` into the new `.env.example` layout.
5. Do not copy old runtime uploads, generated reports, frontend build output, virtual environments, caches or dependency directories.
6. Create a new virtual environment, install dependencies and run the release checks.
7. For production, deploy v3 against a cloned database first and validate audit-chain history, APK analysis history, indicators and jobs.
8. Cut over only after the v3 release gates pass. Retain the old deployment and backup for the approved rollback window.

## Removed configuration

Remove the old CSV limits and any transaction-graph deployment settings. The current product has no CSV upload, dataset, graph-run, account investigation or graph-job endpoint.

## Database behavior

A fresh v3 database creates only APK analyses, indicators/sightings, durable APK jobs and audit-chain tables. If v3 is pointed at a v2 database, legacy tables may remain physically present but are inert: v3 contains no repository, route, worker or UI code that can read or write them.

They are intentionally not dropped automatically because an application startup must not destroy historical data. After retention/legal approval and a verified backup, a database administrator may archive and remove those legacy tables under a separate change record.

Existing v2 durable graph jobs cannot be processed by the v3 worker. Drain or cancel them before cutover. Existing APK jobs and APK analysis records remain structurally compatible, but test this on a clone before production migration.

## API compatibility

Retained:

- `/api/v1/apk-analyses`
- `/api/v1/jobs/apk-analysis`
- `/api/v1/jobs/{job_id}` and job control endpoints
- `/api/v1/indicators`
- `/api/v1/audit-events`
- development legacy APK/report endpoints when explicitly enabled

Removed:
- `/api/v1/demo/seed` (all demo routes removed in v3.0)

Removed operations are absent from OpenAPI and return `404` or method-not-allowed `405` where a generic resource path still matches. Regenerate clients from `docs/openapi.json`; do not reuse the v2 graph client types.

## Result changes

APK result schema is now `3.0` and adds:

- `engine_analysis` with policy, engine status, bounded summaries, normalized findings and reputation;
- `malware_assessment` with a careful verdict, limitations and explicit non-legitimacy stance;
- bounded optional-engine contributions in deterministic rule evidence;
- an `apk_sha256` indicator for high/critical analyses.

Consumers should tolerate new engine IDs and unknown optional-engine statuses.
