# Operations runbook

## Monitor continuously

- API availability, latency and 4xx/5xx rate by route template.
- `fraudshield_audit_persistence_failures_total` (page immediately on increase).
- `fraudshield_jobs{status=...}` and
  `fraudshield_oldest_queued_job_age_seconds`.
- PostgreSQL availability, replication, locks, pool usage, storage and backup age.
- Object-store/KMS errors, denied requests, versioning/replication and access logs.
- Worker restarts, OOM/CPU throttling, lease loss, failure/retry rate and sandbox alerts.
- OIDC/JWKS failures and unusual 401/403/admin activity.
- Kubernetes deployment availability, HPA saturation and NetworkPolicy denies.
- SIEM audit-event lag and scheduled audit-chain verification.

Alert thresholds and SLOs are **TO BE APPROVED** from measured load, business
criticality and the bank's RTO/RPO. Do not copy generic numbers into an SLA.

## Daily

- Review failed/old queued jobs and unexpected admin/auditor actions.
- Check API/worker readiness, database/object/KMS health and SIEM delivery.
- Confirm backup jobs and vulnerability/feed alerts completed.

## Weekly

- Review capacity trends, dependency/container advisories and job retry causes.
- Sample an artifact hash and confirm audit-chain verification.
- Review NetworkPolicy/WAF denies for attack or misconfiguration patterns.

## Monthly / release cadence

- Review access assignments and break-glass use under bank policy.
- Patch/rebuild from approved dependencies; generate SBOM and rescan.
- Review scoring false positives/negatives with fraud operations; version and
  approve any rule/baseline change.
- Test a restore component according to the DR schedule.

## Common responses

| Symptom | First checks | Safe action |
| --- | --- | --- |
| Readiness `database=false` | PostgreSQL DNS/TLS/cert, pool, NetworkPolicy, credentials. | Stop mutations at gateway; do not switch to SQLite. |
| Readiness `storage=false` | S3 endpoint/KMS/workload identity/CA, egress policy. | Pause upload/job submission; do not use pod-local evidence storage. |
| Readiness `audit=false` | DB health/locks and audit error logs. | Pod becomes unready and production mutations fail closed; invoke incident process if prolonged. |
| Queue age rises | Worker replicas/resources, failed jobs, DB locks, S3/KMS, sandbox. | Scale within tested capacity; investigate before mass retry. |
| Audit chain invalid | Key ring, restore/change history, first invalid sequence. | Preserve evidence, restrict admin access and declare an incident; never rewrite rows to “fix” it. |
| OIDC failures | issuer/audience/JWKS/CA, IdP key overlap, clock sync. | Correct IdP/config; never disable signature/issuer/audience checks. |

