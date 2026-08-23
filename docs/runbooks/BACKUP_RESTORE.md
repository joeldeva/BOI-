# Backup and restore runbook

RTO and RPO are governance decisions. The application does not invent them.
Record approved values before production:

| Item | Approved value |
| --- | --- |
| Service criticality | **TO BE APPROVED** |
| PostgreSQL RPO / RTO | **TO BE APPROVED** |
| Object evidence RPO / RTO | **TO BE APPROVED** |
| Audit/SIEM RPO / RTO | **TO BE APPROVED** |
| DR region/site and data residency | **TO BE APPROVED** |

RBI's 2023 IT Governance Directions require defined RPO/RTO, protected usable
backups, periodic restoration, and at least half-yearly DR drills for critical
systems. The Digital Payment Security Controls also call for periodic restore
testing without loss of critical records or audit trails. The bank may require
more frequent testing.

## Backup inventory

- PostgreSQL: encrypted full backups plus WAL/PITR, schema version, roles/grants,
  checksums and backup-job evidence.
- Object storage: versioning, KMS policy, lifecycle/retention, cross-site copy if
  approved, inventory and access logs.
- Audit: database chain plus immutable SIEM/WORM copy and every still-required
  HMAC key version.
- Configuration: reviewed Helm values, manifests, CA bundle references, image
  digest/signature/SBOM and secret-manager references—not plaintext secrets.
- Scoring baselines/rules and trusted bank signer inventory.

## Restore test

1. Open an approved DR test change; record target recovery point and expected hashes/counts.
2. Restore PostgreSQL to a new isolated instance using the selected PITR point.
3. Restore/attach object versions without overwriting the source environment.
4. Restore secret references and prior audit HMAC keys from the secrets manager.
5. Deploy the exact approved image digest with ingress disabled.
6. Run `fraudshield init-db`; forward migrations must complete idempotently.
7. Compare table counts, newest IDs/timestamps, queued/running jobs and object inventory.
8. Verify sampled object SHA-256 values and `/api/v1/audit-events/verify`.
9. Run synthetic smoke tests and approved non-sensitive fixtures.
10. Record achieved RPO/RTO, discrepancies, remediation and owner sign-off.

## Production recovery

Freeze writes at the gateway, preserve evidence, and select a recovery point with
fraud operations/data owners. Restore into new resources when integrity is in
doubt. Do not point production at the restored database until reconciliation,
audit verification, OIDC/RBAC tests, KMS/object access tests, and service-owner
approval are complete. Jobs that were `running` at the recovery point may be
reclaimed after their lease expires; review for duplicate side effects even
though FraudShield itself performs no enforcement action.
