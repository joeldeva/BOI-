# Production deployment

FraudShield DeceptiScope 3.0 supplies a production-oriented APK intelligence
application and a vendor-neutral Kubernetes/Helm reference deployment. It does
**not** by itself grant RBI,
CERT-In, PCI DSS, ISO 27001, or bank production approval. The regulated entity
must complete governance, risk acceptance, VA/PT, privacy, data-residency,
vendor, SOC, DR, and change-management gates.

## Target topology

The reference deployment has these bank-controlled components:

- Bank analyst browser behind the approved WAF/access proxy or BFF.
- Workforce OIDC identity provider with MFA and role claims.
- Static FraudShield frontend replicas served same-origin with the API.
- Stateless FraudShield API replicas.
- Sandboxed APK worker replicas with deny-by-default egress.
- HA PostgreSQL for analyses, indicators, jobs and audit events.
- KMS-encrypted S3/MinIO for queued APK artifacts and generated reports.
- Metrics/logging export to the bank SIEM and observability platform.

The frontend is a static same-origin application. The bank access proxy owns the
approved authorization-code/session flow and forwards a Bearer token to the API;
no service credential is embedded in browser assets. The API is stateless. It validates OIDC access tokens, applies FraudShield RBAC,
accepts bounded uploads, stores queued APK evidence in object storage, and
creates durable jobs. Workers claim jobs with PostgreSQL row locks and renewable
leases. In production, inline analysis, interactive docs, demo endpoints, and
legacy endpoints are disabled.

## Bank-managed prerequisites

- Kubernetes 1.29+ with Restricted Pod Security Admission and a supported
  NetworkPolicy implementation.
- A runtime sandbox such as gVisor or Kata for APK worker pods.
- PostgreSQL HA with TLS hostname verification, encryption at rest, PITR,
  monitoring, a tested cross-site recovery design, and least-privilege roles.
- S3-compatible storage located in the approved jurisdiction, with KMS
  encryption, versioning, lifecycle policy, access logging, and tested restore.
- Workforce OIDC with MFA enforced by the identity provider. Tokens must carry
  one or more roles: `viewer`, `analyst`, `investigator`, `auditor`, `admin`.
- A bank WAF/API gateway providing TLS, rate limiting, DDoS controls, request
  normalization, and allowlisted administrative access.
- A secrets manager or External Secrets integration. Do not commit populated
  Kubernetes Secrets.
- Central metrics/logging and an India-resident SIEM retention policy.

## Runtime secrets

The Secret named by Helm `existingSecret` must provide:

| Variable | Requirement |
| --- | --- |
| `FRAUDSHIELD_DATABASE_URL` | PostgreSQL URL with `sslmode=verify-full`; use `sslrootcert` for a private CA. |
| `FRAUDSHIELD_AUDIT_HMAC_KEY` | At least 32 random characters from the bank secrets manager. |
| `FRAUDSHIELD_AUDIT_HMAC_PREVIOUS_KEYS` | Optional comma-separated `key-id=old-secret` entries during rotation. |

Prefer workload identity for object storage. If the platform cannot provide it,
the Secret may also hold the provider's short-lived access variables. Static,
long-lived cloud credentials are not the recommended design.

## Build and release

1. Build from a reviewed commit in the bank CI environment.
2. Review and install `requirements-production.lock` with hash checking; update
   it only through a dependency-review change.
3. Run unit/integration tests, SAST, dependency audit, secret scan, container
   scan, and the Helm render/server-side dry run.
4. Produce SBOMs and provenance attestations; sign both backend and frontend images.
5. Mirror base images and dependencies into approved internal registries.
6. Pin both deployed images by digest in the production values file. Build the
   frontend with `VITE_DEMO_ENABLED=false` and an empty same-origin API base URL.
7. Obtain change, security, data-owner, and service-owner approvals.

The checked-in CI is a baseline. The bank release pipeline remains responsible
for signing, attestation verification, registry policy, and separation of duties.

## Install

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
helm lint deploy/helm/fraudshield \
  -f /secure/path/fraudshield-production-values.yaml
helm upgrade --install fraudshield deploy/helm/fraudshield \
  --namespace fraudshield \
  -f /secure/path/fraudshield-production-values.yaml \
  --atomic --timeout 15m
```

Populate exact egress CIDRs or approved namespace selectors before rollout. The
default NetworkPolicy permits DNS only and therefore fails closed.

## Required acceptance tests

- `/health/live` succeeds from the kubelet and `/health/ready` reports database,
  artifact storage, baseline, and audit health.
- OIDC signature, issuer, audience, expiry, subject, and role tests succeed;
  missing/incorrect tokens fail.
- Each role passes only its documented permissions.
- Queue an approved APK fixture, run workers, poll the job, retrieve the
  resulting APK analysis, and download a PDF.
- Verify uploaded object metadata/encryption and confirm no internal artifact URI
  is returned by the API.
- Call `/api/v1/audit-events/verify` as an auditor and confirm the chain is valid.
- Confirm security audit events arrive in the SIEM with request and event IDs.
- Prove worker egress cannot reach the public Internet.
- Execute PostgreSQL PITR and object-version restore in the DR environment.
- Run load tests against agreed capacity targets and validate autoscaling.
- Verify the access proxy login, logout, idle/session timeout, MFA, CSRF controls,
  401/403 behavior, and forwarded-token audience/role mapping end to end.

## Frontend production flow

The checked-in UI uses the same durable flow in local and production modes:

1. `POST /api/v1/jobs/apk-analysis` with an idempotency key.
2. Poll `GET /api/v1/jobs/{job_id}` with bounded exponential backoff.
3. Follow `result.resource` after status becomes `completed`.
4. Stop polling on `failed` or `cancelled` and display the safe error plus the
   request/job ID.

Access tokens belong in memory or an approved BFF/session design, never in a
Vite build variable or long-lived browser storage.

## Rollback

Application rollback is performed by deploying the last approved image digest.
Database migrations are forward-only; do not attempt ad-hoc schema reversal.
Before a release, take/verify the approved PostgreSQL recovery point. If a schema
defect is involved, contain writes, restore to a new database, reconcile under
the bank's change process, and then repoint the service. See
`docs/runbooks/BACKUP_RESTORE.md`.
