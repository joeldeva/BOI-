# Security and responsible operation

FraudShield is defensive bank-analyst tooling. Report vulnerabilities privately
to the project/security owner; never attach live malware, secrets, customer data,
tokens or database dumps to a public issue.

## Production security boundary

- Production requires PostgreSQL with `sslmode=verify-full`, KMS-backed S3/MinIO,
  HTTPS OIDC/JWKS, explicit trusted hosts/HTTPS CORS origins, OIDC RBAC, a signed
  audit chain, metrics, and disabled docs/demo/legacy/inline-analysis routes.
- Helm runs backend workloads as UID 10001 and the frontend as non-root UID 101,
  with read-only root filesystems, dropped capabilities,
  RuntimeDefault seccomp, Restricted Pod Security, resource limits and a
  fail-closed NetworkPolicy. Worker RuntimeClass should be gVisor/Kata or the
  bank's equivalent sandbox.
- The public gateway must add TLS, WAF, DDoS and rate/body controls. The coarse
  `/health` status used by the analyst UI may be exposed through that gateway;
  `/health/ready` and `/metrics` stay platform-internal.
- Secrets come from the bank secrets manager; object access should use workload identity.
- Browser identity/session handling belongs to the bank access proxy/BFF. No
  service API key, client secret, or token is embedded in frontend assets.

## APK handling

Static analysis never installs or executes an uploaded APK. Ingestion checks
extension, size, ZIP magic/structure, entry count, expanded size, compression,
paths, duplicates, encryption, symlinks and manifest presence. Evidence files use
restricted permissions, opaque object URIs, KMS encryption and SHA-256
verification after retrieval. Real malware belongs only in the approved isolated
lab; do not use personal devices/accounts or unrestricted networks.

Dynamic-lite is off in the production reference and can target only a configured
`emulator-*` device that reports itself as an emulator. A production dynamic
malware lab requires a separately approved isolation design.

## Identity, data and audit

OIDC access tokens are validated for signature, algorithm, issuer, audience,
expiry, issued-at and subject. Roles are least-privilege application roles; the
IdP must enforce MFA, lifecycle, session and privileged-access policy.

Audit rows are HMAC-chained and rotation-aware. This detects tampering but cannot
make a database administrator's storage immutable. Stream structured audit events
to the approved SIEM/WORM destination in India and retain them per policy (not
less than applicable CERT-In requirements). Never remove an old audit HMAC key
while retained events still use it.

Use only approved, masked APK fixtures outside production. The bank must approve
data classification, India residency, backups/DR, retention/deletion, support
access and any optional LLM provider. The production reference disables LLM.

## Decision safety

Scores prioritize investigation; they do not prove criminal intent. An LLM cannot
change a score. The service cannot freeze/block an account, submit a regulatory
report or accuse a person. High-impact actions require the bank's authorized
human/maker-checker workflow.

See `docs/THREAT_MODEL.md`, `docs/SECURITY_CONTROLS.md`,
`docs/PRODUCTION_DEPLOYMENT.md`, and `docs/runbooks/`.
