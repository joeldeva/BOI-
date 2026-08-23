# Threat model

## Scope and assets

Protected assets include uploaded APK evidence, package and certificate
identifiers, analysis results, threat indicators, audit evidence, credentials,
encryption keys, worker jobs, scoring rules, and the integrity/availability of
analyst decisions. FraudShield is decision support; it is not a malware oracle
and cannot execute enforcement actions.

Trust boundaries are the analyst browser/API gateway, OIDC provider, API pods,
PostgreSQL, object storage/KMS, sandboxed workers, optional LLM provider, and
observability/SIEM platform.

## Principal threats and mitigations

| Threat | Mitigations | Residual risk / required owner action |
| --- | --- | --- |
| Malicious APK exploits a parser | Static-only default, strict archive limits, non-root/read-only worker, Restricted PSS, no ingress, allowlisted egress, optional gVisor/Kata RuntimeClass. | Parser zero-days remain possible. Keep workers isolated, patched, disposable, and outside trusted application networks. |
| ZIP bomb/path traversal/symlink | Size, entry, expanded-size, compression, path, duplicate, encryption, symlink, manifest and magic checks before extraction. | Validate limits through hostile-corpus testing. |
| Stolen/forged access token | JWKS signature verification, explicit issuer/audience/expiry/issued-at/subject, asymmetric allowlist, RBAC, audit. | IdP must enforce MFA, short token lifetime, secure sessions, revocation and access reviews. |
| Insider changes or deletes audit rows | HMAC chain, sequence state lock, key IDs, auditor verification, duplicate structured SIEM event. | Database admins can rewrite data/state. Immutable external SIEM/WORM retention and dual control are mandatory. |
| Artifact tampering | SHA-256 recorded on ingestion and verified again after materialization; KMS-backed S3 and opaque API responses. | KMS/storage policy, object versioning/lock and access-log monitoring are external. |
| Job duplication or abandoned workers | PostgreSQL `FOR UPDATE SKIP LOCKED`, leases, heartbeats, attempt limits, idempotency keys. | Exactly-once processing is not claimed. Downstream actions must remain idempotent and human-approved. |
| Data exfiltration | Production NetworkPolicy fail-closed, exact egress CIDRs, no browser service key, encrypted transport/storage, no raw client IP in DB audit. | Bank proxy, DLP, database and object-store policies must enforce residency and least privilege. |
| DoS/resource exhaustion | Gateway rate/body limits, bounded uploads/ZIP expansion, API HPA, per-pod semaphore, durable workers and resource limits. | Capacity and attack testing must set bank-specific thresholds; WAF/DDoS is external. |
| SQL injection/path injection | Parameterized SQL, internal-only dynamic clauses, safe filenames, artifact URI validation, no server path API. | Continue SAST, review and negative testing. |
| LLM prompt injection/hallucination | LLM optional/disabled in production reference; receives structured evidence; cannot set score, IOC, or enforcement. | Any enabled provider needs privacy/legal approval, residency review and output monitoring. |
| Misleading APK evidence / false confidence | Every result exposes extraction coverage, optional-engine status, evidence and limitations; missing engines and zero detections never imply safety. | Analysts need approved benign and malicious fixtures, signer inventories and review procedures. |
| Supply-chain compromise | Minimal non-root image, CI dependency audit, SBOM baseline, digest deployment field. | Bank CI must pin dependencies/base images, scan, sign, attest, and enforce admission verification. |

## Security invariants

- Synthetic evidence is never used as a fallback for failed real analysis.
- An LLM cannot alter deterministic risk scoring.
- A recommendation cannot execute a bank action.
- Production cannot start with SQLite, local artifacts, disabled authentication,
  wildcard hosts/origins, HTTP OIDC/S3 endpoints, interactive docs, demos,
  legacy APIs, inline heavy analysis, or an unsigned audit chain.
- Internal artifact locations and database secrets are never returned by the API.

## Out of scope / not yet claimed

- Formal malware-detector accuracy, population calibration, or zero-day coverage.
- Automated core-banking, payment-switch, NCRP, RBI, or account-control actions.
- A bank-approved SOC, WAF, IdP, KMS, DR site, data classification, retention
  schedule, model-risk process, VA/PT report, or compliance certification.
