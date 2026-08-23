# Production release gates

A release is not production-approved until every applicable gate has named
evidence and an authorized approver.

- Functional: backend unit/integration/API/worker/migration tests and frontend
  contract/type/lint/build tests pass; OpenAPI and UI contract changes are reviewed.
- Security: threat model updated; SAST/SCA/secret/container scans clean or risk-accepted; SBOM and signed provenance produced.
- Independent assurance: required source review, VA/PT and remediation evidence completed under bank/RBI policy.
- Data: classification, minimization, masking, India residency, retention/deletion and LLM/provider decisions approved.
- Identity: OIDC MFA, role mappings, least privilege, access review and
  break-glass monitoring tested; the browser-to-API access proxy/BFF pattern is
  threat-modeled and does not expose reusable service credentials to JavaScript.
- Platform: UI and API image digests/signatures, exact ingress/egress policy,
  WAF/DDoS/rate limits, restricted/sandbox runtime, TLS/CA, CSP and KMS evidence verified.
- Resilience: capacity results, monitoring/alerts, on-call, backups, restore and DR/RTO/RPO evidence approved.
- Operations: incident contacts/reporting path, runbooks, dashboards and support ownership complete.
- Fraud/model risk: scoring version, evidence rules, calibration limitations, human-review workflow and false-positive process approved.
- Change: image digest/signature, migration/rollback plan, maintenance window and segregation-of-duties approvals recorded.

Automatic blockers should include failing tests, dependency vulnerabilities above
bank policy, secret detection, unsigned/unattested images, unapproved critical
findings, wildcard network exposure, disabled TLS verification, or incomplete DR
and incident ownership.
