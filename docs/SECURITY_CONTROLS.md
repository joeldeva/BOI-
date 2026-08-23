# Security and regulatory control map

This is an engineering control map, not a legal opinion or compliance
certificate. Applicability and evidence sufficiency must be confirmed by the
bank's CISO, compliance, legal, privacy, risk, internal audit, and service owner.

| Control objective | FraudShield implementation | External bank control / evidence | Status |
| --- | --- | --- | --- |
| Need-based access and privileged oversight | OIDC JWT validation plus `viewer`, `analyst`, `investigator`, `auditor`, `admin` permissions; every protected request is audited. | IdP MFA, joiner/mover/leaver process, quarterly access review, privileged-access monitoring. | Shared |
| Audit trails and forensic evidence | Append-only audit API, sequence numbers, HMAC hash chain, key IDs/rotation support, request IDs, actor/action/resource/status, hashed client address and user agent. | Export stdout audit events to immutable/WORM SIEM; 180-day-or-longer approved retention in India; periodic chain verification. | Shared |
| Strong cryptography | OIDC accepts approved asymmetric algorithms only; PostgreSQL requires `sslmode=verify-full`; S3 uses KMS in production; HTTPS-only origins/endpoints. | KMS/HSM policy, certificate lifecycle, approved CA bundle, database/object-store encryption evidence. | Shared |
| Secure application lifecycle | Strict input models, bounded uploads, ZIP-bomb/path/symlink guards, deterministic tests, dependency audit/SBOM baseline, threat model, non-root image. | Independent source review, VA/PT, container scan, signed provenance, change approval, periodic retest. | Shared |
| Segregated architecture and resilience | Stateless API, separate sandboxed workers, HA-ready PostgreSQL, object storage, probes, HPA, PDB, fail-closed NetworkPolicy. | Multi-site platform, capacity tests, WAF/DDoS, RTO/RPO approval, half-yearly DR exercise and restore evidence. | Shared |
| Fraud analysis and explainability | Versioned deterministic rules, evidence contributions, Fraud Delta, IOC correlation, account evidence and next-hop ranking. LLM cannot change scores. | Model/rule governance, tuning approval, false-positive review, drift/performance monitoring, analyst training. | Shared |
| Human decision control | Recommendations are advisory; `automatically_executed` is false; no freeze/block/regulatory submission connector is implemented. | Approved case workflow, maker-checker controls, customer protection and escalation SOPs. | External |
| Data residency | Production settings require external PostgreSQL and KMS-backed object storage; reference region is India. | Contract and technical proof that payment data, backups, logs, support access, and DR copies meet RBI requirements. | External |
| Incident response | Incident runbook, correlated request/job/audit IDs, audit integrity check, reversible containment steps. | Named CSIRT/CERT-In/RBI contacts, 24x7 SOC, reporting authority, exercises and evidence. | Shared |
| Secrets | No production secrets in values; existing Secret/workload identity; audit keys support explicit versions. | Vault/native secrets manager, dual control, rotation schedule, break-glass monitoring. | Shared |

## Regulatory sources used for the design

- [RBI Digital Payment Security Controls, 2021](https://www.rbi.org.in/scripts/NotificationUser.aspx?Id=12032&Mode=0) covers governance, risk assessment, resilience, WAF/DDoS, secure-by-design development, threat modelling, testing, monitoring, fraud parameters, and incident SOPs.
- [RBI IT Governance, Risk, Controls and Assurance Practices Directions, 2023](https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12562) covers audit trails, strong cryptography, need-based access, metrics, incident response, and BCP/DR.
- [RBI Storage of Payment System Data FAQ](https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=2995) explains storage of payment data in India and treatment of overseas processing.
- [CERT-In Directions under section 70B](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf) require applicable incidents to be reported within six hours and ICT logs to be securely retained for a rolling 180 days in Indian jurisdiction.
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) and [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) inform the restricted pod and network design.

Regulations and bank policies change. Revalidate this map at each release and
before any production approval.

