# Incident response runbook

This runbook must be incorporated into the bank's approved CSIRT process. Fill
the contact placeholders and reporting authority before go-live. Do not wait for
perfect attribution before beginning containment and regulatory assessment.

## Required contacts

| Role | Named contact / rota |
| --- | --- |
| Incident commander | **TO BE ASSIGNED** |
| Bank SOC / CSIRT | **TO BE ASSIGNED** |
| CISO delegate | **TO BE ASSIGNED** |
| Fraud operations owner | **TO BE ASSIGNED** |
| Privacy / legal / compliance | **TO BE ASSIGNED** |
| Platform, database, object storage, IdP | **TO BE ASSIGNED** |
| CERT-In and RBI reporting authority | **TO BE ASSIGNED** |

CERT-In's applicable 2022 directions specify reporting identified incident
classes within six hours of notice and rolling 180-day secure ICT log retention
in India. The bank's authorized team—not the application—decides applicability
and submits reports. See the [official direction](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf).

## Declare an incident when

- unauthorized access, suspicious admin use, token forgery, or credential leak is detected;
- audit-chain verification fails or security audit delivery stops;
- customer/payment data is accessed, changed, leaked, or stored outside policy;
- an APK appears to exploit the parser/worker or a worker makes unexpected connections;
- analysis/scoring rules or deployed images change without approval;
- PostgreSQL/object storage/KMS is compromised or materially unavailable;
- a service disruption crosses the bank's approved incident threshold.

## First 15 minutes

1. Open the bank incident record and assign incident commander/severity.
2. Record first-noticed time in synchronized UTC and local time; preserve the
   original alert, request ID, job ID, audit event ID and image digest.
3. Verify `/health/ready`, Prometheus alerts, recent deployment history and
   `/api/v1/audit-events/verify` using an auditor account.
4. Preserve evidence before cleanup: SIEM logs, Kubernetes events/pod metadata,
   database/object access logs, relevant object versions and approved snapshots.
5. If active compromise is plausible, stop new ingress or mutations at the WAF;
   do not delete pods, jobs, objects or database rows until evidence is preserved.
6. Notify SOC/CISO/legal/compliance under the approved escalation tree.

## Containment choices

- Revoke affected IdP sessions/clients and disable implicated identities.
- Rotate exposed API/database/object-store credentials through the secrets manager.
- Scale worker deployment to zero if parser compromise is suspected; quarantine
  the evidence object and image digest.
- Apply a narrow emergency NetworkPolicy/WAF deny rule under change control.
- Set the API read-only by blocking mutating routes at the gateway.
- Isolate, rather than destroy, affected nodes/pods where forensics is required.
- Never alter risk scores or audit rows to hide the incident.

## Within the reporting window

1. Establish known facts, affected systems/data, impact, containment, chronology
   and whether malicious mobile apps, fake apps, digital-payment systems, data
   breach/leak, critical systems, or cloud systems are involved.
2. Compliance/legal determines CERT-In, RBI, customer, law-enforcement and other
   notification duties; record the decision and approver.
3. Submit available facts within required timelines and supplement later. Keep
   copies, timestamps and acknowledgement IDs in the incident record.

## Eradication and recovery

- Deploy only a reviewed, scanned and signed image digest.
- Rotate affected keys; retain prior audit HMAC keys read-only so historical
  chains remain verifiable.
- Restore PostgreSQL/object data to new resources when integrity is uncertain.
- Verify migrations, object hashes, audit chain, OIDC roles and worker egress.
- Execute the approved smoke test before reopening traffic gradually.
- Monitor elevated alerts through the bank-approved observation period.

## Closure

Complete root-cause analysis, affected-record reconciliation, corrective actions,
control-owner assignments and deadlines. Update threat model, tests, runbooks and
detection rules. Exercise the changed procedure and retain evidence of review.

