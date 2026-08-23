# Key and credential rotation

Use the bank secrets manager and dual-control process. Never place real secrets
in Git, Helm values, tickets, chat, screenshots, or test fixtures.

## Audit HMAC key

FraudShield stores an `audit_key_id` with each new event. To rotate without
breaking historical verification:

1. Generate a new random key in the secrets manager and assign a unique ID.
2. Keep the old secret available read-only during the full audit retention period.
3. Set `FRAUDSHIELD_AUDIT_HMAC_KEY` to the new value and
   `FRAUDSHIELD_AUDIT_HMAC_KEY_ID` to the new ID.
4. Add old entries to `FRAUDSHIELD_AUDIT_HMAC_PREVIOUS_KEYS` as
   `old-id=old-secret` (use hex/base64 without commas).
5. Roll API and worker pods, generate a test event, then run audit verification twice.
6. Confirm SIEM ingestion records the new event/key ID and document the change.

Removing a prior key before its events expire makes those events unverifiable.
An emergency rotation after possible key disclosure must be handled as an
incident; the HMAC chain detects changes only while trusted key material remains
trusted and external immutable copies are preserved.

## PostgreSQL credentials

Create a new credential/version, update the Secret, roll pods, verify readiness
and migrations, then revoke the old credential. Use short-lived workload/database
identity where supported. Keep `sslmode=verify-full` and do not bypass a CA error.

## Object storage and KMS

Prefer workload identity. Rotate role/session policy without changing object
ownership. KMS key rotation/alias changes must preserve decrypt access to old
objects and be proven with a sampled old-object download/hash check before old
key material is retired.

## OIDC signing keys and clients

JWKS rotation is consumed through the configured JWKS URL and cache. Preserve
overlap until issued tokens expire. For client/audience changes, deploy the new
configuration, test every role, then retire the old client according to IdP policy.

## TLS certificates and CA bundles

Stage the new CA/certificate with an overlap window, update the mounted CA bundle
and database URL if needed, roll pods, and verify OIDC, PostgreSQL and S3 hostname
validation. Never change to `sslmode=require`, disable verification, or use an
HTTP endpoint as a rotation workaround.

