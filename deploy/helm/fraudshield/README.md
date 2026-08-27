# FraudShield Helm chart

This chart deploys the static FraudShield DeceptiScope analyst UI, stateless API,
and durable APK-analysis workers.
It intentionally does not install PostgreSQL, an identity provider, object
storage, a KMS, or a secrets manager; those must be bank-managed HA services.

## Required before install

1. A Kubernetes 1.29+ namespace enforcing the Restricted Pod Security Standard.
2. A TLS-secured PostgreSQL database reachable from the namespace.
3. An S3-compatible bucket in the required jurisdiction with versioning,
   lifecycle policy, access logging, KMS encryption, and backup configured.
4. An OIDC workforce client whose access token includes one or more roles:
   `viewer`, `analyst`, `investigator`, `auditor`, `admin`.
5. The existing Secret named by `existingSecret`, containing
   `FRAUDSHIELD_DATABASE_URL` and `FRAUDSHIELD_AUDIT_HMAC_KEY`.
6. A signed/attested container image pinned by digest.
7. A bank access proxy/BFF that performs the approved OIDC browser flow and
   forwards a validated Bearer access token to the API. The chart does not
   fabricate the bank identity/session layer.
8. A frontend container image pinned by content digest.
9. Worker images containing every local engine enabled in `config.analysis`.
   Validate the deployed capability endpoint; an enabled but absent optional
   package or executable is reported as `unavailable`.

If private MobSF is enabled, add `FRAUDSHIELD_MOBSF_API_KEY` to the existing
Secret and use an HTTPS bank-controlled endpoint. If hash reputation is enabled,
add `FRAUDSHIELD_VIRUSTOTAL_API_KEY` and, when required,
`FRAUDSHIELD_MALWAREBAZAAR_API_KEY`. Public providers receive only SHA-256;
DeceptiScope does not upload APK bytes to them. These integrations remain off in
the production example until privacy/legal approval and egress allowlisting are
complete.

## Render and validate

```bash
helm lint deploy/helm/fraudshield \
  --values deploy/helm/fraudshield/values-production.example.yaml
helm template fraudshield deploy/helm/fraudshield \
  --namespace fraudshield \
  --values deploy/helm/fraudshield/values-production.example.yaml > rendered.yaml
kubectl apply --server-side --dry-run=server -f rendered.yaml
```

The production example uses documentation-only egress CIDRs. Replace them with
the exact PostgreSQL, object-store, OIDC/JWKS, and approved proxy/SIEM ranges.
With NetworkPolicy enabled and no approved egress ranges, workloads fail closed.

## Install

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
helm upgrade --install fraudshield deploy/helm/fraudshield \
  --namespace fraudshield \
  --values /secure/path/fraudshield-production-values.yaml \
  --atomic --timeout 15m
```

The Ingress exposes the analyst UI, `/api`, and `/health`; `/metrics`, legacy
routes, interactive API docs, and demo routes stay internal or disabled in
production. Put the Ingress behind the bank access proxy/WAF.
