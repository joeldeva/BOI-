# API reference

The generated contract is `docs/openapi.json`. Development documentation is available at `/docs` when enabled.

## Authentication

Development may use disabled authentication or `X-API-Key`. Production requires OIDC by default. Role permissions are enforced server-side.

## System

- `GET /`
- `GET /health`
- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/system/capabilities` — live engine availability and privacy policy.
- `GET /api/v1/dashboard/summary`
- `GET /metrics` when enabled.

## Durable APK jobs

`POST /api/v1/jobs/apk-analysis` accepts multipart fields:

- `file`: APK
- `category`: `banking`, `finance`, `utility`, or `other`
- `dynamic`: boolean
- `priority`: 0–1000
- `max_attempts`: 1–20
- `Idempotency-Key`: optional header, 8–256 safe characters

The public job payload never reveals internal artifact paths/URIs. Poll:

- `GET /api/v1/jobs/{job_id}`
- `POST /api/v1/jobs/{job_id}/cancel`
- `POST /api/v1/jobs/{job_id}/retry`
- `GET /api/v1/jobs`

A completed job returns `result.analysis_id` and `result.resource`.

## APK analyses

- `POST /api/v1/apk-analyses` — synchronous development route; may be disabled.
- `GET /api/v1/apk-analyses`
- `GET /api/v1/apk-analyses/{analysis_id}`
- `GET /api/v1/apk-analyses/{analysis_id}/report.pdf`
- `POST /api/v1/demo/apk-analysis`
- `POST /api/v1/method-review` — bounded deterministic review of supplied snippets, not decompilation.

Result schema `3.0` adds:

```json
{
  "engine_analysis": {
    "policy": {
      "public_binary_uploads": false,
      "external_hash_lookups": false,
      "unknown_is_safe": false
    },
    "engines": [],
    "normalized_findings": [],
    "reputation": {}
  },
  "malware_assessment": {
    "verdict": "INCONCLUSIVE",
    "known_malware": false,
    "legitimacy": "not-established",
    "safe_to_install": false
  }
}
```

## Indicators

- `GET /api/v1/indicators`
- `POST /api/v1/indicators`
- `GET /api/v1/indicators/{indicator_id}`

High/critical APK analyses can emit `apk_sha256`, domain, IP, certificate SHA-256 and package indicators. Indicators are analyst candidates, not autonomous blocking instructions.

## Audit

- `GET /api/v1/audit-events`
- `GET /api/v1/audit-events/{event_id}`
- `GET /api/v1/audit-events/verify`

## Demo

`POST /api/v1/demo/seed` with `{"category":"banking"}` creates only an explicit synthetic APK analysis. Demo routes are forbidden in the production profile.

## Errors

Errors use:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Safe message",
    "details": {},
    "request_id": "..."
  }
}
```

Removed v2 non-APK operations are absent from the v3 contract and return `404`/`405` rather than executing.
