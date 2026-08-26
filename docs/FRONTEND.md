# FraudShield DeceptiScope Frontend

The React/Vite frontend is an APK-only analyst workspace. It consumes the same-origin API by default and contains no service credentials.

## User Flow

1. The dashboard loads health, capabilities, summary and recent APK analyses.
2. The live engine matrix distinguishes ready, unavailable and policy-disabled engines.
3. Uploading an APK creates a durable job with a client-generated idempotency key.
4. The UI polls the job and follows the completed APK resource.
5. The result view presents malware assessment first, then deterministic score, engine execution, normalized evidence, Fraud Delta, MITRE mappings, indicators, extraction coverage, investigation state, runtime evidence, payload lineage, FraudDNA/campaign data, banking impact and narrative.
6. The PDF is downloaded from the analysis report endpoint.

The UI must never convert `LOW_RISK_OBSERVED`, not-found reputation, zero detections, partial coverage or missing engines into "safe", "clean" or "legitimate".

## Configuration

```dotenv
VITE_API_BASE_URL=
VITE_DEMO_ENABLED=true
VITE_MAX_APK_MB=75
```

An empty API base uses same-origin routing through the frontend proxy. Production identity/session behavior belongs in the bank access proxy or BFF, not browser environment variables.

## Verification

```bash
npm ci
npm test
npm run check
npm run build
```

The OpenAPI contract test verifies all consumed routes and confirms removed non-APK routes are absent.
