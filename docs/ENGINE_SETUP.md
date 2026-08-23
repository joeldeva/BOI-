# Optional analysis-engine setup

The core analyzer is functional with the normal installation. Optional engines increase coverage but also increase build complexity and analysis time. Always confirm the live capability endpoint after deployment.

## APKiD, YARA, Quark and fuzzy hashes

```bash
python -m pip install -e '.[analysis]'
```

Platform libraries may be required for YARA/ssdeep. Build and scan these dependencies in the target environment rather than copying a developer virtual environment.

Quark is disabled by default. Supply a reviewed offline rules directory and set:

```dotenv
FRAUDSHIELD_QUARK_ENABLED=true
FRAUDSHIELD_QUARK_RULES_DIR=/opt/fraudshield/quark-rules
FRAUDSHIELD_QUARK_MAX_RULES=300
```

The application never refreshes those rules over the network. Quark executes in
process and is capped by rule count; production workers must additionally enforce
pod/job CPU, memory and wall-time limits.

## Android signature verification

Install Android SDK Build Tools and make `apksigner` available to the worker, or set an explicit executable path:

```dotenv
FRAUDSHIELD_SIGNATURE_VERIFICATION_ENABLED=true
FRAUDSHIELD_APKSIGNER_PATH=/opt/android-sdk/build-tools/36.0.0/apksigner
```

## Private MobSF

MobSF receives APK bytes. Use only a bank-controlled instance approved for the data classification, with TLS and network policy:

```dotenv
FRAUDSHIELD_MOBSF_ENABLED=true
FRAUDSHIELD_MOBSF_URL=https://mobsf.internal.example
FRAUDSHIELD_MOBSF_API_KEY=from-secret-manager
FRAUDSHIELD_MOBSF_ALLOW_BINARY_TRANSFER=true
```

DeceptiScope attempts to delete the MobSF scan after collecting its bounded summary. Apply retention controls on the MobSF side as well.

## Hash-only reputation

```dotenv
FRAUDSHIELD_REPUTATION_ENABLED=true
FRAUDSHIELD_VIRUSTOTAL_API_KEY=from-secret-manager
FRAUDSHIELD_MALWAREBAZAAR_API_KEY=optional-auth-key
```

Only SHA-256 is transmitted. Production additionally requires `FRAUDSHIELD_ALLOW_EXTERNAL_REPUTATION_IN_PRODUCTION=true` after privacy/legal approval and egress allowlisting. DeceptiScope never uploads a binary to either public provider.

## Acceptance checks

1. `GET /api/v1/system/capabilities` reports each intended engine as enabled and available.
2. A synthetic demo is clearly labeled synthetic.
3. A controlled benign test APK produces no safe/legitimate claim.
4. A controlled malicious fixture produces deterministic evidence and a high-risk assessment.
5. Disable provider egress and verify the analysis still completes with a visible failed/unavailable engine status.
6. Confirm temporary APK and object artifacts follow the configured retention policy.
