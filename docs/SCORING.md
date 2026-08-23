# Scoring and Explainability

## APK risk

Model version: `apk-risk-2026.2`.

Four bounded sub-scores are computed from named rules:

- Credential theft: 34% of overall base score
- Payment manipulation: 30%
- Fraud impersonation: 20%
- Evasion/resilience: 16%

Fraud Delta can add at most 10 points. Every matched rule returns its ID, points, rationale, and concrete artifacts. Interaction bonuses require explicit combinations such as SMS permissions plus an SMS receiver, or overlay permission plus an accessibility service.

Severity thresholds:

- `LOW`: 0–24
- `MEDIUM`: 25–49
- `HIGH`: 50–74
- `CRITICAL`: 75–100

## Fraud Delta

Model version: `fraud-delta-2026.2`; baseline version: `2026.2-curated`.

It measures unexpected permissions/components/code signals relative to a declared category. It is deliberately labeled a heuristic distance—not a malware probability. The response exposes every weighted contribution.

## Change control

Do not change points just to make a chosen sample reach a desired score. Update rules only with a documented rationale, keep the model version immutable, add regression fixtures, and compare false-positive behavior across benign and malicious validation sets.
