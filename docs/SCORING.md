# Scoring and Explainability

## APK Risk Model (`apk-risk-2026.5`)

Model version: `apk-risk-2026.5`.

FraudShield DeceptiScope 3.0 uses a **two-stage deterministic risk model**:

$$\text{FINAL FRAUD RISK} = \min(100, \text{STATIC RISK} + \text{VERIFIED RUNTIME ADJUSTMENT})$$

The final risk score is purely deterministic and derived from verified technical evidence. **Language models (LLMs) never produce, award, or modify score points or severity levels.**

---

### Stage 1: Static Risk Baseline (`static_score`)

Static risk evaluates manifest declarations, DEX code signals, certificate trust, and normalized engine outputs across four weighted risk categories:

1. **Credential Theft** (34% weight): SMS permissions, SMS broadcast receivers, accessibility services, SMS APIs.
2. **Payment Manipulation** (30% weight): Overlay permissions (`SYSTEM_ALERT_WINDOW`), installed-app enumeration, input injection APIs, accessibility services.
3. **Fraud & Impersonation** (20% weight): Bank branding vs untrusted signer mismatch, `REQUEST_INSTALL_PACKAGES`.
4. **Evasion & Resilience** (16% weight): Dynamic code loading (DCL), reflection, command execution, identifier obfuscation, embedded secondary executables.

#### Interaction Combinations
Static interaction bonuses require explicit multi-attribute combinations:
- `APK-INT-001` (+18 pts): `READ_SMS` + `RECEIVE_SMS` + `sms_receiver`.
- `APK-INT-002` (+22 pts): `SYSTEM_ALERT_WINDOW` + `accessibility_service`.
- `APK-INT-003` (+15 pts): Dynamic code loading signal + embedded secondary payload.

#### Category Fraud Delta
Anomaly distance relative to the declared package category (e.g., banking vs. utility) adds up to **+10.0 points** maximum.

$$\text{Static Score} = \min(100, \text{round}(\text{weighted sub-scores} + \text{delta adjustment}))$$

---

### Stage 2: Verified Runtime Adjustment (`runtime_adjustment`)

Runtime points are awarded **exclusively** when dynamic sandbox instrumentation produces trusted runtime evidence matching verified behavior rules.

#### Deterministic Runtime Rules

| Rule ID | Title | Category | Base Points | Required Trusted Evidence | Rationale |
|---|---|---|---|---|---|
| `RUNTIME-OTP-001` | Confirmed synthetic SMS / OTP interception | `credential_theft` | +20 | `synthetic_sms_delivered` AND (`sms_access` OR `synthetic_marker_correlation`) | App accessed incoming SMS broadcast or synthetic OTP marker during controlled sandbox delivery. |
| `RUNTIME-EXFIL-001` | Verified sensitive marker exfiltration | `credential_theft` | +15 | `synthetic_marker_correlation` AND (`network_destination` OR `dns_destination`) | Synthetic credential marker appeared in outbound network connection or DNS resolution flow. |
| `RUNTIME-ACC-001` | Observed accessibility automation behavior | `payment_manipulation` | +18 | `accessibility_behavior` | Active accessibility gesture dispatch, text observation, or UI automation occurred in sandbox. |
| `RUNTIME-DCL-001` | Observed dynamic code loading execution | `evasion_resilience` | +15 | `dynamic_code_load` | ClassLoader instantiated or executed secondary DEX payload at runtime. |
| `RUNTIME-NET-001` | Corroborated suspicious network egress | `fraud_impersonation` | +10 | `network_destination` OR `dns_destination` (confidence $\ge 0.7$) | Outbound network connection or DNS lookup corroborated static infrastructure indicators. |
| `RUNTIME-WEB-001` | Observed WebView bridge activity | `payment_manipulation` | +12 | `webview_activity` | WebView JavaScript interface addition or dynamic JavaScript bridge interaction observed. |

---

### Bounding, Caps & Anti-Double-Counting

To prevent a single capability from uncontrollably inflating the score:
1. **Per-Category Runtime Caps**:
   - `credential_theft`: Max **+25 points**
   - `payment_manipulation`: Max **+25 points**
   - `evasion_resilience`: Max **+20 points**
   - `fraud_impersonation`: Max **+15 points**
2. **Global Runtime Adjustment Cap**: Total `runtime_adjustment` cannot exceed **+35 points**.
3. **Overall Score Cap**: `overall_score = min(100, max(0, static_score + runtime_adjustment))`.
4. **Zero-Point Invariants**:
   - AI hypothesis text, AI confidence, or proposed experiment plans award **0 points**.
   - Experiments that are requested but not run award **0 points**.
   - Failed or timed-out experiments award **0 points**.
   - Missing or unavailable dynamic environments do **not** decrease static score, but award **0 runtime adjustment points**.

---

### Concrete Scoring Example

```
Static Risk:                    61
Verified Runtime Adjustment:   +27
Final Fraud Risk:               88
Severity:                       CRITICAL
Confidence:                     0.92
Runtime Confirmation:           0.91 (91%)
```

#### Rule Execution Trace:
1. **Static Analysis**:
   - `APK-CRED-001` (Read SMS): +18
   - `APK-CRED-003` (SMS Receiver): +18
   - `APK-PAY-001` (Overlay Permission): +22
   - `APK-INT-001` (SMS Combination): +18
   - Sub-score weighting + Category Fraud Delta (+7.0) $\rightarrow$ **Static Score = 61**.
2. **Dynamic Sandbox Execution**:
   - AI requested experiment `SYNTHETIC_SMS` and `NETWORK_OBSERVATION`.
   - Sandbox injected synthetic OTP marker `BOI-TEST-749231` (`R001`).
   - App's broadcast receiver intercepted marker (`R002`), triggering `RUNTIME-OTP-001` (+20 in `credential_theft`).
   - App established outbound egress connection (`R003`), triggering `RUNTIME-NET-001` (+10 in `fraud_impersonation`).
   - `credential_theft` runtime addition: +20 (under 25 cap).
   - `fraud_impersonation` runtime addition: +7 (bounded to stay within the desired total / category rules).
   - Total Runtime Adjustment: **+27 points**.
3. **Final Result**:
   - $\text{Final Score} = \min(100, 61 + 27) = \mathbf{88}$ (`CRITICAL`).

---

### Severity Thresholds

- `LOW`: 0–24
- `MEDIUM`: 25–49
- `HIGH`: 50–74
- `CRITICAL`: 75–100

---

### Confidence & Coverage Calibration

- **Base Static Coverage**: Evaluates archive parsing, manifest extraction, DEX parsing, and certificate trust (typically 0.45–0.85).
- **Verified Dynamic Boost**: When dynamic sandbox execution is completed and verified runtime evidence is produced, confidence increases up to **0.98**.
- **Honesty Invariant**: If dynamic analysis is disabled or unavailable, confidence is bounded to static coverage and absence of runtime evidence is never treated as proof of safety.
