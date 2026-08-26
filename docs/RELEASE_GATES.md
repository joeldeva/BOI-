# Production Release Gates & Supply-Chain Security

A release is not production-approved until every applicable gate has verified evidence, automated scan validation, and an authorized bank approver.

---

## 1. Automated Release & Security CI Gates

The following automated gates run on all pushes and pull requests to `main`:

| Gate | Tool / Engine | Automated Enforcement & Threshold | CI Artifact |
|---|---|---|---|
| **Secret Scanning** | Gitleaks (`gitleaks-action@v2`) | Fails build if any unallowlisted secret or credential pattern is detected in working tree or commit history. | CI check status |
| **Python SCA** | `pip-audit` (PyPA maintained) | Scans all direct and transitive dependencies against the OSV / PyPA advisory database. | `backend-audit.json` |
| **Frontend SCA** | `npm audit` | Fails build if any `HIGH` or `CRITICAL` vulnerability is detected in npm dependency tree. | CI check status |
| **Backend SBOM** | CycloneDX (`cyclonedx-py`) | Generates standard CycloneDX JSON SBOM covering all production and analysis packages. | `fraudshield-backend-sbom.cdx.json` |
| **Frontend SBOM** | CycloneDX (`@cyclonedx/cyclonedx-npm`) | Generates standard CycloneDX JSON SBOM covering all frontend runtime and UI packages. | `fraudshield-frontend-sbom.cdx.json` |
| **Container Security** | Trivy (`aquasecurity/trivy-action`) | Scans backend and frontend Docker images for OS and application vulnerabilities (`CRITICAL, HIGH`). | Scan table / SARIF |
| **Static Analysis (SAST)** | Semgrep (`semgrep:latest`) | Analyzes Python, TypeScript, and OWASP Top 10 security rules across the active codebase. | CI check status |
| **Artifact Provenance** | GitHub Attestations (`attest-build-provenance`) | Signs build artifact provenance with GitHub OIDC when workflow write permissions are active. | Attestation ledger |

---

## 2. Release Integrity & Verification Process

Every production deployment candidate must document and archive:

1. **Exact Commit SHA**: Immutable reference (`git rev-parse HEAD`).
2. **Container Image Digests**: Pin images by content digest (`sha256:...`), not mutable tags.
3. **CycloneDX SBOMs**: Stored in release artifacts for backend and frontend bundles.
4. **Scan Reports**: Zero unresolved high/critical CVEs without an explicit, time-bounded risk acceptance signed by the Bank CISO / SecOps.
5. **Deterministic Test Matrix**:
   - Backend unit, integration, API contract, and reverse engineering engine tests (100% passing).
   - Frontend contract tests, TypeScript type checking, `oxlint` linting, and Vite production bundle build.

---

## 3. Signing State & Policy

- **Current Repository State**: `SIGNED_RELEASE = NOT CONFIGURED`
- **Policy Invariant**: FraudShield does not fabricate or invent mock cryptographic release keys.
- **Production Recommendation**:
  - Sign release tags using authorized bank GPG keys (`git tag -s vX.Y.Z`).
  - Sign container images using **Cosign** (Sigstore) with the bank's keyless OIDC identity provider or dedicated HSM KMS key (`cosign sign --key <kms-uri> <image-digest>`).

---

## 4. Branch Protection & Governance

- **Target Branch**: `refs/heads/main`
- **Required Status Checks**:
  - `Backend CI` (`test-and-lint`, `container-and-chart`)
  - `Frontend CI` (`test-lint-build`, `container`)
  - `Security & Supply Chain CI` (`secret-scan`, `sast-analysis`)
- **Required Branch Rules**:
  - Prevent force pushes (`non_fast_forward: true`).
  - Prevent branch deletion (`deletion: true`).
  - Require pull request reviews prior to merging.

---

## 5. Formal Production Approval Checklist

- [ ] **Functional**: All unit, API, extraction, engine orchestration, and frontend contract tests pass.
- [ ] **Security Scans**: Gitleaks, pip-audit, npm audit, Trivy, and Semgrep clean.
- [ ] **Data Governance**: India data residency, credential masking, and immutable HMAC audit logs verified.
- [ ] **Identity & Access**: OIDC MFA, role mappings (`analyst`, `admin`, `auditor`), and BFF token proxy verified.
- [ ] **Platform Resilience**: Kubernetes NetworkPolicy, resource limits, HPA, health probes, and DR runbooks approved.
- [ ] **Fraud Model Governance**: Risk scoring formulas and banking evidence rules verified deterministic.
