"""
PRODUCTIZATION PASS 7 — Release Security & Supply-Chain Gates Tests
===================================================================
Tests to verify:
1. Workflow YAML integrity and parse correctness.
2. Backend CI includes pip-audit (SCA), CycloneDX SBOM generation, and Trivy scan.
3. Frontend CI includes npm audit (SCA), CycloneDX SBOM generation, and Trivy scan.
4. Security CI includes Gitleaks secret scanning and Semgrep SAST.
5. Gitleaks configuration (.gitleaks.toml) is well-formed.
6. RELEASE_GATES.md documents all automated gates, branch protection, and signing state.
"""
from __future__ import annotations

from pathlib import Path
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


# ---------------------------------------------------------------------------
# Test 1: Workflow YAML Files Parse Correctly
# ---------------------------------------------------------------------------
def test_workflow_yamls_parse_without_errors() -> None:
    """All GitHub Actions workflow files must be valid YAML."""
    assert WORKFLOWS_DIR.exists(), "Workflows directory must exist"
    workflow_files = list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
    assert len(workflow_files) >= 3, f"Expected at least 3 workflows, found: {len(workflow_files)}"

    for wf in workflow_files:
        content = wf.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict), f"Workflow {wf.name} did not parse into a dictionary"
        assert "name" in parsed, f"Workflow {wf.name} missing 'name' field"
        assert "jobs" in parsed, f"Workflow {wf.name} missing 'jobs' field"


# ---------------------------------------------------------------------------
# Test 2: Backend CI Includes SCA, SBOM, and Container Scanning
# ---------------------------------------------------------------------------
def test_backend_ci_includes_security_gates() -> None:
    """Backend CI must configure pip-audit, CycloneDX SBOM, and Trivy scanning."""
    backend_wf = WORKFLOWS_DIR / "backend-ci.yml"
    assert backend_wf.exists()
    content = backend_wf.read_text(encoding="utf-8")

    assert "pip-audit" in content, "Backend CI must include pip-audit for Python SCA"
    assert "cyclonedx" in content.lower(), "Backend CI must include CycloneDX SBOM generation"
    assert "fraudshield-backend-sbom" in content, "Backend CI must upload backend SBOM artifact"
    assert "trivy" in content.lower(), "Backend CI must include Trivy container scanning"


# ---------------------------------------------------------------------------
# Test 3: Frontend CI Includes SCA, SBOM, and Container Scanning
# ---------------------------------------------------------------------------
def test_frontend_ci_includes_security_gates() -> None:
    """Frontend CI must configure npm audit, CycloneDX SBOM, and Trivy scanning."""
    frontend_wf = WORKFLOWS_DIR / "frontend-ci.yml"
    assert frontend_wf.exists()
    content = frontend_wf.read_text(encoding="utf-8")

    assert "npm audit" in content, "Frontend CI must include explicit npm audit step"
    assert "--audit-level=high" in content, "Frontend CI must audit at high/critical threshold"
    assert "cyclonedx" in content.lower(), "Frontend CI must include CycloneDX SBOM generation"
    assert "fraudshield-frontend-sbom" in content, "Frontend CI must upload frontend SBOM artifact"
    assert "trivy" in content.lower(), "Frontend CI must include Trivy container scanning"


# ---------------------------------------------------------------------------
# Test 4: Security CI Includes Secret Scanning and SAST
# ---------------------------------------------------------------------------
def test_security_ci_includes_gitleaks_and_sast() -> None:
    """Security CI must configure Gitleaks for secrets and Semgrep for SAST."""
    security_wf = WORKFLOWS_DIR / "security-ci.yml"
    assert security_wf.exists()
    content = security_wf.read_text(encoding="utf-8")

    assert "gitleaks" in content.lower(), "Security CI must include Gitleaks secret scanner"
    assert "semgrep" in content.lower(), "Security CI must include Semgrep SAST analyzer"


# ---------------------------------------------------------------------------
# Test 5: Gitleaks Configuration Exists and is Valid
# ---------------------------------------------------------------------------
def test_gitleaks_config_exists_and_valid() -> None:
    """The repository must have a .gitleaks.toml configuration file."""
    gitleaks_config = REPO_ROOT / ".gitleaks.toml"
    assert gitleaks_config.exists(), ".gitleaks.toml must exist in repo root"
    content = gitleaks_config.read_text(encoding="utf-8")
    assert "allowlist" in content, ".gitleaks.toml must define allowlists for test fixtures"


# ---------------------------------------------------------------------------
# Test 6: RELEASE_GATES.md Documentation Integrity
# ---------------------------------------------------------------------------
def test_release_gates_documentation_integrity() -> None:
    """RELEASE_GATES.md must honestly document automated gates, signing, and branch protection."""
    doc_path = REPO_ROOT / "docs" / "RELEASE_GATES.md"
    assert doc_path.exists(), "docs/RELEASE_GATES.md must exist"
    doc_text = doc_path.read_text(encoding="utf-8")

    assert "Secret Scanning" in doc_text
    assert "pip-audit" in doc_text
    assert "npm audit" in doc_text
    assert "CycloneDX" in doc_text
    assert "Trivy" in doc_text
    assert "Semgrep" in doc_text
    assert "SIGNED_RELEASE = NOT CONFIGURED" in doc_text
    assert "Branch Protection" in doc_text
