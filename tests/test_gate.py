"""The security gate must block delivery exactly when policy says so."""
from security import gate
from security.sbom import build_sbom


def _valid_sbom():
    return build_sbom(resolve_env=False)


def _report(findings):
    return {"findings": findings, "errors": [],
            "counts_by_severity": {}, "highest_severity": "NONE"}


BASE_POLICY = {
    "rules": {
        "require_sbom": True,
        "dependency_confusion": {"fail_on_unscoped_internal": False},
        "cve": {"fail_on_severity": "HIGH",
                "per_severity_max": {"CRITICAL": 0, "HIGH": 0}},
    }
}


def test_gate_passes_when_clean():
    verdict = gate.evaluate(BASE_POLICY, _valid_sbom(), _report([]))
    assert verdict["passed"] is True


def test_gate_blocks_on_high_cve():
    finding = {"id": "CVE-1", "osv_id": "OSV-1", "severity": "HIGH",
               "package": "jinja2", "version": "3.0.0", "fixed_versions": []}
    verdict = gate.evaluate(BASE_POLICY, _valid_sbom(), _report([finding]))
    assert verdict["passed"] is False
    cve = next(r for r in verdict["results"] if r["check"] == "cve")
    assert cve["passed"] is False


def test_gate_respects_cve_allowlist():
    policy = {"rules": dict(BASE_POLICY["rules"],
                            cve={"fail_on_severity": "HIGH",
                                 "allowlist": [{"id": "CVE-1", "reason": "n/a"}]})}
    finding = {"id": "CVE-1", "osv_id": "OSV-1", "severity": "HIGH",
               "package": "jinja2", "version": "3.0.0", "fixed_versions": []}
    verdict = gate.evaluate(policy, _valid_sbom(), _report([finding]))
    assert verdict["passed"] is True


def test_gate_blocks_on_dependency_confusion():
    policy = {"rules": {
        "require_sbom": True,
        "dependency_confusion": {
            "fail_on_unscoped_internal": True,
            "audit_paths": ["target-app/pyproject.toml"],
        },
        "cve": {"fail_on_severity": "HIGH"},
    }}
    verdict = gate.evaluate(policy, _valid_sbom(), _report([]))
    assert verdict["passed"] is False
    dc = next(r for r in verdict["results"] if r["check"] == "dependency_confusion")
    assert dc["passed"] is False


def test_gate_fails_without_sbom():
    verdict = gate.evaluate(BASE_POLICY, None, _report([]))
    assert verdict["passed"] is False
