"""CVE scanning against an injected (offline) OSV transport."""
from security import cve_scan


def _bom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"}
                           for n, v in components]}


def test_scan_reports_high_finding(fake_osv_transport):
    bom = _bom([("jinja2", "3.0.0"), ("fastapi", "0.110.0")])
    report = cve_scan.scan(bom, transport=fake_osv_transport)
    assert report["finding_count"] == 1
    assert report["highest_severity"] == "HIGH"
    f = report["findings"][0]
    assert f["package"] == "jinja2"
    assert f["id"] == "CVE-2024-TESTAAA"      # CVE alias preferred over GHSA
    assert f["fixed_versions"] == ["3.1.0"]


def test_clean_components_have_no_findings(fake_osv_transport):
    bom = _bom([("jinja2", "3.1.5"), ("fastapi", "0.110.0")])
    report = cve_scan.scan(bom, transport=fake_osv_transport)
    assert report["finding_count"] == 0
    assert report["highest_severity"] == "NONE"


def test_offline_transport_records_errors_without_crashing():
    def broken(name, version):
        raise ConnectionError("offline")
    bom = _bom([("jinja2", "3.1.5")])
    report = cve_scan.scan(bom, transport=broken)
    assert report["finding_count"] == 0
    assert report["errors"] and "offline" in report["errors"][0]["error"]


def test_demo_sbom_has_known_vulnerable_versions():
    bom = cve_scan.demo_sbom()
    names = {c["name"] for c in bom["components"]}
    assert {"jinja2", "pyyaml", "requests"}.issubset(names)
    assert all(c.get("version") for c in bom["components"])  # all pinned


def test_demo_scan_with_fake_transport_flags_findings():
    def fake(n, v):
        if (n, v) == ("pyyaml", "5.3"):
            return [{"id": "GHSA-x", "aliases": ["CVE-2020-14343"],
                     "summary": "RCE", "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                     "affected": [{"ranges": [{"events": [{"fixed": "5.4"}]}]}]}]
        return []
    report = cve_scan.scan(cve_scan.demo_sbom(), transport=fake)
    assert report["highest_severity"] == "CRITICAL"
    assert any(f["id"] == "CVE-2020-14343" for f in report["findings"])


def test_severity_normalization_from_cvss():
    vuln = {"id": "X", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert cve_scan.normalize_severity(vuln) == "CRITICAL"
