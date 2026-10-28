"""CVE / vulnerability scanning of the SBOM.

Consumes a CycloneDX SBOM and looks up known vulnerabilities for each component
using the **OSV** database (https://osv.dev), the same data source Trivy,
Scorecard and Dependabot build on. A Trivy integration path is also provided for
teams that prefer the Trivy CLI.

The OSV lookup goes through an injectable `transport` so the scanner is testable
offline (the test suite passes a fake transport with canned vulnerabilities).
On the user's machine the default transport calls the live OSV API.

CLI:
    python -m security.cve_scan --sbom security/sbom.cyclonedx.json \
        -o security/cve_report.json
"""
from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

Transport = Callable[[str, str], list[dict]]  # (name, version) -> [vuln, ...]

# Deliberately OLD, known-vulnerable versions used only by `--demo` to show the
# scanner catching real CVEs via OSV. These are NOT installed and NOT used by
# the project; they are queried against OSV purely to demonstrate detection.
DEMO_COMPONENTS = [
    ("jinja2", "2.10"),      # CVE-2019-10906, CVE-2020-28493
    ("pyyaml", "5.3"),       # CVE-2020-14343 (arbitrary code execution)
    ("requests", "2.19.0"),  # CVE-2018-18074
    ("urllib3", "1.24"),     # CVE-2019-11324, CVE-2019-11236
    ("flask", "0.12.2"),     # CVE-2019-1010083, CVE-2018-1000656
]


# --------------------------------------------------------------------------- #
# severity helpers
# --------------------------------------------------------------------------- #
def _cvss_to_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


# CVSS v3.1 base-score metric weights.
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup to one decimal place."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def _cvss3_base(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string."""
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    try:
        av = _CVSS3_AV[parts["AV"]]; ac = _CVSS3_AC[parts["AC"]]
        ui = _CVSS3_UI[parts["UI"]]; scope = parts["S"]
        pr = (_CVSS3_PR_C if scope == "C" else _CVSS3_PR_U)[parts["PR"]]
        c = _CVSS3_CIA[parts["C"]]; integ = _CVSS3_CIA[parts["I"]]
        a = _CVSS3_CIA[parts["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - integ) * (1 - a))
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    base = min((1.08 if scope == "C" else 1.0) * (impact + expl), 10)
    return _roundup(base)


def _parse_cvss_vector_base(score) -> float | None:
    """Accept either a plain numeric score or a CVSS vector string."""
    if score is None:
        return None
    try:
        return float(score)            # some OSV entries store a number
    except (TypeError, ValueError):
        pass
    s = str(score)
    if s.startswith("CVSS:3"):
        return _cvss3_base(s)
    return None                        # CVSS v4 / unknown format -> not scored


def normalize_severity(vuln: dict) -> str:
    # 1) OSV database_specific severity label (most reliable when present).
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in SEVERITY_ORDER:
        return ds.upper()
    # 2) ecosystem_specific severity
    for aff in vuln.get("affected", []) or []:
        es = (aff.get("ecosystem_specific") or {}).get("severity")
        if isinstance(es, str) and es.upper() in SEVERITY_ORDER:
            return es.upper()
    # 3) CVSS vector/score under severity[]
    best = 0.0
    for sev in vuln.get("severity", []) or []:
        score = _parse_cvss_vector_base(sev.get("score"))
        if score is not None:
            best = max(best, score)
    if best:
        return _cvss_to_label(best)
    return "UNKNOWN"


def _primary_id(vuln: dict) -> str:
    """Prefer a CVE alias over the OSV id for readability."""
    for alias in vuln.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _looks_like_commit(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{7,40}", s))


def _fixed_versions(vuln: dict) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                v = ev.get("fixed")
                # Keep released versions; drop raw git commit hashes.
                if v and not _looks_like_commit(v):
                    fixed.append(v)
    return sorted(set(fixed))


# --------------------------------------------------------------------------- #
# transports
# --------------------------------------------------------------------------- #
def osv_transport(name: str, version: str, timeout: int = 15) -> list[dict]:
    """Default live transport: query OSV for one PyPI package@version."""
    body = json.dumps({
        "version": version,
        "package": {"ecosystem": "PyPI", "name": name},
    }).encode()
    req = urllib.request.Request(
        OSV_QUERY_URL, data=body,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        data = json.load(r)
    return data.get("vulns", []) or []


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def load_sbom(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def components_from_sbom(bom: dict) -> list[tuple[str, str]]:
    out = []
    for c in bom.get("components", []):
        name = c.get("name")
        version = c.get("version") or ""
        if name:
            out.append((name, version))
    return out


def demo_sbom() -> dict:
    """A synthetic SBOM of intentionally vulnerable versions, for `--demo`."""
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "cve-demo"}},
        "components": [
            {"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"}
            for n, v in DEMO_COMPONENTS
        ],
    }


def scan(bom: dict, transport: Transport | None = None) -> dict:
    """Scan every SBOM component. Never raises on network issues — records an
    error per component instead, so CI gets a report rather than a crash."""
    transport = transport or osv_transport
    findings: list[dict] = []
    errors: list[dict] = []

    for name, version in components_from_sbom(bom):
        if not version:
            errors.append({"package": name, "error": "no version in SBOM"})
            continue
        try:
            vulns = transport(name, version)
        except Exception as e:  # network/offline/etc.
            errors.append({"package": name, "error": f"{type(e).__name__}: {e}"})
            continue
        for v in vulns:
            findings.append({
                "package": name,
                "version": version,
                "id": _primary_id(v),
                "osv_id": v.get("id"),
                "severity": normalize_severity(v),
                "summary": (v.get("summary") or v.get("details", "")[:160] or "").strip(),
                "fixed_versions": _fixed_versions(v),
            })

    # Deduplicate: OSV returns multiple alias records (PYSEC/GHSA/CVE) for one
    # flaw. Collapse by (package, CVE id), keeping the highest severity and the
    # union of fixed versions.
    merged: dict[tuple[str, str], dict] = {}
    for f in findings:
        key = (f["package"], f["id"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = f
            continue
        if SEVERITY_ORDER.index(f["severity"]) > SEVERITY_ORDER.index(cur["severity"]):
            cur["severity"] = f["severity"]
        cur["fixed_versions"] = sorted(set(cur["fixed_versions"]) |
                                       set(f["fixed_versions"]))
        if not cur.get("summary") and f.get("summary"):
            cur["summary"] = f["summary"]
    findings = sorted(merged.values(),
                      key=lambda f: (-SEVERITY_ORDER.index(f["severity"]),
                                     f["package"], f["id"]))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    highest = "UNKNOWN"
    for sev in reversed(SEVERITY_ORDER):
        if counts.get(sev):
            highest = sev
            break

    return {
        "tool": "osv",
        "component_count": len(components_from_sbom(bom)),
        "finding_count": len(findings),
        "counts_by_severity": counts,
        "highest_severity": highest if findings else "NONE",
        "findings": findings,
        "errors": errors,
    }


def scan_with_trivy(sbom_path: Path) -> dict | None:
    """Alternative: let Trivy scan the CycloneDX SBOM. Requires the trivy CLI."""
    try:
        res = subprocess.run(
            ["trivy", "sbom", str(sbom_path), "--quiet", "--format", "json"],
            check=True, capture_output=True, text=True)
        return json.loads(res.stdout)
    except Exception:
        return None


def write_report(report: dict, path: Path | None = None) -> Path:
    path = path or (REPO_ROOT / "security" / "cve_report.json")
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def print_summary(report: dict) -> None:
    c = report["counts_by_severity"]
    print(f"CVE scan ({report['tool']}): {report['finding_count']} finding(s) "
          f"across {report['component_count']} component(s)")
    print(f"  CRITICAL={c.get('CRITICAL',0)} HIGH={c.get('HIGH',0)} "
          f"MEDIUM={c.get('MEDIUM',0)} LOW={c.get('LOW',0)} "
          f"UNKNOWN={c.get('UNKNOWN',0)}")
    for f in report["findings"]:
        fix = f" (fixed in {', '.join(f['fixed_versions'])})" if f["fixed_versions"] else ""
        print(f"  [{f['severity']:<8}] {f['package']} {f['version']}: "
              f"{f['id']}{fix}")
    if report["errors"]:
        print(f"  {len(report['errors'])} lookup error(s) "
              f"(offline?) — e.g. {report['errors'][0]['error']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan an SBOM for CVEs via OSV")
    ap.add_argument("--sbom", type=Path,
                    default=REPO_ROOT / "security" / "sbom.cyclonedx.json")
    ap.add_argument("-o", "--output", type=Path,
                    default=REPO_ROOT / "security" / "cve_report.json")
    ap.add_argument("--trivy", action="store_true", help="use Trivy instead of OSV")
    ap.add_argument("--demo", action="store_true",
                    help="scan a set of intentionally vulnerable versions to "
                         "demonstrate real CVE detection (does not use project deps)")
    args = ap.parse_args(argv)

    if args.demo:
        out = args.output.with_name("cve_report.demo.json")
        print("DEMO MODE: scanning intentionally OLD, vulnerable versions via OSV")
        print("(these are NOT installed and NOT used by the project)\n")
        report = scan(demo_sbom())
        write_report(report, out)
        print_summary(report)
        print(f"\nReport written to {out}")
        if report["errors"]:
            print("\nNote: lookups failed (no network to OSV?). On a connected "
                  "machine this prints real CVEs for the versions above.")
        return 0

    if not args.sbom.exists():
        print(f"SBOM not found: {args.sbom}. Run `python -m security.sbom` first.",
              file=sys.stderr)
        return 2

    if args.trivy:
        trivy = scan_with_trivy(args.sbom)
        if trivy is None:
            print("Trivy not available; falling back to OSV.", file=sys.stderr)
        else:
            args.output.write_text(json.dumps(trivy, indent=2), encoding="utf-8")
            print(f"Trivy report written to {args.output}")
            return 0

    report = scan(load_sbom(args.sbom))
    write_report(report, args.output)
    print_summary(report)
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
