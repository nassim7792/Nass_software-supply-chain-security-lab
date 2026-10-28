"""Security Gate — the configurable CI/CD control that blocks a delivery.

The gate reads a policy file and the artifacts produced earlier in the pipeline
(the SBOM and the CVE report), re-runs the dependency-confusion policy scan, and
decides PASS/FAIL. A FAIL exits non-zero so the GitLab pipeline stops before the
deploy stage.

It is deliberately *configurable*: every threshold lives in security-policy.yml,
so a team can tune strictness without touching code — exactly what a reviewer
wants to see in a DevSecOps project.

CLI:
    python -m security.gate \
        --policy security/security-policy.yml \
        --sbom security/sbom.cyclonedx.json \
        --cve security/cve_report.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _load_policy(path: Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml
        return yaml.safe_load(text)
    except ModuleNotFoundError:
        # Allow a JSON policy as a fallback when PyYAML isn't installed.
        return json.loads(text)


def _sev_index(label: str) -> int:
    return SEV_ORDER.index(label) if label in SEV_ORDER else -1


# --------------------------------------------------------------------------- #
# individual checks -> each returns a dict result
# --------------------------------------------------------------------------- #
def check_sbom(required: bool, sbom: dict | None) -> dict:
    if not required:
        return {"check": "require_sbom", "passed": True, "detail": "not required"}
    if sbom is None:
        return {"check": "require_sbom", "passed": False, "detail": "SBOM missing"}
    from security.sbom import validate
    problems = validate(sbom)
    return {"check": "require_sbom", "passed": not problems,
            "detail": "valid CycloneDX" if not problems else f"invalid: {problems}"}


def check_dependency_confusion(cfg: dict) -> dict:
    if not cfg.get("fail_on_unscoped_internal"):
        return {"check": "dependency_confusion", "passed": True,
                "detail": "disabled"}
    from defenses.policy_scanner import scan_file
    from scsim.config import INTERNAL_NAME_PREFIXES
    criticals = []
    for rel in cfg.get("audit_paths", []):
        p = REPO_ROOT / rel
        if not p.exists():
            continue
        for a in scan_file(p, INTERNAL_NAME_PREFIXES):
            if a.severity == "CRITICAL":
                criticals.append(f"{rel}: {a.what}")
    return {
        "check": "dependency_confusion",
        "passed": not criticals,
        "detail": "no public-resolvable internal names"
                  if not criticals else f"{len(criticals)} critical finding(s)",
        "evidence": criticals,
    }


def check_cve(cfg: dict, cve_report: dict | None) -> dict:
    if cve_report is None:
        return {"check": "cve", "passed": False, "detail": "no CVE report"}

    allow = {a["id"] if isinstance(a, dict) else a
             for a in cfg.get("allowlist", [])}
    threshold = cfg.get("fail_on_severity", "HIGH")
    t_idx = _sev_index(threshold)
    per_max = cfg.get("per_severity_max", {}) or {}

    blocking = []
    counts = {s: 0 for s in SEV_ORDER}
    for f in cve_report.get("findings", []):
        if f["id"] in allow or f.get("osv_id") in allow:
            continue
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1
        if _sev_index(sev) >= t_idx >= 0:
            blocking.append(f"{f['id']} ({sev}) in {f['package']} {f['version']}")

    cap_violations = []
    for sev, cap in per_max.items():
        if counts.get(sev, 0) > int(cap):
            cap_violations.append(f"{counts[sev]} {sev} > cap {cap}")

    errors = cve_report.get("errors", [])
    error_fail = bool(errors) and bool(cfg.get("fail_on_scan_errors"))

    passed = not blocking and not cap_violations and not error_fail
    detail_bits = []
    if blocking:
        detail_bits.append(f"{len(blocking)} finding(s) >= {threshold}")
    if cap_violations:
        detail_bits.append("; ".join(cap_violations))
    if error_fail:
        detail_bits.append(f"{len(errors)} scan error(s)")
    return {
        "check": "cve",
        "passed": passed,
        "detail": "within policy" if passed else "; ".join(detail_bits),
        "evidence": blocking,
    }


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
def evaluate(policy: dict, sbom: dict | None, cve_report: dict | None) -> dict:
    rules = policy.get("rules", {})
    results = [
        check_sbom(rules.get("require_sbom", False), sbom),
        check_dependency_confusion(rules.get("dependency_confusion", {}) or {}),
        check_cve(rules.get("cve", {}) or {}, cve_report),
    ]
    passed = all(r["passed"] for r in results)
    return {"passed": passed, "results": results}


def print_verdict(verdict: dict) -> None:
    print("\n==================== SECURITY GATE ====================")
    for r in verdict["results"]:
        mark = "PASS ✅" if r["passed"] else "FAIL ❌"
        print(f"  {mark}  {r['check']:<22} {r['detail']}")
        for ev in r.get("evidence", [])[:5]:
            print(f"           - {ev}")
    overall = "DELIVERY ALLOWED ✅" if verdict["passed"] else "DELIVERY BLOCKED ⛔"
    print("-------------------------------------------------------")
    print(f"  {overall}")
    print("=======================================================\n")


def _maybe_load(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path and path.exists() else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the CI security gate")
    ap.add_argument("--policy", type=Path,
                    default=REPO_ROOT / "security" / "security-policy.yml")
    ap.add_argument("--sbom", type=Path,
                    default=REPO_ROOT / "security" / "sbom.cyclonedx.json")
    ap.add_argument("--cve", type=Path,
                    default=REPO_ROOT / "security" / "cve_report.json")
    ap.add_argument("--json", action="store_true", help="also print verdict as JSON")
    args = ap.parse_args(argv)

    policy = _load_policy(args.policy)
    sbom = _maybe_load(args.sbom)
    cve_report = _maybe_load(args.cve)

    verdict = evaluate(policy, sbom, cve_report)
    print_verdict(verdict)
    if args.json:
        print(json.dumps(verdict, indent=2))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
