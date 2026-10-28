"""Defense #5 — policy-as-code scanner.

A CI gate that reads pyproject.toml / requirements files and fails the build
when an internal-looking package name could resolve from a public registry.
It catches the vulnerable configuration *before* anyone runs an install.

Findings it raises:
  * internal-named dependency not bound to an explicit private index;
  * public PyPI configured as a fallback while internal names are unscoped;
  * dangerous `index-strategy = "unsafe-best-match"`.

Usage:  python -m defenses.policy_scanner path/to/pyproject.toml
Exit code is non-zero if any CRITICAL finding is present (CI-friendly).
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from detection.alerts import Alert, print_alert
from defenses.scoped_registry import validate_pyproject

PUBLIC_INDEXES = ("pypi.org", "pythonhosted.org", "files.pythonhosted.org")


def scan_file(path: Path, internal_prefixes: tuple[str, ...]) -> list[Alert]:
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    uv = data.get("tool", {}).get("uv", {})
    alerts: list[Alert] = []

    # 1) internal names not scoped to an explicit private index
    scoped = validate_pyproject(path, internal_prefixes)
    for name, info in scoped.items():
        if not info["scoped"]:
            alerts.append(Alert(
                detector="policy_scanner", severity="CRITICAL",
                what=f"Internal-looking dependency '{name}' is not pinned to a "
                     f"private index in {path.name}.",
                why="It can resolve from any configured index, including public "
                    "PyPI — a dependency-confusion opening.",
                recommendation="Add [tool.uv.sources] "
                               f"{name} = {{ index = \"internal\" }} with an "
                               "explicit=true index, or use pip index pinning.",
                evidence={"bound_index": info["bound_index"]},
            ))

    # 2) public PyPI as an extra index while internal names exist
    extra = uv.get("extra-index-url", [])
    extra = [extra] if isinstance(extra, str) else extra
    all_index_urls = extra + [uv.get("index-url", "")] + \
        [i.get("url", "") for i in uv.get("index", [])]
    has_public = any(any(p in u for p in PUBLIC_INDEXES) for u in all_index_urls)
    if scoped and has_public and any(not v["scoped"] for v in scoped.values()):
        alerts.append(Alert(
            detector="policy_scanner", severity="WARN",
            what="Public PyPI is a configured fallback while internal names are "
                 "unscoped.",
            why="Widens the trust boundary for internal names to the entire "
                "public namespace.",
            recommendation="Mark the public index non-default or scope internal "
                           "names explicitly.",
            evidence={"indexes": [u for u in all_index_urls if u]},
        ))

    # 3) unsafe-best-match strategy
    if uv.get("index-strategy") == "unsafe-best-match":
        alerts.append(Alert(
            detector="policy_scanner", severity="CRITICAL",
            what="index-strategy = \"unsafe-best-match\" is set.",
            why="The resolver merges all indexes and picks the highest version, "
                "so a higher-versioned impostor on any index wins.",
            recommendation="Remove it (uv defaults to the safer 'first-index').",
            evidence={"index_strategy": "unsafe-best-match"},
        ))

    if not alerts:
        alerts.append(Alert(
            detector="policy_scanner", severity="INFO",
            what=f"{path.name} passes supply-chain policy.",
            why="No internal name can resolve from a public index.",
            recommendation="None.",
        ))
    return alerts


def scan_tree(root: Path, internal_prefixes: tuple[str, ...]) -> list[Alert]:
    alerts: list[Alert] = []
    for pp in Path(root).rglob("pyproject.toml"):
        if ".scsim_state" in str(pp):
            continue
        alerts += scan_file(pp, internal_prefixes)
    return alerts


def test_against_attack() -> dict:
    from scsim.config import TARGET_APP_DIR, INTERNAL_NAME_PREFIXES
    alerts = scan_file(TARGET_APP_DIR / "pyproject.toml", INTERNAL_NAME_PREFIXES)
    caught = any(a.severity == "CRITICAL" for a in alerts)
    return {
        "defense": "policy_scanner",
        "blocked": caught,
        "stage_prevented": "pre-commit / CI (config review)",
        "detail": "Flagged the vulnerable target-app config before any install."
                  if caught else "Config passed policy (unexpected).",
        "findings": [a.to_dict() for a in alerts],
    }


def scan(path: Path | None = None) -> list[Alert]:
    from scsim.config import TARGET_APP_DIR, INTERNAL_NAME_PREFIXES
    target = path or (TARGET_APP_DIR / "pyproject.toml")
    alerts = (scan_tree(target, INTERNAL_NAME_PREFIXES) if target.is_dir()
              else scan_file(target, INTERNAL_NAME_PREFIXES))
    for a in alerts:
        print_alert(a)
    return alerts


if __name__ == "__main__":
    arg = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    results = scan(arg)
    sys.exit(1 if any(a.severity == "CRITICAL" for a in results) else 0)
