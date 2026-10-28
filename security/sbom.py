"""SBOM generation in CycloneDX 1.5 (JSON).

A Software Bill of Materials inventories every component the project ships or
builds against. It is the foundation of the rest of the DevSecOps chain: the CVE
scanner consumes the SBOM, and the security gate makes decisions from it.

This module builds a valid CycloneDX 1.5 BOM from the project's declared
dependencies, resolving concrete installed versions from the environment when
available. In a real pipeline you would usually generate the SBOM with the
`cyclonedx-py` tool; we re-implement a minimal, dependency-free generator so the
lab is self-contained, and we also expose `generate_with_cyclonedx_py()` to
delegate to that tool when it is installed.

CLI:
    python -m security.sbom                 # writes security/sbom.cyclonedx.json
    python -m security.sbom --stdout        # print to stdout
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_VERSION = "1.5"

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+")


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _dep_name(spec: str) -> str:
    m = _NAME_RE.match(spec.strip())
    return _norm(m.group(0)) if m else _norm(spec)


def _installed_version(name: str) -> str | None:
    try:
        from importlib import metadata as importlib_metadata
        return importlib_metadata.version(name)
    except Exception:
        return None


def _declared_dependencies() -> dict[str, str | None]:
    """Collect dependency names from requirements.txt + target-app pyproject +
    the demo package. Values are a pinned version if the spec pins one, else
    None (to be resolved from the environment)."""
    deps: dict[str, str | None] = {}

    req = REPO_ROOT / "requirements.txt"
    if req.exists():
        for line in req.read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            name = _dep_name(line)
            m = re.search(r"==\s*([0-9][^;\s]*)", line)
            deps.setdefault(name, m.group(1) if m else None)

    pp = REPO_ROOT / "target-app" / "pyproject.toml"
    if pp.exists():
        data = tomllib.loads(pp.read_text(encoding="utf-8"))
        for spec in data.get("project", {}).get("dependencies", []):
            name = _dep_name(spec)
            m = re.search(r"==\s*([0-9][^;\s]*)", spec)
            deps.setdefault(name, m.group(1) if m else None)

    # The internal library the app depends on (the impostor in the lab).
    deps.setdefault("internal-auth-utils", "99.0.0")
    return deps


def _component(name: str, version: str) -> dict:
    purl = f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
    comp = {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version or "",
        "purl": purl,
    }
    # Flag the internal name so downstream tooling (and reviewers) can see it.
    if name.startswith(("internal-", "corp-", "acme-")):
        comp["properties"] = [
            {"name": "scsim:internal-name", "value": "true"},
            {"name": "scsim:note",
             "value": "Internal-looking name; must resolve from a private index only."},
        ]
    return comp


def build_sbom(resolve_env: bool = True) -> dict:
    """Return a CycloneDX 1.5 BOM as a dict."""
    deps = _declared_dependencies()
    components = []
    for name in sorted(deps):
        version = deps[name]
        if resolve_env:
            version = _installed_version(name) or version or ""
        components.append(_component(name, version or ""))

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{
                "vendor": "Nass",
                "name": "scsim-sbom",
                "version": "1.0.0",
            }],
            "component": {
                "type": "application",
                "bom-ref": "pkg:pypi/target-app@0.1.0",
                "name": "target-app",
                "version": "0.1.0",
                "description": "Vulnerable FastAPI app (dependency-confusion lab)",
            },
        },
        "components": components,
    }


def write_sbom(path: Path | None = None, resolve_env: bool = True) -> Path:
    path = path or (REPO_ROOT / "security" / "sbom.cyclonedx.json")
    bom = build_sbom(resolve_env=resolve_env)
    path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return path


def generate_with_cyclonedx_py(path: Path | None = None, mode: str = "environment",
                               requirements: Path | None = None,
                               spec: str = SPEC_VERSION) -> Path | None:
    """Delegate to the real `cyclonedx-py` tool (production path).

    mode="environment": full SBOM of the installed env, including TRANSITIVE
        dependencies and the dependency graph (no artifact hashes).
    mode="requirements": build from a requirements file; if that file is
        hash-pinned (pip --hash / `uv pip compile --generate-hashes`), the SBOM
        carries artifact hashes too — full provenance.

    Returns the output path, or None if the tool is missing / failed (so the
    caller can fall back to the built-in generator).
    """
    path = path or (REPO_ROOT / "security" / "sbom.cyclonedx.json")
    # Invoke as a module (`python -m cyclonedx_py`) rather than by the
    # `cyclonedx-py` script name: it works regardless of whether the Scripts
    # directory is on PATH (common gotcha on Windows).
    cmd = [sys.executable, "-m", "cyclonedx_py", mode,
           "--of", "JSON", "--sv", spec, "-o", str(path)]
    if mode == "environment":
        cmd.append(sys.executable)                 # which interpreter to inspect
    elif mode == "requirements":
        if requirements is None:
            return None
        cmd.append(str(requirements))
    try:
        subprocess.run(cmd, check=True, cwd=str(REPO_ROOT),
                       capture_output=True, text=True)
        return path
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def validate(bom: dict) -> list[str]:
    """Lightweight structural validation. Returns a list of problems (empty=ok)."""
    problems = []
    if bom.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be 'CycloneDX'")
    if not str(bom.get("specVersion", "")).startswith("1."):
        problems.append("specVersion missing/invalid")
    if not isinstance(bom.get("components"), list) or not bom["components"]:
        problems.append("components must be a non-empty list")
    for c in bom.get("components", []):
        if not c.get("name") or "purl" not in c:
            problems.append(f"component missing name/purl: {c}")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a CycloneDX SBOM")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing a file")
    ap.add_argument("--no-env", action="store_true", help="don't resolve installed versions")
    ap.add_argument("--real", action="store_true",
                    help="use the real cyclonedx-py tool for a full SBOM "
                         "(transitive dependencies + dependency graph)")
    ap.add_argument("--requirements", type=Path, default=None,
                    help="with --real: build from a (hash-pinned) requirements "
                         "file so artifact hashes are included")
    ap.add_argument("-o", "--output", type=Path, default=None)
    args = ap.parse_args(argv)

    if args.real:
        mode = "requirements" if args.requirements else "environment"
        out = generate_with_cyclonedx_py(args.output, mode=mode,
                                         requirements=args.requirements)
        if out is not None:
            bom = json.loads(out.read_text(encoding="utf-8"))
            n = len(bom.get("components", []))
            hashed = sum(1 for c in bom.get("components", []) if c.get("hashes"))
            print(f"Real SBOM written to {out} "
                  f"({n} components [transitive], {hashed} with hashes, mode={mode})")
            return 0
        print("cyclonedx-py not available or failed. Install it with:\n"
              "  pip install cyclonedx-bom\n"
              "Falling back to the built-in (direct-deps) generator.",
              file=sys.stderr)

    bom = build_sbom(resolve_env=not args.no_env)
    problems = validate(bom)
    if args.stdout:
        print(json.dumps(bom, indent=2))
    else:
        out = write_sbom(args.output, resolve_env=not args.no_env)
        print(f"SBOM written to {out} ({len(bom['components'])} components)")
    if problems:
        print("SBOM validation problems:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
