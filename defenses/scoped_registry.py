"""Defense #3 — scoped registry configuration.

Instead of adding your private index as just another source in a flat list
(which lets the resolver pick the best version across ALL indexes), you bind
each internal package name to the private index *explicitly*, so it can only
ever resolve from there. Public PyPI is never consulted for internal names, so
an impostor on PyPI can't win regardless of version.

For uv this uses an `explicit = true` index plus `[tool.uv.sources]` pins. This
module generates that safe config and validates whether a given pyproject is
scoped correctly (the policy scanner reuses the same check).
"""
from __future__ import annotations

from pathlib import Path

try:  # py3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

SAFE_PYPROJECT = """\
# SAFE configuration — internal names are pinned to the private index only.
[project]
name = "target-app"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "fastapi>=0.110",
    "uvicorn[standard]>=0.29",
    "internal-auth-utils",
]

# PyPI stays the default for public packages...
[[tool.uv.index]]
name = "pypi"
url = "https://pypi.org/simple/"
default = true

# ...but the private index is marked `explicit`: nothing resolves from it
# unless a source pin points at it by name.
[[tool.uv.index]]
name = "internal"
url = "http://127.0.0.1:8080/simple/"
explicit = true

# Bind the internal name to the internal index ONLY. PyPI is never queried for
# internal-auth-utils, so a public impostor cannot be selected.
[tool.uv.sources]
internal-auth-utils = { index = "internal" }
"""


def write_safe_pyproject(dest: Path) -> Path:
    dest.write_text(SAFE_PYPROJECT, encoding="utf-8")
    return dest


def validate_pyproject(path: Path, internal_prefixes: tuple[str, ...]) -> dict:
    """Check whether internal-looking deps are scoped to an explicit index.

    Returns {name: {"scoped": bool, "bound_index": str|None}} for each internal
    dependency found.
    """
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    sources = data.get("tool", {}).get("uv", {}).get("sources", {})
    indexes = {i.get("name"): i for i in
               data.get("tool", {}).get("uv", {}).get("index", [])}

    def dep_name(spec: str) -> str:
        for sep in ("==", ">=", "<=", "~=", ">", "<", "[", " "):
            spec = spec.split(sep)[0]
        return spec.strip().lower()

    results = {}
    for spec in deps:
        name = dep_name(spec)
        if not name.startswith(internal_prefixes):
            continue
        src = sources.get(name) or sources.get(name.replace("_", "-"))
        bound = src.get("index") if isinstance(src, dict) else None
        explicit = bool(bound and indexes.get(bound, {}).get("explicit"))
        results[name] = {"scoped": explicit, "bound_index": bound}
    return results


def test_against_attack() -> dict:
    from scsim.config import INTERNAL_NAME_PREFIXES, STATE_DIR
    safe = write_safe_pyproject(STATE_DIR / "pyproject.safe.toml")
    res = validate_pyproject(safe, INTERNAL_NAME_PREFIXES)
    all_scoped = bool(res) and all(v["scoped"] for v in res.values())
    return {
        "defense": "scoped_registry",
        "blocked": all_scoped,
        "stage_prevented": "resolution",
        "detail": ("Internal names bound to an explicit private index; PyPI never "
                   "consulted for them." if all_scoped
                   else "Internal names are not scoped to a private index."),
        "evidence": res,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(test_against_attack(), indent=2))
