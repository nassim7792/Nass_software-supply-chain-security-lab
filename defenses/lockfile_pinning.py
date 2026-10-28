"""Defense #1 — lockfile pinning with hash verification.

A lockfile records the exact version AND artifact hash of every dependency.
Installing with hash enforcement (`uv sync` against a committed `uv.lock`, or
`pip install --require-hashes -r requirements.txt`) means the resolver must
install those exact bytes or fail. A confusion package cannot win, because its
version/hash is not what the lockfile pins.

This module:
  * explains/generates the pin for the legitimate internal library,
  * `test_against_attack()` proves the impostor is rejected.
"""
from __future__ import annotations

import json
from pathlib import Path

from detection.hash_check import check_artifact


def lockfile_path() -> Path:
    from scsim.config import DEFENSES_DIR
    return DEFENSES_DIR / "known_good.lock.json"


def show_pin(name: str = "internal-auth-utils") -> dict:
    data = json.loads(lockfile_path().read_text(encoding="utf-8"))
    return data["packages"].get(name, {})


def example_requirements_with_hashes() -> str:
    """Show the pip form of a hash-pinned requirement."""
    pin = show_pin()
    return (
        "# requirements.txt — install with: pip install --require-hashes -r requirements.txt\n"
        f"internal-auth-utils=={pin.get('version','1.4.2')} \\\n"
        f"    --hash=sha256:{pin.get('sha256','...')}\n"
    )


def test_against_attack() -> dict:
    """Run the hash check against the built impostor and report whether the
    defense blocked it. Returns a structured result for the report matrix."""
    from scsim.config import (DEMO_PKG_DIR, DEMO_PACKAGE_NAME,
                              DEMO_PACKAGE_VERSION)
    dist = sorted((DEMO_PKG_DIR / "dist").glob("*.tar.gz"))
    if not dist:
        return {"defense": "lockfile_pinning", "blocked": None,
                "detail": "No built artifact; run publish first."}
    alerts = check_artifact(dist[-1], DEMO_PACKAGE_NAME, DEMO_PACKAGE_VERSION,
                            lockfile_path())
    blocked = any(a.severity == "CRITICAL" for a in alerts)
    return {
        "defense": "lockfile_pinning",
        "blocked": blocked,
        "stage_prevented": "resolution/install",
        "detail": "Version+hash mismatch against pinned 1.4.2 → install refused."
                  if blocked else "Impostor matched the pin (unexpected).",
    }


if __name__ == "__main__":
    print(example_requirements_with_hashes())
    print(json.dumps(test_against_attack(), indent=2))
