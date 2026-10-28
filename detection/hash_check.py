"""Detector #1 — hash / lockfile verification (pre-install).

Idea: a trustworthy build pins every dependency to an exact version AND an
exact artifact hash in a lockfile. Before installing, we recompute the hash of
the artifact the resolver actually chose and compare it to the known-good
lockfile. Dependency confusion changes *which* artifact is chosen, so either:

  * the chosen version is not in the lockfile at all (99.0.0 vs pinned 1.4.2), or
  * the chosen artifact's hash does not match the pinned hash.

Either condition is a hard stop. This is the single most effective detector,
because it does not rely on observing behavior — it refuses the swap outright.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from detection.alerts import Alert, print_alert


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lockfile(lockfile: Path) -> dict:
    with open(lockfile) as f:
        return json.load(f)


def check_artifact(artifact: Path, name: str, version: str, lockfile: Path) -> list[Alert]:
    """Compare a resolved artifact against the known-good lockfile."""
    alerts: list[Alert] = []
    lock = load_lockfile(lockfile)
    pinned = lock.get("packages", {}).get(name)
    actual_hash = sha256_file(artifact)

    if pinned is None:
        alerts.append(Alert(
            detector="hash_check",
            severity="WARN",
            what=f"'{name}' is being installed but is not pinned in the lockfile.",
            why="Unpinned dependencies can be silently swapped for a higher "
                "version from any trusted index — the core of dependency confusion.",
            recommendation="Pin every dependency with a hash (uv lock / "
                           "pip-compile --generate-hashes) and install with "
                           "--require-hashes.",
            evidence={"artifact": artifact.name, "version": version,
                      "sha256": actual_hash},
        ))
        return alerts

    if pinned["version"] != version:
        alerts.append(Alert(
            detector="hash_check",
            severity="CRITICAL",
            what=f"Version mismatch for '{name}': resolver chose {version}, "
                 f"lockfile pins {pinned['version']}.",
            why="A dependency jumped to an unexpected (higher) version. This is "
                "exactly how a confusion package wins resolution.",
            recommendation="Reject this install. Investigate why a newer version "
                           "appeared and on which index.",
            evidence={"resolved_version": version,
                      "pinned_version": pinned["version"]},
        ))

    if actual_hash != pinned["sha256"]:
        alerts.append(Alert(
            detector="hash_check",
            severity="CRITICAL",
            what=f"Hash mismatch for '{name}' {version}.",
            why="The artifact's content does not match the known-good hash. The "
                "bytes being installed are not the bytes you trusted.",
            recommendation="Reject this install. The lockfile prevented a "
                           "supply-chain swap — do not override the hash check.",
            evidence={"expected_sha256": pinned["sha256"],
                      "actual_sha256": actual_hash},
        ))

    if not alerts:
        alerts.append(Alert(
            detector="hash_check",
            severity="INFO",
            what=f"'{name}' {version} matches the lockfile hash.",
            why="Version and content both match the pin.",
            recommendation="Safe to install.",
            evidence={"sha256": actual_hash},
        ))
    return alerts


def scan(artifact: Path | None = None) -> list[Alert]:
    """Convenience entry point used by the runner.

    Finds the built impostor sdist and checks it against the lockfile that pins
    the legitimate internal version.
    """
    from scsim.config import DEMO_PKG_DIR, DEMO_PACKAGE_NAME, DEMO_PACKAGE_VERSION
    from scsim.config import DEFENSES_DIR

    lockfile = DEFENSES_DIR / "known_good.lock.json"
    if artifact is None:
        dist = sorted((DEMO_PKG_DIR / "dist").glob("*.tar.gz"))
        if not dist:
            return [Alert(
                detector="hash_check", severity="WARN",
                what="No built artifact found to check.",
                why="Build the demo package first (scsim publish).",
                recommendation="Run `python -m scsim.runner publish`.",
            )]
        artifact = dist[-1]

    alerts = check_artifact(artifact, DEMO_PACKAGE_NAME, DEMO_PACKAGE_VERSION, lockfile)
    for a in alerts:
        print_alert(a)
    return alerts


if __name__ == "__main__":
    scan()
