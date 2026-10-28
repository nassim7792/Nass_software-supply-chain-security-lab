"""Shared pytest fixtures. Everything runs offline."""
from __future__ import annotations

import io
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def built_dist() -> Path:
    """Ensure an impostor artifact exists at packages/internal-auth-utils/dist/.

    Tries a real sdist build; if the build environment is offline, falls back to
    a fabricated tarball so hash/signing logic is still exercised deterministically.
    """
    pkg = REPO_ROOT / "packages" / "internal-auth-utils"
    dist = pkg / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    existing = sorted(dist.glob("*.tar.gz"))
    if existing:
        return existing[-1]

    try:
        subprocess.run([sys.executable, "-m", "build", "--sdist", str(pkg)],
                       check=True, capture_output=True)
        built = sorted(dist.glob("*.tar.gz"))
        if built:
            return built[-1]
    except Exception:
        pass

    # Fallback: fabricate a tarball with the impostor's contents.
    art = dist / "internal_auth_utils-99.0.0.tar.gz"
    with tarfile.open(art, "w:gz") as tf:
        data = b"# impostor internal-auth-utils 99.0.0 (test fixture)\n"
        info = tarfile.TarInfo("internal_auth_utils-99.0.0/setup.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return art


@pytest.fixture()
def fake_osv_transport():
    """A deterministic OSV transport: pretends jinja2 3.0.0 has a HIGH CVE and
    everything else is clean. Signature matches security.cve_scan.Transport."""
    def transport(name: str, version: str):
        if name == "jinja2" and version.startswith("3.0"):
            return [{
                "id": "GHSA-xxxx-test",
                "aliases": ["CVE-2024-TESTAAA"],
                "summary": "Test XSS in jinja2 (lab fixture).",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{"fixed": "3.1.0"}]}]}],
            }]
        return []
    return transport
