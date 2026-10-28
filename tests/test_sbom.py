"""The SBOM must be a valid CycloneDX document that inventories the deps."""
import json
import shutil

import pytest

from security import sbom


def test_sbom_is_valid_cyclonedx():
    bom = sbom.build_sbom(resolve_env=True)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"].startswith("1.")
    assert bom["components"], "SBOM must have components"
    assert sbom.validate(bom) == []


def test_sbom_flags_internal_name():
    bom = sbom.build_sbom(resolve_env=False)
    internal = [c for c in bom["components"] if c["name"] == "internal-auth-utils"]
    assert internal, "internal-auth-utils must be in the SBOM"
    props = {p["name"] for p in internal[0].get("properties", [])}
    assert "scsim:internal-name" in props


def test_every_component_has_a_purl():
    bom = sbom.build_sbom(resolve_env=False)
    assert all(c.get("purl", "").startswith("pkg:pypi/") for c in bom["components"])


@pytest.mark.skipif(shutil.which("cyclonedx-py") is None,
                    reason="cyclonedx-py (cyclonedx-bom) not installed")
def test_real_sbom_has_transitive_components(tmp_path):
    """The production path (cyclonedx-py) yields a valid SBOM with transitive
    dependencies, consumable by the gate and CVE scanner."""
    out = sbom.generate_with_cyclonedx_py(tmp_path / "real.json", mode="environment")
    assert out is not None
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert len(bom["components"]) > 5          # transitive deps present
    assert sbom.validate(bom) == []
