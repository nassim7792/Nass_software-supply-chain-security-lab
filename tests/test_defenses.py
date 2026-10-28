"""Every defense must block the attack in its self-test."""
import pytest

from defenses import (lockfile_pinning, namespace_reservation, scoped_registry,
                      signing_verification, policy_scanner)


@pytest.mark.parametrize("mod", [scoped_registry, namespace_reservation,
                                 policy_scanner])
def test_config_defenses_block(mod):
    res = mod.test_against_attack()
    assert res["blocked"] is True, res


def test_lockfile_pinning_blocks(built_dist):
    res = lockfile_pinning.test_against_attack()
    assert res["blocked"] is True, res


def test_signing_verification_blocks(built_dist):
    res = signing_verification.test_against_attack()
    assert res["blocked"] is True, res


def test_policy_scanner_passes_safe_config(tmp_path):
    from scsim.config import INTERNAL_NAME_PREFIXES
    safe = scoped_registry.write_safe_pyproject(tmp_path / "pyproject.toml")
    alerts = policy_scanner.scan_file(safe, INTERNAL_NAME_PREFIXES)
    assert not any(a.severity == "CRITICAL" for a in alerts)
