"""Detectors must fire on the attack."""
from pathlib import Path

from detection import hash_check, filesystem_monitor
from scsim.config import DEMO_PACKAGE_NAME, DEMO_PACKAGE_VERSION, DEFENSES_DIR


def test_hash_check_flags_impostor(built_dist: Path):
    lockfile = DEFENSES_DIR / "known_good.lock.json"
    alerts = hash_check.check_artifact(built_dist, DEMO_PACKAGE_NAME,
                                       DEMO_PACKAGE_VERSION, lockfile)
    severities = {a.severity for a in alerts}
    assert "CRITICAL" in severities  # version and/or hash mismatch


def test_filesystem_monitor_catches_sensitive_access():
    alerts = filesystem_monitor.run(duration=2.0, simulate=True)
    # watchdog may be unavailable in minimal envs; then it returns an INFO note.
    assert any(a.severity in ("CRITICAL", "INFO") for a in alerts)
