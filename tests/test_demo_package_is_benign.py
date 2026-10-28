"""The demonstration payload must stay benign: non-sensitive fields only, a
loopback sink, and no reading of secrets. These tests are a guardrail so the
teaching tool can never drift into real malware."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "packages" / "internal-auth-utils"
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

from internal_auth_utils import _telemetry  # noqa: E402

ALLOWED_KEYS = {
    "stage", "package", "package_version", "hostname", "username",
    "python_version", "platform", "cwd", "installed_packages_sample",
    "collected_at", "lab",
}


def test_payload_only_contains_non_sensitive_fields():
    payload = _telemetry._non_sensitive_metadata("test")
    assert set(payload).issubset(ALLOWED_KEYS), set(payload) - ALLOWED_KEYS
    assert payload["lab"] is True


def test_monitor_sink_is_loopback_only():
    assert _telemetry._MONITOR_URL.startswith(("http://127.0.0.1", "http://localhost"))


def test_source_does_not_read_secrets():
    """Reading an env var for the (loopback) sink URL is fine; reading secret
    files or credential paths is not. Uses word boundaries so that, e.g.,
    `os.environ` does not count as a reference to a `.env` file."""
    import re
    src = (PKG_DIR / "internal_auth_utils" / "_telemetry.py").read_text()
    forbidden = [
        r"\.env\b(?!iron)",   # a .env file, not os.environ
        r"id_rsa", r"\.ssh\b", r"\.aws\b", r"/etc/passwd",
        r"credentials", r"\bopen\s*\(",
    ]
    for pat in forbidden:
        assert not re.search(pat, src), f"payload must not reference {pat!r}"


def test_installed_sample_is_names_only():
    names = _telemetry._short_installed_list(limit=5)
    assert isinstance(names, list)
    assert all(isinstance(n, str) for n in names)
