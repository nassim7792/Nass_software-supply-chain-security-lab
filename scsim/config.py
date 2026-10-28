"""Shared configuration for every component of the simulator.

All network endpoints are pinned to loopback (127.0.0.1) on purpose: this lab
must never reach a real registry or the internet.
"""
from __future__ import annotations

import os
from pathlib import Path

# --- Repo paths -------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGES_DIR = REPO_ROOT / "packages"
DEMO_PKG_DIR = PACKAGES_DIR / "internal-auth-utils"
TARGET_APP_DIR = REPO_ROOT / "target-app"
MONITORING_DIR = REPO_ROOT / "monitoring"
DETECTION_DIR = REPO_ROOT / "detection"
DEFENSES_DIR = REPO_ROOT / "defenses"
REPORT_DIR = REPO_ROOT / "report"
STATE_DIR = REPO_ROOT / ".scsim_state"       # runtime artifacts (db, registry store, pids)

# --- Local private registry (simulates a company internal index) ------------
REGISTRY_HOST = "127.0.0.1"
REGISTRY_PORT = int(os.environ.get("SCSIM_REGISTRY_PORT", "8080"))
REGISTRY_URL = f"http://{REGISTRY_HOST}:{REGISTRY_PORT}"
REGISTRY_SIMPLE_URL = f"{REGISTRY_URL}/simple/"
REGISTRY_STORE = STATE_DIR / "registry_packages"   # where pypiserver keeps uploads

# --- Monitoring server (the "exfil" sink — on localhost) --------------------
MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = int(os.environ.get("SCSIM_MONITOR_PORT", "8888"))
MONITOR_URL = f"http://{MONITOR_HOST}:{MONITOR_PORT}"
MONITOR_COLLECT_PATH = "/collect"
MONITOR_COLLECT_URL = f"{MONITOR_URL}{MONITOR_COLLECT_PATH}"
MONITOR_DB = STATE_DIR / "captures.sqlite3"

# --- The demonstration package ----------------------------------------------
DEMO_PACKAGE_NAME = "internal-auth-utils"
DEMO_PACKAGE_IMPORT = "internal_auth_utils"
# High version so it wins resolution against any legitimate internal version.
DEMO_PACKAGE_VERSION = "99.0.0"
# What a plausible *legitimate* internal version would have been.
LEGIT_INTERNAL_VERSION = "1.4.2"

# Names that look like internal/private libraries. The policy scanner flags
# any dependency matching these prefixes that is allowed to resolve publicly.
INTERNAL_NAME_PREFIXES = ("internal-", "internal_", "corp-", "acme-", "acme_")

STATE_DIR.mkdir(exist_ok=True)
REGISTRY_STORE.mkdir(parents=True, exist_ok=True)
