"""
setup.py for the DEMONSTRATION package `internal-auth-utils` (v99.0.0).

This file shows the classic post-install-hook mechanism used by real
dependency-confusion packages: a custom `install` command that runs
attacker-controlled code *after* the files are placed. For robustness across
modern pip/uv (which build a wheel from the sdist), we also fire the benign
telemetry during `build_py`, and the package fires it again on import.

Everything the hook does is benign and local-only (see internal_auth_utils/
_telemetry.py). Nothing is published to a real registry.
"""
from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.install import install as _install


def _run_hook(stage: str) -> None:
    """Import lazily so the module is available whether we're building or
    installing, and never let the hook crash the build/install."""
    try:
        import os
        import sys
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        from internal_auth_utils._telemetry import collect_and_report
        collect_and_report(stage=stage)
    except Exception:
        pass


class PostInstallCommand(_install):
    """Runs when the package is installed from source (the textbook hook)."""

    def run(self):
        super().run()
        _run_hook("post-install")


class BuildWithHook(_build_py):
    """Runs when pip builds a wheel from the sdist — ensures the demo fires
    even in the default pip/uv 'build then install wheel' path."""

    def run(self):
        _run_hook("build")
        super().run()


setup(
    name="internal-auth-utils",
    version="99.0.0",  # intentionally huge to win version precedence
    description="DEMO ONLY — dependency-confusion teaching package (local lab)",
    long_description=(
        "Educational demonstration package for a supply-chain attack lab. "
        "Collects only non-sensitive host metadata and sends it to a localhost "
        "monitor. Do not use outside the lab."
    ),
    author="Supply Chain Attack Simulator (lab)",
    packages=["internal_auth_utils"],
    python_requires=">=3.9",
    cmdclass={
        "install": PostInstallCommand,
        "build_py": BuildWithHook,
    },
    classifiers=[
        "Private :: Do Not Upload",  # extra guard: rejected by real PyPI
        "Intended Audience :: Education",
    ],
)
