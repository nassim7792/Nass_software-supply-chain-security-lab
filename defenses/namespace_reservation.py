"""Defense #2 — namespace reservation.

Dependency confusion needs the attacker to be able to *claim* your internal name
on a public index. If you proactively register (reserve) your internal package
names on PyPI yourself, the attacker can't publish under them. Modern PyPI also
supports **organization namespaces** (reserved name prefixes) so an org can own
`acme-*` outright.

We cannot and must not register anything on real PyPI from this lab, so this
module simulates the reservation registry locally and shows exactly what the
registration flow looks like, then proves that a reserved name blocks the
impostor's publish attempt.
"""
from __future__ import annotations

import json
from pathlib import Path


def _reservation_store() -> Path:
    from scsim.config import STATE_DIR
    return STATE_DIR / "pypi_reservations.json"


def reserved_names() -> set[str]:
    p = _reservation_store()
    if p.exists():
        return set(json.loads(p.read_text(encoding="utf-8")).get("reserved", []))
    return set()


def reserve(name: str) -> dict:
    """Simulate reserving a project name (what `twine upload` of a 0.0.0
    placeholder, or an org namespace grant, achieves on real PyPI)."""
    p = _reservation_store()
    names = reserved_names()
    names.add(name.lower())
    p.write_text(json.dumps({"reserved": sorted(names)}, indent=2), encoding="utf-8")
    return {"reserved": name, "method": "placeholder upload / org namespace"}


def registration_walkthrough() -> str:
    return (
        "Namespace reservation on PyPI — real-world steps:\n"
        "  1. Enumerate every internal package name used anywhere "
        "(grep pyproject/requirements across all repos).\n"
        "  2. For each name, register it on PyPI yourself with a harmless 0.0.0\n"
        "     placeholder:\n"
        "       python -m build  &&  twine upload dist/*\n"
        "     The project classifier 'Private :: Do Not Upload' and an empty\n"
        "     module make it clear it is a reservation, not a real release.\n"
        "  3. Prefer PyPI **organization namespaces** to reserve a whole prefix\n"
        "     (e.g. 'acme-*') so you don't have to chase every new name.\n"
        "  4. Re-run enumeration in CI so new internal names get reserved too.\n"
    )


def attempt_publish(name: str) -> dict:
    """Simulate the attacker trying to publish `name` to the public index."""
    if name.lower() in reserved_names():
        return {"published": False,
                "reason": f"'{name}' is already owned/reserved — PyPI rejects the upload."}
    return {"published": True,
            "reason": f"'{name}' was unclaimed — attacker now owns it on the public index."}


def test_against_attack() -> dict:
    from scsim.config import DEMO_PACKAGE_NAME
    # The defense: reserve the internal name first.
    reserve(DEMO_PACKAGE_NAME)
    result = attempt_publish(DEMO_PACKAGE_NAME)
    return {
        "defense": "namespace_reservation",
        "blocked": not result["published"],
        "stage_prevented": "publish (pre-attack)",
        "detail": result["reason"],
    }


if __name__ == "__main__":
    print(registration_walkthrough())
    print(json.dumps(test_against_attack(), indent=2))
