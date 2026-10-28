"""Shared alert formatting so every detector speaks the same clear language.

An alert always answers three questions:
  WHAT was detected, WHY it is suspicious, and WHAT to do next.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field, asdict


@dataclass
class Alert:
    detector: str            # which detector fired
    severity: str            # INFO | WARN | CRITICAL
    what: str                # what was observed
    why: str                 # why it is suspicious
    recommendation: str      # what to do about it
    evidence: dict = field(default_factory=dict)
    ts: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> dict:
        return asdict(self)


_COLORS = {"INFO": "\033[36m", "WARN": "\033[33m", "CRITICAL": "\033[31m"}
_RESET = "\033[0m"


def print_alert(alert: Alert, color: bool = True) -> None:
    c = _COLORS.get(alert.severity, "") if color and sys.stdout.isatty() else ""
    r = _RESET if c else ""
    print(f"\n{c}┌─ [{alert.severity}] {alert.detector}{r}")
    print(f"{c}│ WHAT:{r} {alert.what}")
    print(f"{c}│ WHY :{r} {alert.why}")
    print(f"{c}│ FIX :{r} {alert.recommendation}")
    if alert.evidence:
        ev = json.dumps(alert.evidence, indent=2)
        for line in ev.splitlines():
            print(f"{c}│{r}   {line}")
    print(f"{c}└{'─' * 40}{r}")
