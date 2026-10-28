"""Tiny narration helper with graceful fallback if `rich` isn't installed."""
from __future__ import annotations

import sys

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    _console = Console()
    _HAVE_RICH = True
except Exception:  # pragma: no cover
    _console = None
    _HAVE_RICH = False


def rule(title: str) -> None:
    if _HAVE_RICH:
        _console.print(Rule(title))
    else:
        print(f"\n{'=' * 8} {title} {'=' * 8}")


def say(text: str, style: str = "") -> None:
    if _HAVE_RICH:
        _console.print(text, style=style)
    else:
        print(text)


def panel(text: str, title: str = "") -> None:
    if _HAVE_RICH:
        _console.print(Panel(text, title=title, expand=False))
    else:
        print(f"\n--- {title} ---\n{text}\n")


def pause(narrated: bool, prompt: str = "   [press Enter to continue]") -> None:
    if narrated and sys.stdin.isatty():
        try:
            input(prompt)
        except EOFError:
            pass
