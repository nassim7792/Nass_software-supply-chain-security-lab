"""Detector #3 — filesystem monitor (watchdog).

Idea: an install step has no business touching sensitive directories (SSH keys,
cloud credential files, token caches) or staging copies of them for exfil. This
detector watches a set of sensitive paths during the install window and raises
an alert on any create/modify/delete event there.

Honest limitation: watchdog observes filesystem *mutations*, not pure reads.
True read-detection needs the OS audit layer (Linux auditd/eBPF, macOS ES,
Windows ETW). For the lab we watch canary files and a staging area: a realistic
exfil stager copies secrets into a temp file before sending them, and that write
is exactly what we catch. The module documents how to extend it to auditd.

By default, run() sets up lab canaries in a decoy directory and simulates an
install script rummaging through them, so you can see the detector fire without
pointing it at your real ~/.ssh.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from detection.alerts import Alert, print_alert

# Directory/file names an install script should never be reading or copying.
SENSITIVE_HINTS = (".ssh", "id_rsa", "id_ed25519", ".aws", "credentials",
                   ".env", ".netrc", "token", ".kube", ".docker/config.json")

LAB_DECOY_DIR = Path.home() / ".scsim_canary"


def _is_sensitive(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in SENSITIVE_HINTS)


def watch(paths: list[Path], duration: float = 5.0) -> list[Alert]:
    """Watch paths for mutation events for `duration` seconds."""
    try:
        from watchdog.observers import Observer  # type: ignore
        from watchdog.events import FileSystemEventHandler  # type: ignore
    except Exception as e:  # pragma: no cover
        return [Alert(
            detector="filesystem_monitor", severity="INFO",
            what="watchdog not available.",
            why=f"Install it to enable filesystem monitoring ({e}).",
            recommendation="pip install watchdog",
        )]

    events: list[tuple[str, str]] = []

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            events.append((event.event_type, event.src_path))

    observer = Observer()
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)
        observer.schedule(Handler(), str(p), recursive=True)
    observer.start()
    time.sleep(duration)
    observer.stop()
    observer.join()

    alerts: list[Alert] = []
    for etype, src in events:
        if _is_sensitive(src):
            alerts.append(Alert(
                detector="filesystem_monitor", severity="CRITICAL",
                what=f"Install-time activity touched a sensitive path "
                     f"({etype}): {src}",
                why="Build/install code accessed credential-like files. A "
                    "confusion payload stages secrets here before exfiltrating.",
                recommendation="Run installs in a sandbox with no access to "
                               "developer credentials; audit the package.",
                evidence={"event": etype, "path": src},
            ))
    if not alerts:
        alerts.append(Alert(
            detector="filesystem_monitor", severity="INFO",
            what="No sensitive-path activity during the window.",
            why="Nothing touched credential-like files.",
            recommendation="None.",
        ))
    return alerts


def _simulate_malicious_fs_access() -> None:
    """Lab-only: imitate what a malicious install hook would do to the
    filesystem, so the detector has something to catch. This is run by the
    DETECTOR, not by the demo package — the package stays benign."""
    LAB_DECOY_DIR.mkdir(parents=True, exist_ok=True)
    canary = LAB_DECOY_DIR / "id_rsa"           # looks like an SSH private key
    canary.write_text("LAB CANARY, not a real key\n", encoding="utf-8")
    # Simulate a stager copying the "secret" into an exfil buffer.
    (LAB_DECOY_DIR / "exfil_stage.tmp").write_text(
        canary.read_text(encoding="utf-8"), encoding="utf-8")


def run(duration: float = 3.0, simulate: bool = True,
        extra_paths: list[Path] | None = None) -> list[Alert]:
    """Entry point used by the runner."""
    import threading
    paths = [LAB_DECOY_DIR] + (extra_paths or [])
    if simulate:
        # Kick off the simulated rummaging slightly after the watcher starts.
        threading.Timer(0.8, _simulate_malicious_fs_access).start()
    alerts = watch(paths, duration=duration)
    for a in alerts:
        print_alert(a)
    return alerts


if __name__ == "__main__":
    run()
