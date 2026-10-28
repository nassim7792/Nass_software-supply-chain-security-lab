"""scsim — the interactive demonstration runner.

Orchestrates the whole dependency-confusion lab end to end:

    python -m scsim.runner run --narrated

Subcommands:
    registry   start the local pypiserver (:8080)
    monitor    start the monitoring dashboard (:8888)
    publish    build the impostor sdist and publish it to the local registry
    attack     install the target app so the impostor's hooks fire
    detect     run all three detectors
    defend     run all five defenses
    report     regenerate the analysis report
    run        do everything (add --narrated to pause + explain each step)

Everything is local. `attack` uses uv/pip against the local index; a
`--simulate` flag drives the beacons directly so the lab works offline.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scsim import config as C
from scsim.narrate import rule, say, panel, pause

_PROCS: list[subprocess.Popen] = []


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #
def _wait_http(url: str, timeout: float = 15.0) -> bool:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.4)
    return False


def start_registry(background: bool = True) -> subprocess.Popen | None:
    """Start pypiserver serving C.REGISTRY_STORE on :8080 (anonymous ok)."""
    if _wait_http(C.REGISTRY_URL, timeout=1):
        say(f"registry already up at {C.REGISTRY_URL}", "green")
        return None
    cmd = [sys.executable, "-m", "pypiserver", "run",
           "-p", str(C.REGISTRY_PORT), "-i", C.REGISTRY_HOST,
           "-a", ".", "-P", ".",  # disable auth for the lab
           str(C.REGISTRY_STORE)]
    say(f"starting registry: {' '.join(cmd)}", "dim")
    proc = subprocess.Popen(cmd)
    _PROCS.append(proc)
    if _wait_http(C.REGISTRY_URL):
        say(f"registry up at {C.REGISTRY_URL}", "green")
    else:
        say("registry did not come up — is pypiserver installed?", "red")
    return proc


def start_monitor(background: bool = True) -> subprocess.Popen | None:
    if _wait_http(C.MONITOR_URL, timeout=1):
        say(f"monitor already up at {C.MONITOR_URL}", "green")
        return None
    cmd = [sys.executable, "-m", "uvicorn", "monitoring.server:app",
           "--host", C.MONITOR_HOST, "--port", str(C.MONITOR_PORT)]
    say(f"starting monitor: {' '.join(cmd)}", "dim")
    proc = subprocess.Popen(cmd, cwd=str(C.REPO_ROOT))
    _PROCS.append(proc)
    if _wait_http(C.MONITOR_URL):
        say(f"monitor up at {C.MONITOR_URL}  (open it in a browser)", "green")
    else:
        say("monitor did not come up — check uvicorn/fastapi install", "red")
    return proc


# --------------------------------------------------------------------------- #
# steps
# --------------------------------------------------------------------------- #
def publish() -> None:
    """Build the impostor sdist and drop it into the local registry store."""
    pkg = C.DEMO_PKG_DIR
    dist = pkg / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    say("building impostor sdist (runs the build-time hook once)...", "dim")
    # Build with no isolation off by default; build backend runs setup.py.
    subprocess.run([sys.executable, "-m", "build", "--sdist", str(pkg)],
                   check=True)
    produced = sorted(dist.glob("*.tar.gz"))
    if not produced:
        raise RuntimeError("sdist build produced no artifact")
    for art in produced:
        shutil.copy2(art, C.REGISTRY_STORE / art.name)
        say(f"published {art.name} -> local registry store", "green")
    say(f"registry now serves: {C.REGISTRY_SIMPLE_URL}{C.DEMO_PACKAGE_NAME}/", "dim")


def attack(simulate: bool = False) -> None:
    """Install the target app so the impostor's hooks fire."""
    import os
    env = dict(os.environ, SCSIM_MONITOR_URL=C.MONITOR_COLLECT_URL)

    if simulate:
        say("SIMULATE: driving the install hooks directly (no network).", "yellow")
        sys.path.insert(0, str(C.DEMO_PKG_DIR))
        from internal_auth_utils._telemetry import collect_and_report
        for stage in ("build", "post-install", "import"):
            collect_and_report(stage=stage)
            say(f"  beacon sent: stage={stage}", "dim")
            time.sleep(0.3)
        return

    venv = C.STATE_DIR / "target_venv"
    uv = shutil.which("uv")
    if uv:
        say("installing target app deps with uv (impostor wins resolution)...", "dim")
        subprocess.run([uv, "venv", str(venv)], check=True, env=env)
        # --no-binary forces a source install so the setup.py install hook runs.
        subprocess.run(
            [uv, "pip", "install", "--python", str(venv),
             "--index-url", C.REGISTRY_SIMPLE_URL,
             "--no-binary", C.DEMO_PACKAGE_NAME,
             C.DEMO_PACKAGE_NAME],
            check=True, env=env)
    else:
        say("uv not found; falling back to pip + venv.", "yellow")
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        pip = venv / ("Scripts" if sys.platform == "win32" else "bin") / "pip"
        subprocess.run(
            [str(pip), "install", "--index-url", C.REGISTRY_SIMPLE_URL,
             "--no-binary", C.DEMO_PACKAGE_NAME, C.DEMO_PACKAGE_NAME],
            check=True, env=env)
    say("install complete — hooks fired. Check the monitor dashboard.", "green")


def detect(live_network: bool = False) -> list[dict]:
    from detection import hash_check, network_monitor, filesystem_monitor
    rule("Detection")
    out = []
    say("\n[1/3] hash / lockfile verification", "bold")
    out += [a.to_dict() for a in hash_check.scan()]
    say("\n[2/3] network monitor", "bold")
    out += [a.to_dict() for a in network_monitor.scan(live=live_network)]
    say("\n[3/3] filesystem monitor", "bold")
    out += [a.to_dict() for a in filesystem_monitor.run()]
    return out


def defend() -> list[dict]:
    from defenses import (lockfile_pinning, namespace_reservation,
                          scoped_registry, signing_verification, policy_scanner)
    rule("Defenses")
    results = []
    for mod in (lockfile_pinning, namespace_reservation, scoped_registry,
                signing_verification, policy_scanner):
        res = mod.test_against_attack()
        results.append(res)
        status = {True: "BLOCKED ✓", False: "did not block", None: "n/a"}[res["blocked"]]
        say(f"  • {res['defense']:<22} {status:<16} {res['detail']}")
    return results


def report() -> Path:
    from report.generate_report import generate
    path = generate()
    say(f"report written to {path}", "green")
    return path


# --------------------------------------------------------------------------- #
# full run
# --------------------------------------------------------------------------- #
NARRATION = {
    "intro": (
        "Dependency confusion: a package manager, offered the same name on more "
        "than one index, installs the highest version it finds — so an attacker "
        "who publishes a high version under your internal name gets their code "
        "run on your machines. We'll watch it happen locally, then stop it."),
    "registry": "Starting a local private index. It stands in for a company's "
                "internal registry (and, in this lab, for the public index the "
                "attacker abuses).",
    "monitor": "Starting the monitor. This is where the impostor's benign "
               "beacons land so we can see each time its code runs.",
    "publish": "Publishing the impostor internal-auth-utils 99.0.0. The giant "
               "version number is the whole trick — it beats the real 1.4.2.",
    "attack": "Installing the target app. Resolution picks 99.0.0; building and "
              "installing it runs the hooks; importing it runs more. Watch the "
              "timeline fill.",
    "detect": "Now the blue-team view: three independent detectors, each saying "
              "what it saw and why it's suspicious.",
    "defend": "Finally, five defenses tested against this exact attack — which "
              "one stops it, and at which stage.",
}


def run_all(narrated: bool = False, simulate: bool = False,
            live_network: bool = False) -> None:
    rule("Supply Chain Attack Simulator")
    panel(NARRATION["intro"], title="What is dependency confusion?")
    pause(narrated)

    say("\n» " + NARRATION["registry"]) if narrated else None
    start_registry()
    pause(narrated)

    say("\n» " + NARRATION["monitor"]) if narrated else None
    start_monitor()
    pause(narrated)

    say("\n» " + NARRATION["publish"]) if narrated else None
    publish()
    pause(narrated)

    say("\n» " + NARRATION["attack"]) if narrated else None
    attack(simulate=simulate)
    time.sleep(1.0)
    say(f"   → open {C.MONITOR_URL}/timeline to see the sequence", "cyan")
    pause(narrated)

    say("\n» " + NARRATION["detect"]) if narrated else None
    detections = detect(live_network=live_network)
    pause(narrated)

    say("\n» " + NARRATION["defend"]) if narrated else None
    defenses = defend()
    pause(narrated)

    say("\n» Generating the analysis report...") if narrated else None
    report()

    rule("Done")
    blocked = sum(1 for d in defenses if d["blocked"])
    say(f"Captured beacons on the monitor, {len([d for d in detections if d['severity']=='CRITICAL'])} "
        f"critical detections, {blocked}/5 defenses blocked the attack.", "bold green")
    say("Leave the registry/monitor running to explore the dashboard, or Ctrl-C.", "dim")


def _cleanup() -> None:
    for p in _PROCS:
        try:
            p.terminate()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scsim", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("registry")
    sub.add_parser("monitor")
    sub.add_parser("publish")
    a = sub.add_parser("attack"); a.add_argument("--simulate", action="store_true")
    d = sub.add_parser("detect"); d.add_argument("--live-network", action="store_true")
    sub.add_parser("defend")
    sub.add_parser("report")
    r = sub.add_parser("run")
    r.add_argument("--narrated", action="store_true")
    r.add_argument("--simulate", action="store_true",
                   help="drive hooks directly instead of uv/pip (offline-safe)")
    r.add_argument("--live-network", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "registry":
            start_registry(); _hold()
        elif args.cmd == "monitor":
            start_monitor(); _hold()
        elif args.cmd == "publish":
            publish()
        elif args.cmd == "attack":
            attack(simulate=args.simulate)
        elif args.cmd == "detect":
            detect(live_network=args.live_network)
        elif args.cmd == "defend":
            defend()
        elif args.cmd == "report":
            report()
        elif args.cmd == "run":
            run_all(narrated=args.narrated, simulate=args.simulate,
                    live_network=args.live_network)
    finally:
        if args.cmd not in ("registry", "monitor"):
            _cleanup()
    return 0


def _hold() -> None:
    say("running — press Ctrl-C to stop.", "dim")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
