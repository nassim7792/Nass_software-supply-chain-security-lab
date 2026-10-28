"""Detector #2 — network monitor (scapy).

Idea: package installation should not make surprising outbound connections. A
confusion payload typically "phones home". This detector sniffs traffic during
the install window and flags any TCP connection to a host/port that is not on
an allowlist of expected package-infrastructure endpoints.

scapy needs raw-socket privileges (run with sudo / CAP_NET_RAW). If those are
unavailable, the detector falls back to a log-based mode: it reads the monitor's
SQLite capture log to confirm whether an unexpected beacon was received during
the window, and raises an equivalent alert. The runner uses the fallback by
default so the lab works without root.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass

from detection.alerts import Alert, print_alert

# Endpoints an install is *expected* to talk to (package indexes, mirrors).
# Anything else during install is suspicious.
DEFAULT_ALLOWLIST = {
    ("127.0.0.1", 8080),   # the internal/local index (pypiserver)
    ("127.0.0.1", 443),    # placeholder for an https mirror
}


@dataclass
class Connection:
    dst_ip: str
    dst_port: int
    note: str = ""


def _classify(conns: list[Connection], allow: set[tuple[str, int]]) -> list[Alert]:
    alerts: list[Alert] = []
    for c in conns:
        if (c.dst_ip, c.dst_port) in allow:
            continue
        sev = "CRITICAL" if c.dst_port in (80, 8888) else "WARN"
        alerts.append(Alert(
            detector="network_monitor",
            severity=sev,
            what=f"Unexpected outbound connection to {c.dst_ip}:{c.dst_port} "
                 f"during package installation.",
            why="Installing a package should only contact your package indexes. "
                "A connection to an unlisted host is a classic sign of an "
                "install-time implant beaconing out. " + (c.note or ""),
            recommendation="Block egress from build/CI to everything except your "
                           "registry. Investigate the package that triggered this.",
            evidence={"dst": f"{c.dst_ip}:{c.dst_port}"},
        ))
    if not alerts:
        alerts.append(Alert(
            detector="network_monitor", severity="INFO",
            what="No unexpected outbound connections observed during install.",
            why="All traffic stayed within the allowlisted index endpoints.",
            recommendation="None.",
        ))
    return alerts


def sniff_live(duration: int = 10, iface: str | None = None,
               allow: set[tuple[str, int]] | None = None) -> list[Alert]:
    """Live capture with scapy. Requires privileges."""
    allow = allow or DEFAULT_ALLOWLIST
    try:
        from scapy.all import sniff, IP, TCP  # type: ignore
    except Exception as e:  # pragma: no cover
        return [Alert(
            detector="network_monitor", severity="INFO",
            what="scapy not available for live capture.",
            why=f"Falling back to log mode ({e}).",
            recommendation="pip install scapy and run this detector with sudo "
                           "for true packet capture.",
        )]

    seen: list[Connection] = []

    def handle(pkt):
        if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":  # SYN = new conn
            seen.append(Connection(pkt[IP].dst, int(pkt[TCP].dport)))

    try:
        sniff(prn=handle, store=False, timeout=duration,
              filter="tcp", iface=iface)
    except PermissionError:
        return [Alert(
            detector="network_monitor", severity="INFO",
            what="Insufficient privileges for packet capture.",
            why="scapy needs raw-socket access (sudo / CAP_NET_RAW).",
            recommendation="Re-run with sudo, or use the log-based fallback.",
        )]
    return _classify(seen, allow)


def scan_from_log(window_seconds: int = 3600) -> list[Alert]:
    """Fallback: infer a 'phone-home' from the monitor's capture log.

    If the demo beaconed to the localhost monitor, a row exists. From a network
    detector's point of view, that beacon *is* the unexpected connection to
    127.0.0.1:8888 — a destination not on the install allowlist.
    """
    from scsim.config import MONITOR_DB
    if not MONITOR_DB.exists():
        return [Alert(
            detector="network_monitor", severity="INFO",
            what="No capture log found.",
            why="The monitor has not recorded any beacon.",
            recommendation="Start the monitor and run the attack first.",
        )]
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S",
                           time.localtime(time.time() - window_seconds))
    with closing(sqlite3.connect(MONITOR_DB)) as conn:
        cur = conn.execute(
            "SELECT remote_addr, COUNT(*) FROM captures WHERE received_at >= ? "
            "GROUP BY remote_addr", (cutoff,))
        rows = cur.fetchall()
    conns = [Connection(addr or "127.0.0.1", 8888,
                        note=f"{n} beacon(s) received on the monitor port.")
             for addr, n in rows]
    alerts = _classify(conns, DEFAULT_ALLOWLIST)
    for a in alerts:
        print_alert(a)
    return alerts


def scan(live: bool = False, duration: int = 8) -> list[Alert]:
    if live:
        alerts = sniff_live(duration=duration)
        for a in alerts:
            print_alert(a)
        return alerts
    return scan_from_log()


if __name__ == "__main__":
    import sys
    scan(live="--live" in sys.argv)
