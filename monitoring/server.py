"""Monitoring dashboard — the localhost sink that captures the demo's beacons.

Run it:  python -m scsim.runner monitor   (or)   python monitoring/server.py
Then open http://127.0.0.1:8888/ in a browser.

It receives the benign metadata beacons the demo package sends, stores every
one in SQLite, and renders a dashboard + a timeline so the impact of a single
careless dependency is visceral and concrete.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# Import shared config (works whether run as module or script).
try:
    from scsim.config import MONITOR_DB, MONITOR_HOST, MONITOR_PORT
except Exception:  # pragma: no cover - script fallback
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from scsim.config import MONITOR_DB, MONITOR_HOST, MONITOR_PORT

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

app = FastAPI(title="Supply Chain Monitor")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(MONITOR_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(_db()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS captures (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at     TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                stage           TEXT,
                package         TEXT,
                package_version TEXT,
                hostname        TEXT,
                username        TEXT,
                python_version  TEXT,
                platform        TEXT,
                cwd             TEXT,
                remote_addr     TEXT,
                user_agent      TEXT,
                raw             TEXT
            )
            """
        )
        conn.commit()


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.post("/collect")
async def collect(request: Request):
    """Endpoint the demo package POSTs to. Stores the beacon verbatim."""
    try:
        payload = await request.json()
    except Exception:
        payload = {"_parse_error": (await request.body()).decode("utf-8", "replace")}

    with closing(_db()) as conn:
        conn.execute(
            """
            INSERT INTO captures
              (stage, package, package_version, hostname, username,
               python_version, platform, cwd, remote_addr, user_agent, raw)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                payload.get("stage"),
                payload.get("package"),
                payload.get("package_version"),
                payload.get("hostname"),
                payload.get("username"),
                payload.get("python_version"),
                payload.get("platform"),
                payload.get("cwd"),
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
                json.dumps(payload),
            ),
        )
        conn.commit()
    return JSONResponse({"status": "captured", "stage": payload.get("stage")})


def _rows(order: str = "DESC") -> list[dict]:
    with closing(_db()) as conn:
        cur = conn.execute(f"SELECT * FROM captures ORDER BY id {order}")
        return [dict(r) for r in cur.fetchall()]


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    rows = _rows("DESC")
    for r in rows:
        try:
            r["installed_sample"] = json.loads(r["raw"]).get("installed_packages_sample", [])
        except Exception:
            r["installed_sample"] = []
    return TEMPLATES.TemplateResponse(
        request, "dashboard.html", {"rows": rows, "count": len(rows)},
    )


@app.get("/timeline", response_class=HTMLResponse)
def timeline(request: Request):
    rows = _rows("ASC")  # chronological for the timeline
    return TEMPLATES.TemplateResponse(request, "timeline.html", {"rows": rows})


@app.get("/api/events")
def api_events():
    return _rows("ASC")


# --------------------------------------------------------------------------- #
# Security console: SBOM + CVE findings + gate verdict, read from the artifacts
# produced by the DevSecOps pipeline (security/*.json).
# --------------------------------------------------------------------------- #
def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    except Exception:
        return None


def _security_state() -> dict:
    from scsim.config import REPO_ROOT
    sec = REPO_ROOT / "security"
    sbom = _load_json(sec / "sbom.cyclonedx.json")
    # Prefer the demo report (richer) if present, else the real one.
    cve = _load_json(sec / "cve_report.demo.json") or _load_json(sec / "cve_report.json")
    verdict = None
    policy_path = sec / "security-policy.yml"
    if policy_path.exists():
        try:
            from security import gate as gate_mod
            policy = gate_mod._load_policy(policy_path)
            verdict = gate_mod.evaluate(policy, sbom, cve)
        except Exception:
            verdict = None
    return {"sbom": sbom, "cve": cve, "verdict": verdict}


@app.get("/security", response_class=HTMLResponse)
def security_console(request: Request):
    state = _security_state()
    return TEMPLATES.TemplateResponse(request, "security.html", state)


@app.get("/api/security")
def api_security():
    return _security_state()


@app.post("/api/clear")
def api_clear():
    with closing(_db()) as conn:
        conn.execute("DELETE FROM captures")
        conn.commit()
    return {"status": "cleared"}


if __name__ == "__main__":
    import uvicorn

    init_db()
    uvicorn.run(app, host=MONITOR_HOST, port=MONITOR_PORT)
