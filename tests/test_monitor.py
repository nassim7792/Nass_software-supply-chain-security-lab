"""The monitoring dashboard must capture beacons and render."""
import importlib

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Point the monitor DB at a temp file so tests don't touch real state.
    import scsim.config as cfg
    monkeypatch.setattr(cfg, "MONITOR_DB", tmp_path / "captures.sqlite3")
    server = importlib.reload(importlib.import_module("monitoring.server"))
    server.init_db()
    return TestClient(server.app)


def test_collect_stores_beacon(client):
    r = client.post("/collect", json={
        "stage": "post-install", "package": "internal-auth-utils",
        "package_version": "99.0.0", "hostname": "h", "username": "u",
        "python_version": "3.12", "platform": "linux", "cwd": "/x", "lab": True,
    })
    assert r.status_code == 200
    events = client.get("/api/events").json()
    assert len(events) == 1
    assert events[0]["stage"] == "post-install"


def test_dashboard_and_timeline_render(client):
    client.post("/collect", json={"stage": "import", "package": "x",
                                   "package_version": "99.0.0", "lab": True})
    assert client.get("/").status_code == 200
    assert client.get("/timeline").status_code == 200


def test_security_console_renders(client):
    # Renders whether or not pipeline artifacts exist on disk.
    r = client.get("/security")
    assert r.status_code == 200
    assert client.get("/api/security").status_code == 200
