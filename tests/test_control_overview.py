"""The control center must separate observed traffic from configured policy."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import deployment


@pytest.fixture
def control_client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "control.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "secure-test-admin-password")
    monkeypatch.setattr(deployment, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    client = TestClient(app)
    return client


def authenticate(client):
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "secure-test-admin-password"},
    )
    assert response.status_code == 200, response.text


def test_control_overview_is_not_public(control_client):
    response = control_client.get("/security-control/overview")
    assert response.status_code == 401


def test_control_overview_returns_real_zero_values(control_client):
    authenticate(control_client)
    response = control_client.get("/security-control/overview")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["window_hours"] == 24
    assert data["policy"]["state"] == "not_configured"
    assert data["rules"]["active_total"] == 0
    assert data["rules"]["trusted_total"] == 0
    assert data["traffic"]["requests"] == 0
    assert data["traffic"]["proxy_blocked"] == 0
    assert data["detections"]["signals"] == 0
    assert data["recent_actions"] == []


def test_counts_do_not_confuse_rule_storage_with_proxy_blocks(control_client):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type, value, reason)
               VALUES ('ip','203.0.113.5','manual')"""
        )
        conn.execute(
            """INSERT INTO blocklist(type, value, reason, expires_at)
               VALUES ('country','RU','expired', datetime('now','-1 hour'))"""
        )
        conn.execute(
            """INSERT INTO trusted_entries(type, value, reason)
               VALUES ('ip','192.0.2.42','operator')"""
        )
        conn.execute(
            """INSERT INTO access_logs(timestamp,ip,blocked)
               VALUES (datetime('now'), '203.0.113.10', 0)"""
        )
        conn.execute(
            """INSERT INTO access_logs(timestamp,ip,blocked)
               VALUES (datetime('now'), '203.0.113.11', 1)"""
        )
        conn.execute(
            """INSERT INTO access_logs(timestamp,ip,blocked)
               VALUES (datetime('now','-3 days'), '203.0.113.12', 1)"""
        )
        conn.execute(
            """INSERT INTO threat_events(ip,threat_type,score)
               VALUES ('203.0.113.10','brute_force',75)"""
        )
        conn.execute(
            """INSERT INTO threat_events(ip,threat_type,score)
               VALUES ('203.0.113.11','scanner',65)"""
        )
        conn.execute(
            """INSERT INTO ban_events(target,type,action,reason)
               VALUES ('203.0.113.5','ip','BLOCK','manual')"""
        )
        conn.commit()

    authenticate(control_client)
    response = control_client.get("/security-control/overview?hours=24")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["rules"]["active_total"] == 1
    assert data["rules"]["by_type"] == {"ip": 1, "cidr": 0, "country": 0}
    assert data["rules"]["trusted_total"] == 1
    assert data["traffic"] == {
        "requests": 2, "proxy_blocked": 1, "unique_ips": 2
    }
    assert data["detections"] == {
        "signals": 2, "suspicious_ips": 2, "brute_force": 1, "http_scans": 1
    }
    assert data["policy"]["state"] == "not_configured"
    assert data["recent_actions"][0]["action"] == "BLOCK"


@pytest.mark.parametrize("hours", [0, 169, -2])
def test_rejects_invalid_time_window(control_client, hours):
    authenticate(control_client)
    assert (
        control_client.get(f"/security-control/overview?hours={hours}").status_code
        == 422
    )


def test_control_center_is_wired_to_dashboard():
    page = Path("templates/dashboard.html").read_text(encoding="utf-8")
    script = Path("static/dashboard.js").read_text(encoding="utf-8")
    assert 'id="security-control-overview"' in page
    assert "/security-control/overview?hours=24" in script
    assert "loadSecurityControlOverview()" in script
    assert "policy.state" in script
