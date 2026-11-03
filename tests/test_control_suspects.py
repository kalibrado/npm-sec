"""Control center threat triage: permission, ranking, exemptions and rule states."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import deployment


@pytest.fixture
def triage(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "triage.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "temporary-admin-test-password")
    monkeypatch.setattr(deployment, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    return TestClient(app)


def login(client):
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "temporary-admin-test-password"},
    )
    assert response.status_code == 200, response.text


def test_suspects_require_admin(triage):
    assert triage.get("/security-control/suspects").status_code == 401


def test_empty_threats_and_invalid_filters(triage):
    login(triage)
    data = triage.get("/security-control/suspects").json()
    assert data["items"] == []
    assert data["policy_state"] == "not_configured"
    for params in ("hours=0", "hours=169", "min_score=101", "limit=0", "limit=101"):
        assert triage.get(f"/security-control/suspects?{params}").status_code == 422


def add_threat(conn, ip, score=80, threat_type="scanner", created_at="datetime('now')", host="cloud.example.test"):
    # The created_at argument is a trusted test fixture expression, never user input.
    conn.execute(
        """INSERT INTO access_logs(timestamp, ip, host, status, uri)
           VALUES (datetime('now'), ?, ?, 403, '/.env')""",
        [ip, host],
    )
    log_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        f"""INSERT INTO threat_events(access_log_id, ip, score, threat_type, created_at)
            VALUES (?, ?, ?, ?, {created_at})""",
        [log_id, ip, score, threat_type],
    )


def test_suspects_ranking_and_policy_context(triage):
    with database.get_db() as conn:
        add_threat(conn, "203.0.113.21", 90, "brute_force")
        add_threat(conn, "203.0.113.21", 70, "scanner")
        add_threat(conn, "203.0.113.22", 65)
        add_threat(conn, "192.168.1.10", 95)
        add_threat(conn, "203.0.113.25", 99, created_at="datetime('now','-3 days')")
        conn.execute(
            "INSERT INTO blocklist(type, value, reason) VALUES ('ip', '203.0.113.21', 'block')"
        )
        conn.execute(
            "INSERT INTO blocklist(type, value, reason) VALUES ('cidr', '203.0.113.0/24', 'network')"
        )
        conn.execute(
            "INSERT INTO trusted_entries(type, value) VALUES ('ip', '203.0.113.22')"
        )
        conn.commit()

    login(triage)
    response = triage.get("/security-control/suspects?hours=24&min_score=50")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["window_hours"] == 24
    assert len(data["items"]) == 3
    by_ip = {item["ip"]: item for item in data["items"]}
    assert "203.0.113.25" not in by_ip
    assert by_ip["203.0.113.21"]["signals"] == 2
    assert by_ip["203.0.113.21"]["brute_force"] == 1
    assert by_ip["203.0.113.21"]["scans"] == 1
    assert by_ip["203.0.113.21"]["direct_block_id"] is not None
    assert by_ip["203.0.113.21"]["block_rule"]["type"] == "ip"
    assert by_ip["203.0.113.22"]["trusted"] is True
    assert by_ip["203.0.113.22"]["trust_source"] == "ip"
    assert by_ip["203.0.113.22"]["block_rule"]["type"] == "cidr"
    assert by_ip["203.0.113.22"]["direct_block_id"] is None
    assert by_ip["192.168.1.10"]["internal"] is True
    assert by_ip["192.168.1.10"]["trusted"] is True
    assert data["policy_state"] == "not_configured"


def test_score_filter_and_invalid_ip_ignored(triage):
    with database.get_db() as conn:
        add_threat(conn, "203.0.113.2", 29)
        add_threat(conn, "203.0.113.3", 60)
        add_threat(conn, "not-an-ip", 100)
        conn.commit()
    login(triage)
    data = triage.get("/security-control/suspects?min_score=50").json()
    assert [item["ip"] for item in data["items"]] == ["203.0.113.3"]


def test_expired_block_rule_not_reported_as_active(triage):
    with database.get_db() as conn:
        add_threat(conn, "203.0.113.4", 75)
        conn.execute(
            """INSERT INTO blocklist(type, value, expires_at)
               VALUES ('ip', '203.0.113.4', datetime('now','-1 minute'))"""
        )
        conn.commit()
    login(triage)
    item = triage.get("/security-control/suspects").json()["items"][0]
    assert item["block_rule"] is None
    assert item["direct_block_id"] is None


def test_triage_ui_exposes_manual_actions_and_confirmations():
    page = Path("templates/dashboard.html").read_text(encoding="utf-8")
    script = Path("static/dashboard.js").read_text(encoding="utf-8")
    assert 'id="suspects-body"' in page
    assert "/security-control/suspects?hours=" in script
    assert "data-suspect-action" in script
    assert "confirm(prompts[action])" in script
    assert "showIPProfile(ip)" in script
