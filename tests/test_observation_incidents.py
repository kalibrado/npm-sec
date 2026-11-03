"""Real JSON-file ingestion and admin incident lifecycle regression tests."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import auto_ban, ingestion, log_parser, observation


@pytest.fixture
def environment(tmp_path, monkeypatch):
    log_file = tmp_path / "npm-security.jsonl"
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "observation.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "observation-admin-test-password")
    monkeypatch.setattr(ingestion, "LOG_FILE", log_file)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_ENABLED", True)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_THRESHOLD", 3)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_WINDOW_MINUTES", 5)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_COOLDOWN_MINUTES", 15)
    monkeypatch.setattr(log_parser, "OBSERVE_ALERT_DISCORD_ENABLED", False)
    database.init_db()
    return TestClient(app), log_file


def logged_line(
    ip="203.0.113.45",
    host="cloud.kaliorbis.fr",
    mode="observe",
    would_deny="1",
    uri="/login",
    timestamp=None,
):
    record = {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "remote_addr": ip,
        "host": host,
        "uri": uri,
        "status": "200",
        "allowed": "yes",
        "http_user_agent": "Mozilla/5.0",
    }
    if mode is not None:
        record["npm_security_policy_mode"] = mode
    if would_deny is not None:
        record["npm_security_would_deny"] = would_deny
    return json.dumps(record) + "\n"


def write_and_ingest(log_file, *lines):
    with log_file.open("a", encoding="utf-8") as stream:
        stream.writelines(lines)
    return ingestion.ingest_file_once(log_file)


def login(client):
    r = client.post(
        "/auth/login",
        json={"username": "admin", "password": "observation-admin-test-password"},
    )
    assert r.status_code == 200, r.text


def counts():
    with database.get_db() as conn:
        return {
            "logs": conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0],
            "incidents": conn.execute("SELECT COUNT(*) FROM observation_incidents").fetchone()[0],
            "alerts": conn.execute("SELECT COUNT(*) FROM observation_alerts").fetchone()[0],
            "bans": conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0],
        }


def test_observation_requires_actual_nginx_log_fields(environment):
    c, path = environment
    assert write_and_ingest(
        path,
        logged_line(mode=None, would_deny=None),
        logged_line(mode="observe", would_deny=None),
        logged_line(mode=None, would_deny="1"),
        logged_line(mode="block", would_deny="1"),
        logged_line(mode="observe", would_deny="0"),
        logged_line(mode="observe", would_deny="maybe"),
        logged_line(mode="observe", would_deny=True),
    ) == 7
    assert counts() == {"logs": 7, "incidents": 0, "alerts": 0, "bans": 0}
    with database.get_db() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE policy_mode='block' AND would_deny=1"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE policy_mode IS NULL"
        ).fetchone()[0] == 5

    assert write_and_ingest(path, logged_line()) == 1
    assert counts()["incidents"] == 1
    login(c)
    summary = c.get("/security-control/observations").json()
    assert summary["telemetry_available"] is True
    assert summary["telemetry"]["would_deny_requests"] == 1
    assert summary["telemetry"]["would_deny_block_mode"] == 1


def test_incident_threshold_alert_cooldown_and_idempotent_cursor(environment):
    c, path = environment
    assert write_and_ingest(path, *(logged_line(uri=f"/probe/{i}") for i in range(3))) == 3
    assert counts() == {"logs": 3, "incidents": 1, "alerts": 1, "bans": 0}
    assert write_and_ingest(path, logged_line(uri="/probe/4")) == 1
    assert counts()["alerts"] == 1
    with database.get_db() as conn:
        item = conn.execute("SELECT * FROM observation_incidents").fetchone()
        assert item["hits"] == 4
        assert item["last_uri"] == "/probe/4"
        conn.execute("UPDATE ingestion_state SET byte_offset=0")
        conn.commit()
    assert ingestion.ingest_file_once(path) == 0
    assert counts() == {"logs": 4, "incidents": 1, "alerts": 1, "bans": 0}

    login(c)
    response = c.get("/security-control/observations?hours=24")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["telemetry_available"] is True
    assert data["telemetry"]["instrumented_requests"] == 4
    assert data["telemetry"]["would_deny_requests"] == 4
    assert data["alert_count"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["hits"] == 4
    assert data["items"][0]["status"] == "open"

    alerts = c.get("/security-control/observations/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["recent_hits"] == 3
    assert alerts[0]["incident_id"] == data["items"][0]["id"]

    with database.get_db() as conn:
        conn.execute(
            """UPDATE observation_incidents
               SET last_alert_at=datetime('now','-20 minutes')"""
        )
        conn.commit()
    assert write_and_ingest(path, logged_line(uri="/new/alert")) == 1
    assert counts()["alerts"] == 2


def test_no_early_alert_and_separate_hosts_or_ips(environment):
    c, path = environment
    lines = [
        logged_line(host="cloud.kaliorbis.fr", ip="203.0.113.5"),
        logged_line(host="cloud.kaliorbis.fr", ip="203.0.113.5"),
        logged_line(host="jellyfin.kaliorbis.fr", ip="203.0.113.5"),
        logged_line(host="cloud.kaliorbis.fr", ip="203.0.113.6"),
    ]
    assert write_and_ingest(path, *lines) == 4
    assert counts()["incidents"] == 3
    assert counts()["alerts"] == 0
    login(c)
    data = c.get("/security-control/observations").json()
    assert len(data["items"]) == 3


def test_stale_log_does_not_create_fresh_alert(environment):
    c, path = environment
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    assert write_and_ingest(
        path, *(logged_line(timestamp=old) for _ in range(4))
    ) == 4
    assert counts()["incidents"] == 1
    assert counts()["alerts"] == 0
    login(c)
    data = c.get("/security-control/observations?hours=24").json()
    assert data["telemetry_available"] is False
    assert data["telemetry"]["would_deny_requests"] == 0


def test_incidents_can_be_acknowledged_resolved_and_reopened(environment):
    c, path = environment
    write_and_ingest(path, logged_line())
    assert c.get("/security-control/observations").status_code == 401
    assert c.get("/security-control/observations/alerts").status_code == 401
    assert c.post(
        "/security-control/observations/1/status", json={"status": "resolved"}
    ).status_code == 401
    login(c)

    for status in ("acknowledged", "resolved"):
        response = c.post(
            "/security-control/observations/1/status", json={"status": status}
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == status
    assert c.get("/security-control/observations?status=resolved").json()["items"][0]["status"] == "resolved"

    assert write_and_ingest(path, logged_line(uri="/new")) == 1
    assert c.get("/security-control/observations?status=open").json()["items"][0]["status"] == "open"
    assert c.post(
        "/security-control/observations/1/status", json={"status": "invalid"}
    ).status_code == 422
    assert c.post(
        "/security-control/observations/999/status", json={"status": "resolved"}
    ).status_code == 404
    assert c.get("/security-control/observations?status=invalid").status_code == 422
    assert c.get("/security-control/observations?hours=500").status_code == 422


def test_observe_mode_never_triggers_auto_ban(environment, monkeypatch):
    c, path = environment
    monkeypatch.setattr(auto_ban, "AUTO_BAN_ENABLED", True)
    monkeypatch.setattr(auto_ban, "AUTO_BAN_SCORE", 0)
    monkeypatch.setattr(auto_ban, "AUTO_BAN_DRY_RUN", False)
    monkeypatch.setattr(auto_ban, "AUTO_BAN_EXPORT_APPLY", False, raising=False)
    assert write_and_ingest(
        path, logged_line(ip="203.0.113.66", uri="/.env"),
        logged_line(ip="203.0.113.66", uri="/wp-admin"),
    ) == 2
    assert counts()["bans"] == 0


def test_migration_and_ui_bindings(environment):
    database.init_db()
    with database.get_db() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(access_logs)")}
        assert {"policy_mode", "would_deny"} <= columns
    page = Path("templates/dashboard.html").read_text(encoding="utf-8")
    script = Path("static/dashboard.js").read_text(encoding="utf-8")
    assert 'id="observation-incidents-body"' in page
    assert "/security-control/observations" in script
    assert "changeObservationStatus" in script
    assert "loadObservationIncidents()" in script
