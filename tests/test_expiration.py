"""Temporary IP and country block expiration tests."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import expiration, export


@pytest.fixture
def state(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "logs.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "long-enough-test-password")
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    return tmp_path


def test_expired_ip_removed_and_export_updated(state):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type, value, reason, expires_at)
               VALUES ('ip', '203.0.113.55', 'test', datetime('now','-1 minute'))"""
        )
        conn.commit()
    assert expiration.expire_block_rules() == 1
    assert expiration.expire_block_rules() == 0
    with database.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM ban_events WHERE action='EXPIRE'"
        ).fetchone()[0] == 1
    assert "203.0.113.55" not in (state / "exports" / "npm-blocklist.conf").read_text()


def test_not_yet_expired_ip_stays_active(state):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type, value, reason, expires_at)
               VALUES ('ip', '203.0.113.42', 'test', datetime('now','+1 hour'))"""
        )
        conn.commit()
    assert expiration.expire_block_rules() == 0
    with database.get_db() as conn:
        assert len(export.get_blocklist_items(conn)) == 1


def test_admin_can_create_temporary_block(state):
    client = TestClient(app)
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "long-enough-test-password"},
    )
    assert response.status_code == 200, response.text
    added = client.post(
        "/blocklist",
        json={
            "type": "ip",
            "value": "203.0.113.99",
            "reason": "temporary incident",
            "duration_minutes": 60,
        },
    )
    assert added.status_code == 200, added.text
    assert added.json()["pending_apply"] is True
    rows = client.get("/blocklist").json()
    row = next(item for item in rows if item["value"] == "203.0.113.99")
    assert row["expires_at"] is not None


def test_invalid_duration_is_rejected(state):
    client = TestClient(app)
    client.post("/auth/login", json={"username": "admin", "password": "long-enough-test-password"})
    response = client.post(
        "/blocklist",
        json={"type": "ip", "value": "203.0.113.12", "duration_minutes": 43201},
    )
    assert response.status_code == 422, response.text
