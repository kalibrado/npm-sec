"""Manual ban guardrails and API error status regression tests."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import export


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "guardrails.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "test-admin-guardrails-password")
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    c = TestClient(app)
    r = c.post(
        "/auth/login",
        json={"username": "admin", "password": "test-admin-guardrails-password"},
    )
    assert r.status_code == 200, r.text
    return c


def count_bans():
    with database.get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]


@pytest.mark.parametrize(
    "value",
    ["127.0.0.1", "192.168.1.4", "10.12.0.17", "::1", "fd00::2", "fe80::44"],
)
def test_internal_addresses_cannot_be_manual_banned(client, value):
    result = client.post("/blocklist", json={"type": "ip", "value": value})
    assert result.status_code == 409, (value, result.text)
    assert "protected internal network" in result.json()["detail"]
    assert count_bans() == 0


@pytest.mark.parametrize(
    "value",
    ["0.0.0.0/0", "10.3.0.0/16", "192.168.1.0/24", "::/0", "fd00::/48"],
)
def test_cidrs_overlapping_management_networks_are_rejected(client, value):
    result = client.post("/blocklist", json={"type": "cidr", "value": value})
    assert result.status_code == 409, (value, result.text)
    assert count_bans() == 0


def test_direct_block_api_protects_lan(client):
    result = client.post("/block_ip/127.0.0.1")
    assert result.status_code == 409
    assert count_bans() == 0


def test_explicit_trusted_ip_prevents_conflicting_manual_block(client):
    trust = client.post(
        "/trusted",
        json={"type": "ip", "value": "203.0.113.24", "reason": "operator"},
    )
    assert trust.status_code == 200, trust.text

    first = client.post(
        "/blocklist", json={"type": "ip", "value": "203.0.113.24"}
    )
    second = client.post("/block_ip/203.0.113.24")
    assert first.status_code == 409
    assert second.status_code == 409
    assert "takes precedence" in first.json()["detail"]
    assert count_bans() == 0


def test_trusted_network_prevents_ineffective_ip_block(client):
    client.post(
        "/trusted",
        json={"type": "cidr", "value": "203.0.113.0/24"},
    )
    r = client.post(
        "/blocklist", json={"type": "ip", "value": "203.0.113.99"}
    )
    assert r.status_code == 409
    assert count_bans() == 0


def test_public_ip_block_still_works(client):
    r = client.post(
        "/blocklist",
        json={
            "type": "ip",
            "value": "198.51.100.21",
            "duration_minutes": 60,
            "reason": "investigated",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["pending_apply"] is True
    assert count_bans() == 1


def test_public_cidr_can_have_trusted_ip_exception(client):
    client.post(
        "/trusted",
        json={"type": "ip", "value": "203.0.113.24"},
    )
    r = client.post(
        "/blocklist", json={"type": "cidr", "value": "203.0.113.0/24"}
    )
    assert r.status_code == 200, r.text
    assert count_bans() == 1
    content = (Path(export.EXPORT_DIR) / "npm-blocklist.conf").read_text()
    assert "203.0.113.0/24 1;" in content
    assert "203.0.113.24 1;" in content


def test_unicode_country_code_rejected_before_nginx_export(client):
    r = client.post("/blocklist", json={"type": "country", "value": "ΑΒ"})
    assert r.status_code == 400
    assert count_bans() == 0
