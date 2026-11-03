"""Observe mode is explicit, opt-in, persisted and cannot silently deploy itself."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import deployment, expiration, export


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "observe.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "observe-mode-admin-password")
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path / "exports")
    monkeypatch.setattr(deployment, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    c = TestClient(app)
    return c


def login(c):
    r = c.post(
        "/auth/login",
        json={"username": "admin", "password": "observe-mode-admin-password"},
    )
    assert r.status_code == 200, r.text


def preview(c, host):
    r = c.get(
        "/security-control/policy/preview",
        params={"ip": "203.0.113.45", "host": host, "country_code": "FR"},
    )
    assert r.status_code == 200, r.text
    return r.json()


def add_global_block(c):
    response = c.post(
        "/blocklist",
        json={"type": "cidr", "value": "203.0.113.0/24", "reason": "test"},
    )
    assert response.status_code == 200, response.text


def test_policy_modes_are_admin_only(client):
    assert client.get("/security-control/policy/modes").status_code == 401
    assert client.post(
        "/security-control/policy/modes",
        json={"host": "", "mode": "observe"},
    ).status_code == 401
    assert client.delete("/security-control/policy/modes").status_code == 401


def test_default_mode_remains_block_to_preserve_existing_behavior(client):
    login(client)
    modes = client.get("/security-control/policy/modes")
    assert modes.status_code == 200
    assert modes.json()["default_mode"] == "block"
    assert modes.json()["overrides"] == []
    add_global_block(client)
    result = preview(client, "cloud.kaliorbis.fr")
    assert result["predicted_decision"] == "deny"
    assert result["rule_decision"] == "deny"
    assert result["enforcement_mode"] == "block"
    assert result["would_deny"] is True
    snippet = (Path(export.EXPORT_DIR) / "npm-blocklist.conf").read_text()
    assert "map $host $npm_security_policy_mode {" in snippet
    assert "    default block;" in snippet
    assert '"block:1" 1;' in snippet


def test_scoped_observe_disables_403_only_for_its_domain(client):
    login(client)
    add_global_block(client)
    set_mode = client.post(
        "/security-control/policy/modes",
        json={"host": "CLOUD.KALIORBIS.FR.", "mode": "observe"},
    )
    assert set_mode.status_code == 200, set_mode.text
    assert set_mode.json() == {
        "host": "cloud.kaliorbis.fr",
        "mode": "observe",
        "pending_apply": True,
    }
    modes = client.get("/security-control/policy/modes").json()
    assert modes["default_mode"] == "block"
    assert modes["overrides"] == [
        {"host": "cloud.kaliorbis.fr", "mode": "observe"}
    ]
    assert modes["policy"]["state"] == "pending"

    cloud = preview(client, "cloud.kaliorbis.fr")
    jellyfin = preview(client, "jellyfin.kaliorbis.fr")
    assert cloud["predicted_decision"] == "allow"
    assert cloud["rule_decision"] == "deny"
    assert cloud["would_deny"] is True
    assert cloud["enforcement_mode"] == "observe"
    assert jellyfin["predicted_decision"] == "deny"
    assert jellyfin["enforcement_mode"] == "block"
    text = (Path(export.EXPORT_DIR) / "npm-blocklist.conf").read_text()
    assert "    cloud.kaliorbis.fr observe;" in text
    assert "    default block;" in text
    assert "map \"$npm_security_policy_mode:$npm_security_would_deny\" $npm_security_deny" in text

    reset = client.delete(
        "/security-control/policy/modes", params={"host": "cloud.kaliorbis.fr"}
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["pending_apply"] is True
    assert preview(client, "cloud.kaliorbis.fr")["predicted_decision"] == "deny"


def test_global_observe_with_per_host_block_exception(client):
    login(client)
    add_global_block(client)
    global_result = client.post(
        "/security-control/policy/modes",
        json={"mode": "observe"},
    )
    assert global_result.status_code == 200, global_result.text
    scoped_result = client.post(
        "/security-control/policy/modes",
        json={"host": "jellyfin.kaliorbis.fr", "mode": "block"},
    )
    assert scoped_result.status_code == 200, scoped_result.text
    assert preview(client, "cloud.kaliorbis.fr")["predicted_decision"] == "allow"
    assert preview(client, "jellyfin.kaliorbis.fr")["predicted_decision"] == "deny"
    modes = client.get("/security-control/policy/modes").json()
    assert modes["default_mode"] == "observe"
    assert modes["overrides"] == [
        {"host": "jellyfin.kaliorbis.fr", "mode": "block"}
    ]
    text = (Path(export.EXPORT_DIR) / "npm-blocklist.conf").read_text()
    assert "    default observe;" in text
    assert "    jellyfin.kaliorbis.fr block;" in text


def test_missing_country_is_explained_even_in_observe_mode(client):
    login(client)
    assert client.post(
        "/blocklist", json={"type": "country", "value": "CN"}
    ).status_code == 200
    assert client.post(
        "/security-control/policy/modes", json={"mode": "observe"}
    ).status_code == 200
    r = client.get(
        "/security-control/policy/preview",
        params={"ip": "203.0.113.45", "host": "cloud.kaliorbis.fr"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["predicted_decision"] == "allow"
    assert data["rule_decision"] == "unknown"
    assert data["would_deny"] is None
    assert data["requires_country"] is True


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"host": "cloud.kaliorbis.fr", "mode": "alert"}, 422),
        ({"host": "cloud.kaliorbis.fr", "mode": "disabled"}, 422),
        ({"host": "https://cloud.kaliorbis.fr", "mode": "observe"}, 422),
        ({"host": "*.kaliorbis.fr", "mode": "observe"}, 422),
        ({"host": "cloud.kaliorbis.fr:443", "mode": "observe"}, 422),
    ],
)
def test_rejects_invalid_modes_and_hostnames(client, payload, status):
    login(client)
    response = client.post("/security-control/policy/modes", json=payload)
    assert response.status_code == status, response.text
    assert client.get("/security-control/policy/modes").json()["overrides"] == []


def test_expiration_export_keeps_observe_mode(client):
    login(client)
    client.post(
        "/security-control/policy/modes",
        json={"host": "cloud.kaliorbis.fr", "mode": "observe"},
    )
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type, value, host, expires_at)
               VALUES ('ip', '198.51.100.22', 'cloud.kaliorbis.fr',
                       datetime('now', '-1 minute'))"""
        )
        conn.commit()
    assert expiration.expire_block_rules() == 1
    snippet = (Path(export.EXPORT_DIR) / "npm-blocklist.conf").read_text()
    assert "cloud.kaliorbis.fr observe;" in snippet
    assert "198.51.100.22" not in snippet


def test_ui_mode_form_and_observe_confirmation_are_wired():
    html = Path("templates/dashboard.html").read_text(encoding="utf-8")
    js = Path("static/dashboard.js").read_text(encoding="utf-8")
    assert 'id="security-modes-form"' in html
    assert 'id="security-modes-list"' in html
    assert "/security-control/policy/modes" in js
    assert "savePolicyMode" in js
    assert "mode === 'observe' && !confirm(" in js
    assert "result.would_deny" in js
