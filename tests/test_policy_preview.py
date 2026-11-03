"""Security policy preview is explainable, read-only and host-aware."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import deployment, export


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "preview.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "preview-test-admin-password")
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path / "exports")
    monkeypatch.setattr(deployment, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    return TestClient(app)


def login(client):
    r = client.post(
        "/auth/login",
        json={"username": "admin", "password": "preview-test-admin-password"},
    )
    assert r.status_code == 200, r.text


def preview(client, ip="203.0.113.17", host="cloud.kaliorbis.fr", country_code=None):
    args = {"ip": ip, "host": host}
    if country_code:
        args["country_code"] = country_code
    return client.get("/security-control/policy/preview", params=args)


def test_policy_preview_requires_authentication(client):
    assert preview(client).status_code == 401


def test_empty_policy_allows_but_is_not_confirmed_by_nginx(client):
    login(client)
    r = preview(client)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["predicted_decision"] == "allow"
    assert data["matching_block_rules"] == []
    assert data["trusted_matches"] == []
    assert data["policy"]["state"] == "not_configured"
    assert data["source"] == "stored_rules_only"


def test_host_scope_only_blocks_matching_domain(client):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type,value,host)
               VALUES ('cidr','203.0.113.0/24','cloud.kaliorbis.fr')"""
        )
        conn.commit()
    login(client)
    a = preview(client).json()
    b = preview(client, host="jellyfin.kaliorbis.fr").json()
    assert a["predicted_decision"] == "deny"
    assert a["matching_block_rules"][0]["host"] == "cloud.kaliorbis.fr"
    assert b["predicted_decision"] == "allow"
    assert b["matching_block_rules"] == []


def test_global_country_blocks_all_domains_when_country_is_known(client):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type,value,host)
               VALUES ('country','CN','')"""
        )
        conn.commit()
    login(client)
    assert preview(client, country_code="CN").json()["predicted_decision"] == "deny"
    assert preview(
        client, host="jellyfin.kaliorbis.fr", country_code="CN"
    ).json()["predicted_decision"] == "deny"
    assert preview(client, country_code="FR").json()["predicted_decision"] == "allow"
    unknown = preview(client).json()
    assert unknown["predicted_decision"] == "unknown"
    assert unknown["requires_country"] is True


def test_trust_override_of_block_and_country(client):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type,value,host)
               VALUES ('country','CN','cloud.kaliorbis.fr')"""
        )
        conn.execute(
            """INSERT INTO blocklist(type,value,host)
               VALUES ('ip','203.0.113.17','')"""
        )
        conn.execute(
            """INSERT INTO trusted_entries(type,value)
               VALUES ('cidr','203.0.113.0/24')"""
        )
        conn.commit()
    login(client)
    d = preview(client, country_code="CN").json()
    assert d["predicted_decision"] == "allow"
    assert d["trusted"] is True
    assert len(d["matching_block_rules"]) == 2
    assert d["trusted_matches"][0]["type"] == "cidr"
    assert d["requires_country"] is False


def test_private_management_ip_is_trusted(client):
    with database.get_db() as conn:
        conn.execute(
            "INSERT INTO blocklist(type,value,host) VALUES ('country','RU','')"
        )
        conn.commit()
    login(client)
    d = preview(client, ip="192.168.1.1", country_code="RU").json()
    assert d["predicted_decision"] == "allow"
    assert d["trusted"] is True
    assert any(x["type"] == "internal_network" for x in d["trusted_matches"])


def test_expired_policy_is_ignored(client):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type,value,host,expires_at)
               VALUES ('ip','203.0.113.17','', datetime('now','-1 hour'))"""
        )
        conn.commit()
    login(client)
    assert preview(client).json()["predicted_decision"] == "allow"


@pytest.mark.parametrize(
    "query, code",
    [
        ({"ip": "wrong", "host": "cloud.kaliorbis.fr"}, 400),
        ({"ip": "203.0.113.1", "host": "*.kaliorbis.fr"}, 422),
        ({"ip": "203.0.113.1", "host": ""}, 422),
        ({"ip": "203.0.113.1", "host": "cloud.kaliorbis.fr", "country_code": "RU;"}, 400),
    ],
)
def test_rejects_invalid_preview_arguments(client, query, code):
    login(client)
    r = client.get("/security-control/policy/preview", params=query)
    assert r.status_code == code, r.text


def test_preview_never_changes_policy_state(client, tmp_path):
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type,value,host)
               VALUES ('country','CN','cloud.kaliorbis.fr')"""
        )
        conn.commit()
    login(client)
    for _ in range(3):
        assert preview(client, country_code="CN").status_code == 200
    with database.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ban_events").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0] == 1
    assert not (Path(export.EXPORT_DIR) / "npm-blocklist.conf").exists()


def test_preview_form_is_wired_to_read_only_endpoint():
    html = Path("templates/dashboard.html").read_text()
    script = Path("static/dashboard.js").read_text()
    assert 'id="security-preview-form"' in html
    assert "/security-control/policy/preview?" in script
    assert "addEventListener('submit', simulateSavedSecurityPolicy)" in script
    assert "source" in Path("services/policy_preview.py").read_text()
