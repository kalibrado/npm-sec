"""Admin config editing, validation, audit and no-write preview regression tests."""
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import security_profiles as profiles


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "profile.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "profile-test-admin-password")
    database.init_db()
    return TestClient(app)


def login(client, username="admin", password="profile-test-admin-password"):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text


def stored_count():
    with database.get_db() as db:
        return db.execute("SELECT COUNT(*) FROM security_profile_revisions").fetchone()[0]


def test_default_profile_is_preserved_without_deploying_or_writing(client):
    assert client.get("/security-profile").status_code == 401
    assert client.post("/security-profile/preview", json={"settings":{}}).status_code == 401
    login(client)
    profile = client.get("/security-profile").json()
    assert profile["revision"] == 0
    assert profile["settings"] == profiles.DEFAULTS
    assert profile["deployment"]["state"] == "not_applied_by_agent"
    assert profile["history"] == []
    assert stored_count() == 0
    rendered = profiles.render_profile(profile["settings"])
    assert "rate=100r/s;" in rendered["http-security.conf"]
    assert "burst=70 nodelay;" in rendered["server-security.conf"]
    assert "FR yes;" in rendered["http-security.conf"]
    assert "192.168.1.0/24 yes;" in rendered["http-security.conf"]
    assert "return 444;" in rendered["server-security.conf"]


def test_preview_renders_real_changes_and_never_persists(client):
    login(client)
    settings = deepcopy(profiles.DEFAULTS)
    settings["rate_limit_rps"] = 50
    settings["allowed_countries"] = ["FR", "PT"]
    settings["scanner_user_agents"] = ["masscan", "nuclei"]
    result = client.post("/security-profile/preview", json={"settings": settings})
    assert result.status_code == 200, result.text
    preview = result.json()
    assert preview["validation"] == "schéma_et_rendu_uniquement"
    assert preview["deployment"] == "non_appliqué"
    assert "http-security.conf" in preview["changed_files"]
    assert "rate=50r/s;" in preview["diff"]["http-security.conf"]
    assert "PT yes;" in preview["diff"]["http-security.conf"]
    assert stored_count() == 0
    assert not (Path("data") / "exports" / "managed-profile").exists()


@pytest.mark.parametrize("key,value", [
    ("rate_limit_rps", True),
    ("rate_limit_rps", 0),
    ("rate_limit_burst", 1000),
    ("scanner_user_agents", ["masscan; return 200;"]),
    ("scanner_user_agents", ["nuclei", "nuclei"]),
    ("allowed_countries", ["CN;"]),
    ("allowed_countries", ["fr", "FR"]),
    ("local_allowed_networks", ["0.0.0.0/0", "127.0.0.1/32"]),
    ("local_allowed_networks", ["127.0.0.1/32"]),
    ("legacy_country_filter_enabled", 1),
    ("legacy_refusal_status", "200"),
])
def test_schema_rejects_invalid_or_unsafe_directives(client, key, value):
    login(client)
    settings = deepcopy(profiles.DEFAULTS)
    settings[key] = value
    r = client.post("/security-profile/preview", json={"settings": settings})
    assert r.status_code == 422, (key, r.text)
    assert stored_count() == 0


def test_only_allowlisted_settings_are_accepted(client):
    login(client)
    a = deepcopy(profiles.DEFAULTS)
    a["nginx_command"] = "rm -rf /"
    assert client.post("/security-profile/preview", json={"settings":a}).status_code == 422
    del a["nginx_command"]
    del a["rate_limit_rps"]
    assert client.post("/security-profile/preview", json={"settings":a}).status_code == 422


def test_revision_save_has_optimistic_lock_and_immutable_audit(client):
    login(client)
    values = deepcopy(profiles.DEFAULTS)
    values["rate_limit_burst"] = 45
    request = {"settings": values, "expected_revision": 0, "note": "Recette burst ajusté"}
    result = client.post("/security-profile/revisions", json=request)
    assert result.status_code == 200, result.text
    assert result.json()["revision"] == 1
    assert result.json()["status"] == "draft_pending"
    assert stored_count() == 1

    current = client.get("/security-profile").json()
    assert current["revision"] == 1
    assert current["settings"]["rate_limit_burst"] == 45
    assert current["history"][0]["created_by"] == "admin"
    assert current["history"][0]["note"] == "Recette burst ajusté"

    assert client.post("/security-profile/revisions", json=request).status_code == 409
    assert stored_count() == 1
    assert client.post("/security-profile/revisions", json={
        **request, "expected_revision": 1
    }).status_code == 409
    assert stored_count() == 1

    values["rate_limit_rps"] = 20
    second = client.post("/security-profile/revisions", json={
        "settings": values, "expected_revision": 1,
        "note": "Deuxième changement",
    })
    assert second.status_code == 200, second.text
    assert second.json()["revision"] == 2

    revision = client.get("/security-profile/revisions/1").json()
    assert revision["settings"]["rate_limit_rps"] == 100
    assert revision["settings"]["rate_limit_burst"] == 45
    assert stored_count() == 2


def test_rollback_creates_new_revision_and_preserves_history(client):
    login(client)
    values = deepcopy(profiles.DEFAULTS)
    values["legacy_refusal_status"] = "403"
    changed = client.post("/security-profile/revisions", json={
        "settings": values, "expected_revision": 0, "note": "Tester les codes 403",
    })
    assert changed.status_code == 200, changed.text
    values["rate_limit_burst"] = 25
    second = client.post("/security-profile/revisions", json={
        "settings": values, "expected_revision": 1, "note": "Limiter les rafales",
    })
    assert second.status_code == 200, second.text

    stale = client.post("/security-profile/revisions/1/restore", json={
        "expected_revision": 1,
    })
    assert stale.status_code == 409
    rollback = client.post("/security-profile/revisions/1/restore", json={
        "expected_revision": 2,
    })
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["revision"] == 3
    current = client.get("/security-profile").json()
    assert current["settings"]["legacy_refusal_status"] == "403"
    assert current["settings"]["rate_limit_burst"] == 70
    assert current["history"][0]["parent_revision"] == 1
    assert stored_count() == 3
    assert client.get("/security-profile/revisions/2").json()["settings"]["rate_limit_burst"] == 25


def test_viewer_cannot_access_or_edit_profile(client):
    login(client)
    created = client.post("/users", json={
        "username": "viewer-profile", "password": "viewer-password-123",
        "role": "viewer",
    })
    assert created.status_code in (200, 201), created.text
    client.post("/auth/logout")
    login(client, "viewer-profile", "viewer-password-123")
    assert client.get("/security-profile").status_code == 403
    assert client.post("/security-profile/preview", json={
        "settings": profiles.DEFAULTS,
    }).status_code == 403
    assert client.post("/security-profile/revisions", json={
        "settings": profiles.DEFAULTS, "expected_revision": 0,
        "note": "do not save",
    }).status_code == 403


def test_config_ui_has_form_preview_history_and_loading_feedback():
    html = Path("templates/dashboard.html").read_text()
    js = Path("static/dashboard.js").read_text()
    assert 'id="nsd-profile-form"' in html
    assert 'id="nsd-profile-fields"' in html
    assert 'id="nsd-profile-diff"' in html
    assert 'id="nsd-profile-history"' in html
    assert "loadSecurityProfile()" in js
    assert "/security-profile/preview" in js
    assert "/security-profile/revisions" in js
    assert "expected_revision" in js
    assert "withBusyButton('nsd-profile-save-btn'" in js
