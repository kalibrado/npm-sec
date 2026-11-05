"""Authorization and integrity regression tests for the read-only settings API."""
import contextlib
import sqlite3

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_deps import get_current_user
from routers import nginx_settings
from services.nginx_settings_revisions import (
    create_settings_revision, initialize_settings_revisions,
)

SETTINGS = {
    "auto_ban_enabled": False,
    "country_block_enabled": False,
    "blocked_countries": [],
    "trusted_proxy_cidrs": [],
    "rate_limit_rps": 10,
    "rate_limit_burst": 20,
}


def test_settings_read_endpoints_require_auth_and_validate_integrity(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)
        create_settings_revision(conn, SETTINGS, expected_revision=0, author="admin", reason="initial")

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)

    assert client.get("/api/nginx-settings/latest").status_code == 401
    assert client.get("/api/nginx-settings/history").status_code == 401

    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    latest = client.get("/api/nginx-settings/latest")
    assert latest.status_code == 200
    assert latest.json()["draft"]["revision"] == 1
    assert latest.json()["draft"]["settings"] == SETTINGS
    history = client.get("/api/nginx-settings/history")
    assert history.status_code == 200
    assert history.json()["revisions"][0]["revision"] == 1
    assert "settings" not in history.json()["revisions"][0]
    assert client.get("/api/nginx-settings/history?limit=101").status_code == 422
    assert client.get("/api/nginx-settings/history?before_revision=0").status_code == 422

    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE nginx_settings_revisions SET settings_sha256=? WHERE revision=1", ("0" * 64,))
        conn.commit()
    assert client.get("/api/nginx-settings/latest").status_code == 409
    assert client.get("/api/nginx-settings/history").status_code == 409

def test_revision_diff_api_permissions_and_corruption(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)
        create_settings_revision(conn, SETTINGS, expected_revision=0, author="admin", reason="initial")
        updated = {**SETTINGS, "rate_limit_rps": 12}
        create_settings_revision(conn, updated, expected_revision=1, author="admin", reason="rate change")

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)
    endpoint = "/api/nginx-settings/diff?before_revision=1&after_revision=2"

    assert client.get(endpoint).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    response = client.get(endpoint)
    assert response.status_code == 200
    assert response.json() == {
        "before_revision": 1,
        "after_revision": 2,
        "changes": {"rate_limit_rps": {"before": 10, "after": 12}},
    }
    assert client.get("/api/nginx-settings/diff?before_revision=2&after_revision=2").json()["changes"] == {}
    assert client.get("/api/nginx-settings/diff?before_revision=0&after_revision=2").status_code == 422
    assert client.get("/api/nginx-settings/diff?before_revision=1").status_code == 422
    assert client.get("/api/nginx-settings/diff?before_revision=1&after_revision=999").status_code == 404

    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE nginx_settings_revisions SET settings_sha256=? WHERE revision=2", ("0" * 64,))
        conn.commit()
    assert client.get(endpoint).status_code == 409


def test_admin_write_requires_intent_and_enforces_revision(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)
        create_settings_revision(conn, SETTINGS, expected_revision=0, author="importer", reason="verified initial", source_sha256="a" * 64)

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)
    url = "/api/nginx-settings/revisions"
    payload = {"settings": SETTINGS, "expected_revision": 1, "reason": "update"}

    assert client.post(url, json=payload, headers={"X-NSD-Intent": "save-settings"}).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    assert client.post(url, json=payload, headers={"X-NSD-Intent": "save-settings"}).status_code == 403
    app.dependency_overrides[get_current_user] = lambda: {"username": "writer", "role": "admin"}
    assert client.post(url, json=payload).status_code == 403
    headers = {"X-NSD-Intent": "save-settings"}
    response = client.post(url, json=payload, headers=headers)
    assert response.status_code == 201
    assert response.json()["draft"]["revision"] == 2
    assert response.json()["draft"]["author"] == "writer"
    assert client.post(url, json=payload, headers=headers).status_code == 409
    assert client.post(url, json={**payload, "expected_revision": 1, "settings": {"bad": True}}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "expected_revision": -1}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "expected_revision": 0}, headers=headers).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 2
        conn.execute("UPDATE nginx_settings_revisions SET settings_sha256=? WHERE revision=2", ("0" * 64,))
        conn.commit()
    assert client.post(url, json={**payload, "expected_revision": 2}, headers=headers).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 2


def test_admin_write_rejects_cross_origin_and_fetch_metadata(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "writer", "role": "admin"}
    client = TestClient(app)
    url = "/api/nginx-settings/revisions"
    payload = {"settings": SETTINGS, "expected_revision": 0, "reason": "safe"}
    base = {"X-NSD-Intent": "save-settings"}
    for headers in (
        {"Origin": "https://attacker.example"},
        {"Origin": "null"},
        {"Origin": "https://testserver.attacker.example"},
        {"Origin": "https://testserver@attacker.example"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"},
    ):
        assert client.post(url, json=payload, headers={**base, **headers}).status_code == 403

    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 0

    response = client.post(
        url, json=payload,
        headers={**base, "Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Initial revision requires verified source import"


def test_verified_initial_import_requires_admin_source_and_empty_history(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)
    url = "/api/nginx-settings/import-initial"
    headers = {"X-NSD-Intent": "import-settings"}
    payload = {
        "settings": SETTINGS,
        "source_sha256": "a" * 64,
        "source_description": "verified local nginx snapshot",
        "reason": "baseline migration",
        "verified_against_source": True,
    }
    assert client.post(url, json=payload, headers=headers).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    assert client.post(url, json=payload, headers=headers).status_code == 403
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "admin"}
    assert client.post(url, json=payload).status_code == 403
    assert client.post(url, json=payload, headers={**headers, "Origin": "https://evil.example"}).status_code == 403
    assert client.post(url, json={**payload, "verified_against_source": False}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "source_sha256": "invalid"}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "settings": {"unknown": 1}}, headers=headers).status_code == 422
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 0

    response = client.post(url, json=payload, headers=headers)
    assert response.status_code == 201

    assert response.json()["draft"]["revision"] == 1

    draft = response.json()["draft"]
    assert draft["revision"] == 1
    assert draft["author"] == "admin"
    assert draft["source_sha256"] == "a" * 64
    assert "verified local nginx snapshot" in draft["reason"]
    assert client.post(url, json=payload, headers=headers).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 1
def test_typed_schema_endpoint_is_authenticated_and_does_not_invent_defaults():
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)
    assert client.get("/api/nginx-settings/schema").status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    response = client.get("/api/nginx-settings/schema")
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == 1
    assert body["legacy_defaults_imported"] is False
    assert set(body["fields"]) == set(SETTINGS)
    assert body["fields"]["rate_limit_rps"]["min"] == 1
    assert body["fields"]["rate_limit_burst"]["min"] == 0
    assert body["fields"]["trusted_proxy_cidrs"]["max_items"] == 256
    assert all("default" not in field for field in body["fields"].values())

def test_full_import_edit_diff_and_reimport_rejection(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "operator", "role": "admin"}
    client = TestClient(app)
    assert client.get("/api/nginx-settings/latest").json()["draft"] is None
    assert client.post("/api/nginx-settings/revisions", json={
        "settings": SETTINGS, "expected_revision": 0, "reason": "bypass",
    }, headers={"X-NSD-Intent": "save-settings"}).status_code == 409

    imported = client.post("/api/nginx-settings/import-initial", json={
        "settings": SETTINGS, "source_sha256": "b" * 64,
        "source_description": "manually verified snapshot",
        "reason": "baseline", "verified_against_source": True,
    }, headers={"X-NSD-Intent": "import-settings"})
    assert imported.status_code == 201
    assert imported.json()["draft"]["revision"] == 1
    updated = {**SETTINGS, "rate_limit_rps": 15}
    saved = client.post("/api/nginx-settings/revisions", json={
        "settings": updated, "expected_revision": 1, "reason": "adjust rate",
    }, headers={"X-NSD-Intent": "save-settings"})
    assert saved.status_code == 201
    assert saved.json()["draft"]["revision"] == 2
    diff = client.get("/api/nginx-settings/diff?before_revision=1&after_revision=2")
    assert diff.status_code == 200
    assert diff.json()["changes"] == {"rate_limit_rps": {"before": 10, "after": 15}}
    assert client.get("/api/nginx-settings/latest").json()["draft"]["settings"] == updated
    assert len(client.get("/api/nginx-settings/history").json()["revisions"]) == 2
    assert client.post("/api/nginx-settings/import-initial", json={
        "settings": SETTINGS, "source_sha256": "b" * 64,
        "source_description": "manually verified snapshot",
        "reason": "again", "verified_against_source": True,
    }, headers={"X-NSD-Intent": "import-settings"}).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 2



def test_admin_restore_api_auth_conflict_and_integrity(tmp_path, monkeypatch):
    path = tmp_path / "settings.db"
    with sqlite3.connect(path) as conn:
        initialize_settings_revisions(conn)
        create_settings_revision(conn, SETTINGS, expected_revision=0, author="importer", reason="initial")
        changed = {**SETTINGS, "rate_limit_rps": 25}
        create_settings_revision(conn, changed, expected_revision=1, author="admin", reason="change")

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)
    url = "/api/nginx-settings/restore"
    payload = {"target_revision": 1, "expected_revision": 2, "reason": "restore baseline"}
    headers = {"X-NSD-Intent": "restore-settings"}

    assert client.post(url, json=payload, headers=headers).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    assert client.post(url, json=payload, headers=headers).status_code == 403
    app.dependency_overrides[get_current_user] = lambda: {"username": "operator", "role": "admin"}
    assert client.post(url, json=payload).status_code == 403
    assert client.post(url, json=payload, headers={**headers, "Origin": "https://evil.example"}).status_code == 403
    assert client.post(url, json={**payload, "target_revision": 0}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "reason": "   "}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "target_revision": 999}, headers=headers).status_code == 404
    restored = client.post(url, json=payload, headers=headers)
    assert restored.status_code == 201
    assert restored.json()["draft"]["revision"] == 3
    assert restored.json()["draft"]["settings"] == SETTINGS
    assert restored.json()["draft"]["author"] == "operator"
    assert restored.json()["draft"]["status"] == "DRAFT"
    assert client.post(url, json=payload, headers=headers).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 3
        conn.execute("UPDATE nginx_settings_revisions SET settings_sha256=? WHERE revision=1", ("0" * 64,))
        conn.commit()
    assert client.post(url, json={**payload, "expected_revision": 3}, headers=headers).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 3
