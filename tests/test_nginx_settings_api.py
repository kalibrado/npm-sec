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

    @contextlib.contextmanager
    def isolated_db():
        with sqlite3.connect(path) as conn:
            yield conn

    monkeypatch.setattr(nginx_settings, "get_db", isolated_db)
    app = FastAPI()
    app.include_router(nginx_settings.router)
    client = TestClient(app)
    url = "/api/nginx-settings/revisions"
    payload = {"settings": SETTINGS, "expected_revision": 0, "reason": "initial"}

    assert client.post(url, json=payload, headers={"X-NSD-Intent": "save-settings"}).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    assert client.post(url, json=payload, headers={"X-NSD-Intent": "save-settings"}).status_code == 403
    app.dependency_overrides[get_current_user] = lambda: {"username": "writer", "role": "admin"}
    assert client.post(url, json=payload).status_code == 403
    headers = {"X-NSD-Intent": "save-settings"}
    response = client.post(url, json=payload, headers=headers)
    assert response.status_code == 201
    assert response.json()["draft"]["revision"] == 1
    assert response.json()["draft"]["author"] == "writer"
    assert client.post(url, json=payload, headers=headers).status_code == 409
    assert client.post(url, json={**payload, "expected_revision": 1, "settings": {"bad": True}}, headers=headers).status_code == 422
    assert client.post(url, json={**payload, "expected_revision": -1}, headers=headers).status_code == 422
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 1
        conn.execute("UPDATE nginx_settings_revisions SET settings_sha256=? WHERE revision=1", ("0" * 64,))
        conn.commit()
    assert client.post(url, json={**payload, "expected_revision": 1}, headers=headers).status_code == 409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 1
