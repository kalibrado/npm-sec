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
