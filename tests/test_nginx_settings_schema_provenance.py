"""Schema import status must reflect persisted provenance, not a static flag."""
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


def test_schema_reports_import_provenance_and_detects_corruption(tmp_path, monkeypatch):
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
    url = "/api/nginx-settings/schema"
    assert client.get(url).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}
    assert client.get(url).json()["legacy_defaults_imported"] is False

    with sqlite3.connect(path) as conn:
        create_settings_revision(
            conn, SETTINGS, expected_revision=0, author="admin",
            reason="ordinary draft without verified source",
        )
    assert client.get(url).json()["legacy_defaults_imported"] is False

    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM nginx_settings_revisions")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='nginx_settings_revisions'")
        conn.commit()
        create_settings_revision(
            conn, SETTINGS, expected_revision=0, author="admin",
            reason="verified import", source_sha256="a" * 64,
        )
        create_settings_revision(
            conn, {**SETTINGS, "rate_limit_rps": 12},
            expected_revision=1, author="admin", reason="edited draft",
        )
    assert client.get(url).json()["legacy_defaults_imported"] is True

    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE nginx_settings_revisions SET settings_sha256=? WHERE revision=1",
            ("0" * 64,),
        )
        conn.commit()
    assert client.get(url).status_code == 409
