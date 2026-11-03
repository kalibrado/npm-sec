"""Security regression tests for exposed API routes and first-run credentials."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import config
import database
from main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.parametrize(
    "path",
    [
        "/events",
        "/history?limit=1",
        "/stats",
        "/timeline",
        "/heatmap",
        "/sparklines?ips=192.0.2.1",
        "/whois/192.0.2.1",
        "/widget",
        "/security-activity",
        "/ip/192.0.2.1/profile",
        "/metrics",
        "/health/details",
        "/threats",
        "/blocklist",
    ],
)
def test_sensitive_endpoint_requires_authentication(client, path):
    response = client.get(path)
    assert response.status_code == 401, (path, response.text)


def test_missing_initial_admin_password_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "app.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "")
    with pytest.raises(RuntimeError, match="DEFAULT_ADMIN_PASSWORD"):
        database.init_db()


def test_short_production_session_secret_rejected(monkeypatch):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "SESSION_SECRET", "short")
    monkeypatch.setattr(config, "ADMIN_TOKEN", "")
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        config.validate_runtime_config()


def test_production_example_mount_paths():
    values = dict(
        line.split("=", 1)
        for line in Path(".env.example").read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    assert values["DB_FILE"] == "/data/logs.db"
    assert values["LOG_FILE"] == "/logs/access-geo-detailed.log"
    assert values["EXPORT_DIR"] == "/data/exports"
    assert values["BACKUP_DIR"] == "/data/backups"
