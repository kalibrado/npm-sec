"""Extended security settings, historical revision compatibility and Nginx syntax."""
import importlib.util
import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import security_profiles as profiles


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "profile-v2.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "legacy-schema-admin-password")
    database.init_db()
    c = TestClient(app)
    login = c.post("/auth/login", json={
        "username": "admin", "password": "legacy-schema-admin-password",
    })
    assert login.status_code == 200
    return c


def test_all_new_fields_have_safe_historic_defaults_and_descriptions(client):
    response = client.get("/security-profile")
    assert response.status_code == 200
    data = response.json()
    assert len(data["schema"]) == 22
    assert set(data["schema"]) == set(data["settings"])
    assert all(spec.get("group") and spec.get("description") and
               "default" in spec for spec in data["schema"].values())
    assert data["settings"]["real_ip_header"] == "X-Real-IP"
    assert data["settings"]["log_internal_requests"] is True
    assert data["settings"]["geoip_auto_reload_hours"] == 3
    assert data["settings"]["debug_geo_headers_enabled"] is True
    assert data["settings"]["security_response_headers_enabled"] is False


def test_rendering_extended_switches_without_freeform_directives(client):
    s = deepcopy(profiles.DEFAULTS)
    s.update({
        "rate_limit_enabled": False,
        "rate_limit_status": "503",
        "scanner_rules_enabled": False,
        "geoip_auto_reload_hours": 6,
        "real_ip_header": "disabled",
        "trusted_proxy_networks": [],
        "log_exclude_networks": ["127.0.0.1/32"],
        "log_internal_requests": False,
        "custom_error_pages_enabled": False,
        "sensitive_path_protection_enabled": False,
        "proxy_buffering_enabled": True,
        "proxy_intercept_errors_enabled": False,
        "debug_geo_headers_enabled": False,
        "security_response_headers_enabled": True,
    })
    response = client.post("/security-profile/preview", json={"settings":s})
    assert response.status_code == 200, response.text
    assert sorted(response.json()["changed_files"]) == [
        "http-security.conf", "server-security.conf",
    ]
    rendered = profiles.render_profile(s)
    http, server = rendered["http-security.conf"], rendered["server-security.conf"]
    assert "auto_reload 6h;" in http
    assert "real_ip_header " not in http.split("geo $remote_addr", 1)[0]
    assert "set_real_ip_from" not in http
    assert "geo $remote_addr $exclude_from_log" in http
    assert "127.0.0.1/32 0;" in http
    assert "192.168.1.0/24 0;" not in http
    assert "~*masscan" not in http
    assert "X-Visitor-IP" not in http
    assert "access-geo-detailed.log detailed_visitor if=$exclude_from_log;" in server
    assert "limit_req_status 503;" in server
    assert "limit_req zone=req_limit_per_ip" not in server
    assert "proxy_buffering on;" in server
    assert "proxy_intercept_errors off;" in server
    assert "error_page 403" not in server
    assert "location /error_pages/" not in server
    assert "location ~" not in server
    assert "X-Content-Type-Options nosniff always;" in server


@pytest.mark.parametrize("key,value", [
    ("geoip_auto_reload_hours", 0),
    ("geoip_auto_reload_hours", 30),
    ("rate_limit_status", "200"),
    ("real_ip_header", "$http_x_forwarded_for"),
    ("real_ip_header", "X-Foo"),
    ("trusted_proxy_networks", ["0.0.0.0/0"]),
    ("trusted_proxy_networks", ["192.168.1.0/24", "192.168.1.0/24"]),
    ("log_exclude_networks", ["192.168.1.0/24; return 200"]),
    ("log_internal_requests", "false"),
    ("custom_error_pages_enabled", 1),
    ("security_response_headers_enabled", "yes"),
])
def test_extended_settings_reject_invalid_nginx_values(client, key, value):
    values = deepcopy(profiles.DEFAULTS)
    values[key] = value
    response = client.post("/security-profile/preview", json={"settings":values})
    assert response.status_code == 422, (key, response.text)


def test_prior_schema_revisions_are_still_editable_and_restorable(client):
    original_8 = {
        k: deepcopy(value) for k, value in profiles.DEFAULTS.items()
        if k in {
            "rate_limit_rps", "rate_limit_burst", "allowed_countries",
            "local_allowed_networks", "scanner_user_agents",
            "legacy_country_filter_enabled", "block_empty_user_agent",
            "legacy_refusal_status",
        }
    }
    original_8["rate_limit_rps"] = 65
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO security_profile_revisions
               (payload,hash,created_by,note,parent_revision)
               VALUES (?,?,?,?,?)""",
            (json.dumps(original_8), "a"*64, "admin", "Ancienne révision", 0),
        )
        conn.commit()
    current = client.get("/security-profile")
    assert current.status_code == 200, current.text
    loaded = current.json()
    assert loaded["revision"] == 1
    assert loaded["settings"]["rate_limit_rps"] == 65
    assert loaded["settings"]["rate_limit_status"] == "429"
    assert loaded["settings"]["log_internal_requests"] is True
    old = client.get("/security-profile/revisions/1")
    assert old.status_code == 200
    assert old.json()["settings"]["real_ip_header"] == "X-Real-IP"

    updated = dict(loaded["settings"])
    updated["rate_limit_status"] = "503"
    saved = client.post("/security-profile/revisions", json={
        "settings": updated, "expected_revision": 1,
        "note": "Ajouter statut de limitation",
    })
    assert saved.status_code == 200, saved.text

    restored = client.post("/security-profile/revisions/1/restore", json={
        "expected_revision": 2,
    })
    assert restored.status_code == 200, restored.text
    assert restored.json()["revision"] == 3
    now = client.get("/security-profile").json()
    assert now["settings"]["rate_limit_status"] == "429"
    assert now["settings"]["rate_limit_rps"] == 65
    with database.get_db() as conn:
        row = conn.execute(
            "SELECT payload FROM security_profile_revisions WHERE id=1"
        ).fetchone()
        assert json.loads(row["payload"]) == original_8


@pytest.mark.parametrize("changes", [
    {"scanner_rules_enabled":False, "sensitive_path_protection_enabled":False,
     "custom_error_pages_enabled":False, "rate_limit_enabled":False,
     "real_ip_header":"disabled"},
    {"rate_limit_rps":50, "rate_limit_burst":15,
     "log_internal_requests":False, "rate_limit_status":"503",
     "security_response_headers_enabled":True},
    {"geoip_auto_reload_hours":12, "trusted_proxy_networks":["192.168.1.254/32"],
     "real_ip_header":"X-Forwarded-For", "debug_geo_headers_enabled":False,
     "proxy_buffering_enabled":True, "proxy_intercept_errors_enabled":False},
])
def test_extended_compiler_passes_real_nginx_syntax(tmp_path, monkeypatch, changes):
    nginx = shutil.which("nginx")
    if not nginx:
        pytest.skip("Nginx not installed on runner")
    settings = deepcopy(profiles.DEFAULTS)
    settings.update(changes)
    compiled = profiles.render_profile(settings)
    http = tmp_path / "http-profile.conf"
    server = tmp_path / "server-profile.conf"
    http.write_text(compiled["http-security.conf"])
    server.write_text(compiled["server-security.conf"])

    spec = importlib.util.spec_from_file_location(
        "managed_nginx_fixture_v2", "tests/test_managed_nginx_profile.py"
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    monkeypatch.setattr(fixture, "HTTP", http)
    monkeypatch.setattr(fixture, "SERVER", server)
    conf, logfile = fixture.nginx_config(tmp_path, "block", 19091)
    # Production has only the profile's real_ip_header. The test's synthetic
    # GeoIP fixture declares a second one, which must be removed here.
    conf.write_text(conf.read_text().replace("real_ip_header X-Lab-IP;\n", ""))
    result = subprocess.run(
        [nginx, "-t", "-p", str(tmp_path), "-c", str(conf)],
        text=True, capture_output=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_configuration_ui_groups_settings_for_readability():
    html = Path("templates/dashboard.html").read_text()
    css = Path("static/dashboard.css").read_text()
    js = Path("static/dashboard.js").read_text()
    assert 'id="nsd-profile-fields"' in html
    assert "nsd-settings-group" in css
    assert "spec.group || 'Autres'" in js
    assert "<fieldset class=" in js
