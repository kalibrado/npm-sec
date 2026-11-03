"""Scoped blocking preserves global rules and never leaks rules across hosts."""
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import export


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_file = tmp_path / "policy.db"
    monkeypatch.setattr(database, "DB_FILE", db_file)
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "temporary-admin-domain-test")
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path / "exports")
    database.init_db()
    c = TestClient(app)
    login = c.post(
        "/auth/login",
        json={"username": "admin", "password": "temporary-admin-domain-test"},
    )
    assert login.status_code == 200, login.text
    return c


def test_existing_global_rules_are_migrated_without_changes(tmp_path, monkeypatch):
    db_file = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_file)
    conn.execute(
        """CREATE TABLE blocklist (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           type TEXT NOT NULL,
           value TEXT NOT NULL,
           reason TEXT DEFAULT '',
           created_at TEXT DEFAULT (datetime('now')),
           expires_at TEXT,
           UNIQUE(type, value)
        )"""
    )
    conn.execute(
        """INSERT INTO blocklist(type,value,reason,expires_at)
           VALUES ('country','CN','legacy ban','2031-01-01 00:00:00')"""
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(database, "DB_FILE", db_file)
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "migration-admin-test")
    database.init_db()
    database.init_db()

    with database.get_db() as conn:
        old = conn.execute(
            "SELECT id,type,value,reason,expires_at,host FROM blocklist"
        ).fetchone()
        assert dict(old) == {
            "id": 1, "type": "country", "value": "CN",
            "reason": "legacy ban", "expires_at": "2031-01-01 00:00:00",
            "host": "",
        }
        conn.execute(
            """INSERT INTO blocklist(type,value,host)
               VALUES ('country','CN','cloud.kaliorbis.fr')"""
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0] == 2


def test_same_ip_can_be_blocked_for_two_hosts_without_global_block(env):
    for host in ("cloud.kaliorbis.fr", "jellyfin.kaliorbis.fr"):
        r = env.post(
            "/blocklist",
            json={
                "type": "ip",
                "value": "203.0.113.8",
                "host": host,
                "duration_minutes": 60,
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["host"] == host
        assert r.json()["pending_apply"] is True

    all_rules = env.get("/blocklist").json()
    assert len(all_rules) == 2
    assert all(item["host"] for item in all_rules)
    global_rules = env.get("/blocklist?host=").json()
    assert global_rules == []
    only_cloud = env.get("/blocklist?host=cloud.kaliorbis.fr").json()
    assert len(only_cloud) == 1
    assert only_cloud[0]["host"] == "cloud.kaliorbis.fr"

    conf = env.get("/blocklist/export/nginx").text
    assert "geo $npm_security_blocked_ip {" in conf
    assert "geo $npm_security_scoped_ip_1 {" in conf
    assert "geo $npm_security_scoped_ip_2 {" in conf
    assert "    cloud.kaliorbis.fr $npm_security_scoped_ip_1;" in conf
    assert "    jellyfin.kaliorbis.fr $npm_security_scoped_ip_2;" in conf


def test_host_scoped_country_generates_exact_host_geoip_key(env):
    a = env.post(
        "/blocklist",
        json={"type": "country", "value": "CN", "host": "cloud.kaliorbis.fr"},
    )
    assert a.status_code == 200, a.text
    b = env.post(
        "/blocklist",
        json={"type": "country", "value": "RU"},
    )
    assert b.status_code == 200, b.text
    conf = env.get("/blocklist/export/nginx").text
    assert '"cloud.kaliorbis.fr:CN" 1;' in conf
    assert '    RU 1;' in conf
    assert '    CN 1;' not in conf  # CN is scoped, not global


@pytest.mark.parametrize(
    "host",
    ["https://cloud.kaliorbis.fr", "cloud.kaliorbis.fr:443", "*.example.com",
     "bad host", "a;return 200", "example.com\nreturn", "exa_mple.com",
     "bad..example.com", "💥.example.com"],
)
def test_malformed_host_rejected_before_config_write(env, host):
    response = env.post(
        "/blocklist",
        json={"type": "country", "value": "CN", "host": host},
    )
    assert response.status_code == 422, (host, response.text)
    assert env.get("/blocklist").json() == []


def test_hostname_canonicalization_and_scoped_shortcuts(env):
    r = env.post(
        "/block_ip/203.0.113.20?host=CLOUD.KALIORBIS.FR.&duration_minutes=60"
    )
    assert r.status_code == 200, r.text
    assert r.json()["host"] == "cloud.kaliorbis.fr"
    cc = env.post("/block_country/CN?host=jellyfin.kaliorbis.fr")
    assert cc.status_code == 200, cc.text
    assert cc.json()["host"] == "jellyfin.kaliorbis.fr"


def test_nginx_config_syntax_for_global_and_scoped_policy(tmp_path):
    if not shutil.which("nginx"):
        pytest.skip("nginx is unavailable in local environment")
    conf_text = export.render_nginx_blocklist(
        [
            {"type": "ip", "value": "198.51.100.9", "host": ""},
            {"type": "cidr", "value": "203.0.113.0/24", "host": "cloud.kaliorbis.fr"},
            {"type": "country", "value": "CN", "host": "cloud.kaliorbis.fr"},
            {"type": "country", "value": "RU", "host": ""},
        ],
        [{"type": "ip", "value": "192.0.2.2"}],
    )
    policy = tmp_path / "blocklist.conf"
    guard = tmp_path / "guard.conf"
    policy.write_text(conf_text, encoding="utf-8")
    guard.write_text(export.render_nginx_server_guard(), encoding="utf-8")
    # Stub the GeoIP variable only for a syntax test; production needs GeoIP2.
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text(
        f"""worker_processes 1;
error_log stderr warn;
pid {tmp_path / 'nginx.pid'};
events {{ worker_connections 16; }}
http {{
    map $host $geoip2_data_country_code {{ default US; }}
    include {policy};
    server {{
        listen 127.0.0.1:18781;
        server_name cloud.kaliorbis.fr;
        include {guard};
        return 200 "ok";
    }}
}}
""",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["nginx", "-t", "-c", str(nginx_conf), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_frontend_has_domain_scope_controls():
    html = Path("templates/dashboard.html").read_text()
    js = Path("static/dashboard.js").read_text()
    assert 'id="lists-block-host"' in html
    assert 'id="bl-host"' in html
    assert "host:host" in js or "duration_minutes, host" in js
    assert "item.host" in js
