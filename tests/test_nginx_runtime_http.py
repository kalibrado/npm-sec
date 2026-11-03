"""Real HTTP regression tests for generated NPM Security Nginx policies.

This is a disposable local Nginx instance. It never contacts a live NPM,
does not require Docker, and only accepts requests on 127.0.0.1.
The forwarded IP and country headers are accepted solely by this test
fixture; production must derive them from trusted proxies and GeoIP2.
"""
import http.client
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

import database
from services import export, ingestion, observation


HOST_CLOUD = "cloud.kaliorbis.fr"
HOST_JELLYFIN = "jellyfin.kaliorbis.fr"


@pytest.fixture(params=["block", "host-observe", "global-observe"])
def nginx_policy_server(tmp_path, request):
    nginx = shutil.which("nginx")
    if nginx is None:
        pytest.skip("Nginx executable not installed")

    blocked = [
        {"type": "cidr", "value": "198.51.100.0/25", "host": ""},
        {"type": "ip", "value": "198.51.100.99", "host": ""},
        {"type": "cidr", "value": "203.0.113.0/24", "host": HOST_CLOUD},
        {"type": "ip", "value": "203.0.114.7", "host": HOST_JELLYFIN},
        {"type": "country", "value": "CN", "host": HOST_CLOUD},
        {"type": "country", "value": "RU", "host": ""},
    ]
    trusted = [
        {"type": "ip", "value": "203.0.113.42"},
        {"type": "ip", "value": "198.51.100.25"},
        {"type": "cidr", "value": "192.0.2.0/29"},
    ]
    http_snippet = tmp_path / "npm-blocklist.conf"
    guard_snippet = tmp_path / "npm-server-guard.conf"
    modes = (
        {HOST_CLOUD: "observe"} if request.param == "host-observe"
        else {"": "observe", HOST_JELLYFIN: "block"} if request.param == "global-observe"
        else None
    )
    http_snippet.write_text(
        export.render_nginx_blocklist(blocked, trusted, modes), encoding="utf-8"
    )
    guard_snippet.write_text(export.render_nginx_server_guard(), encoding="utf-8")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    conf = tmp_path / "nginx.conf"
    nginx_log = tmp_path / "nginx-error.log"
    access_log = tmp_path / "nginx-access.jsonl"
    # Realip is deliberately restricted to loopback, where this test
    # runs. Country is a test-only GeoIP2 stub, not a production setting.
    conf.write_text(
        f"""worker_processes 1;
error_log {nginx_log} notice;
pid {tmp_path / "nginx.pid"};
events {{ worker_connections 64; }}
http {{
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;

    map $http_x_lab_country $geoip2_data_country_code {{
        default "";
        CN CN;
        RU RU;
        FR FR;
    }}

    include {http_snippet};
    map $npm_security_deny $npm_sec_allowed {{
        default "yes";
        1 "no";
    }}
    log_format security_json escape=json
        '{{"timestamp":"$time_iso8601",'
        '"remote_addr":"$remote_addr",'
        '"host":"$host",'
        '"uri":"$request_uri",'
        '"status":"$status",'
        '"allowed":"$npm_sec_allowed",'
        '"http_user_agent":"$http_user_agent",'
        '"country_code":"$geoip2_data_country_code",'
        '"npm_security_policy_mode":"$npm_security_policy_mode",'
        '"npm_security_would_deny":"$npm_security_would_deny"}}';
    access_log {access_log} security_json;

    server {{
        listen 127.0.0.1:{port};
        server_name {HOST_CLOUD};
        include {guard_snippet};
        location / {{ return 204; }}
    }}
    server {{
        listen 127.0.0.1:{port};
        server_name {HOST_JELLYFIN};
        include {guard_snippet};
        location / {{ return 204; }}
    }}
}}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [nginx, "-t", "-p", str(tmp_path), "-c", str(conf)],
        text=True, capture_output=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr

    with (tmp_path / "worker-output.log").open("wb") as output:
        process = subprocess.Popen(
            [nginx, "-p", str(tmp_path), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                if process.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Disposable Nginx did not start")

            assert process.poll() is None, (
                f"Nginx exited early: {nginx_log.read_text() if nginx_log.exists() else ''}"
            )
            yield port, request.param, access_log
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def request_status(port, ip, host, country="FR"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(
            "GET", "/",
            headers={
                "Host": host,
                "X-Forwarded-For": ip,
                "X-Lab-Country": country,
            },
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


@pytest.mark.parametrize(
    "ip,host,country,expected",
    [
        ("203.0.113.41", HOST_CLOUD, "FR", 403),  # CIDR only on Nextcloud
        ("203.0.113.41", HOST_JELLYFIN, "FR", 204),
        ("203.0.113.42", HOST_CLOUD, "FR", 204),  # IP trusted override
        ("203.0.113.42", HOST_CLOUD, "CN", 204),  # Trust overrides country
        ("203.0.114.7", HOST_JELLYFIN, "FR", 403),  # Jellyfin-only IP
        ("203.0.114.7", HOST_CLOUD, "FR", 204),
        ("198.51.100.20", HOST_CLOUD, "FR", 403),  # Global CIDR
        ("198.51.100.20", HOST_JELLYFIN, "FR", 403),
        ("198.51.100.25", HOST_CLOUD, "FR", 204),  # Trust inside CIDR
        ("198.51.100.25", HOST_JELLYFIN, "RU", 204),
        ("198.51.100.99", HOST_CLOUD, "FR", 403),  # Global exact IP
        ("198.51.100.99", HOST_JELLYFIN, "FR", 403),
        ("192.0.2.44", HOST_CLOUD, "CN", 403),  # Country only on Nextcloud
        ("192.0.2.44", HOST_JELLYFIN, "CN", 204),
        ("192.0.2.44", HOST_JELLYFIN, "RU", 403),  # Global country
        ("192.0.2.44", HOST_CLOUD, "FR", 204),
        ("192.0.2.4", HOST_CLOUD, "RU", 204),  # Trusted network
        ("10.0.0.5", HOST_CLOUD, "RU", 204),  # Internal network
    ],
)
def test_nginx_real_http_policy_decision(nginx_policy_server, ip, host, country, expected):
    port, mode, _ = nginx_policy_server
    actual = request_status(port, ip, host, country)
    # Two independent configurations demonstrate both an exact-host
    # OBSERVE override and a global OBSERVE default with a BLOCK exception.
    if mode != "block" and host == HOST_CLOUD and expected == 403:
        expected = 204
    assert actual == expected, (
        f"mode={mode}, host={host}, ip={ip}, country={country}: "
        f"expected {expected}, got {actual}"
    )


def test_live_nginx_json_log_to_ingestion_incident_and_alert(
    nginx_policy_server, tmp_path, monkeypatch
):
    """Nginx decision -> access JSON -> SQLite -> alert, without NPM deployment.

    This validates the actual Nginx HTTP variables and log formatting.
    GeoIP is deliberately a test-only map, not the native GeoIP2 module.
    """
    port, mode, access_log = nginx_policy_server
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "observation-integration.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "integration-only-strong-password")
    monkeypatch.setattr(observation, "OBSERVE_ALERT_ENABLED", True)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_THRESHOLD", 3)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_WINDOW_MINUTES", 5)
    monkeypatch.setattr(observation, "OBSERVE_ALERT_COOLDOWN_MINUTES", 15)
    database.init_db()

    # A CIDR scoped to cloud would reject this IP in BLOCK. On Observe,
    # Nginx forwards the request but logs would_deny=1 and mode=observe.
    statuses = [
        request_status(port, "203.0.113.41", HOST_CLOUD, "FR")
        for _ in range(3)
    ]
    observing_cloud = mode != "block"
    assert statuses == ([204] if observing_cloud else [403]) * 3

    lines = [
        json.loads(line)
        for line in access_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    records = [row for row in lines if row.get("remote_addr") == "203.0.113.41"]
    assert len(records) == 3
    assert all(row["npm_security_would_deny"] == "1" for row in records)
    assert all(
        row["npm_security_policy_mode"] == ("observe" if observing_cloud else "block")
        for row in records
    )
    assert all(
        row["allowed"] == ("yes" if observing_cloud else "no") for row in records
    )

    # This is the same persisted cursor ingestion used by the app in production.
    ingested = ingestion.ingest_file_once(access_log)
    assert ingested == len(lines)
    with database.get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM observation_incidents").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM observation_alerts").fetchone()[0]
        if observing_cloud:
            incident = conn.execute(
                "SELECT hits, status, last_country FROM observation_incidents"
            ).fetchone()
            assert tuple(incident) == (3, "open", "FR")
        else:
            assert conn.execute(
                "SELECT COUNT(*) FROM access_logs WHERE blocked=1"
            ).fetchone()[0] == 3
    assert count == (1 if observing_cloud else 0)
    assert alerts == (1 if observing_cloud else 0)

    # Replaying a checkpoint cannot send duplicate alert notifications.
    with database.get_db() as conn:
        conn.execute("UPDATE ingestion_state SET byte_offset=0")
        conn.commit()
    assert ingestion.ingest_file_once(access_log) == 0
    with database.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM observation_alerts").fetchone()[0] == alerts


def test_live_geo_country_observe_log_carries_policy_signal(nginx_policy_server):
    """Country signal is generated inside Nginx, never from application rules."""
    port, mode, access_log = nginx_policy_server
    ip = "192.0.2.44"  # deliberately not part of the trusted /29 network
    expected = 403 if mode == "block" else 204
    assert request_status(port, ip, HOST_CLOUD, country="CN") == expected
    lines = [json.loads(line) for line in access_log.read_text().splitlines() if line]
    latest = [line for line in lines if line.get("remote_addr") == ip][-1]
    assert latest["npm_security_would_deny"] == "1"
    assert latest["npm_security_policy_mode"] == ("block" if mode == "block" else "observe")
    assert latest["country_code"] == "CN"
