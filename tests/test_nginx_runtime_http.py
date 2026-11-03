"""Real HTTP regression tests for generated NPM Security Nginx policies.

This is a disposable local Nginx instance. It never contacts a live NPM,
does not require Docker, and only accepts requests on 127.0.0.1.
The forwarded IP and country headers are accepted solely by this test
fixture; production must derive them from trusted proxies and GeoIP2.
"""
import http.client
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from services import export


HOST_CLOUD = "cloud.kaliorbis.fr"
HOST_JELLYFIN = "jellyfin.kaliorbis.fr"


@pytest.fixture
def nginx_policy_server(tmp_path):
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
    http_snippet.write_text(export.render_nginx_blocklist(blocked, trusted), encoding="utf-8")
    guard_snippet.write_text(export.render_nginx_server_guard(), encoding="utf-8")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    conf = tmp_path / "nginx.conf"
    nginx_log = tmp_path / "nginx-error.log"
    # Realip is deliberately restricted to loopback, where this test
    # runs. Country is a test-only GeoIP2 stub, not a production setting.
    conf.write_text(
        f"""worker_processes 1;
error_log {nginx_log} notice;
pid {tmp_path / "nginx.pid"};
events {{ worker_connections 64; }}
http {{
    access_log off;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;

    map $http_x_lab_country $geoip2_data_country_code {{
        default "";
        CN CN;
        RU RU;
        FR FR;
    }}

    include {http_snippet};
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
            yield port
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
    actual = request_status(nginx_policy_server, ip, host, country)
    assert actual == expected, (
        f"host={host}, ip={ip}, country={country}: expected {expected}, got {actual}"
    )
