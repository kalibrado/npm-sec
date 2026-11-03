"""Validate the Git-managed NPM security profile using a disposable real Nginx.

Country values in this test are synthetic: production still requires GeoIP2.
"""
import http.client
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from services.export import render_nginx_blocklist, render_nginx_server_guard

ROOT = Path(__file__).resolve().parents[1]
HTTP = ROOT / "config/nginx-managed/http-security.conf"
SERVER = ROOT / "config/nginx-managed/server-security.conf"
MIGRATE = ROOT / "scripts/npm-sec-migrate-nginx.py"


def test_migrated_profile_retains_security_rules_without_overlapping_dynamic_if():
    http = HTTP.read_text()
    server = SERVER.read_text()
    for name in ["GeoLite2-Country.mmdb", "GeoLite2-City.mmdb",
                 "GeoLite2-ASN.mmdb", "set_real_ip_from 192.168.1.0/24",
                 "FR yes;", "192.168.1.0/24 yes;", "rate=100r/s",
                 "masscan", "zgrab", "nikto", "sqlmap", "nmap",
                 "libredtail", "nuclei", "dirbuster", "gobuster"]:
        assert name in http
    assert http.count("include /data/nginx/custom/npm-security/npm-blocklist.conf;") == 1
    assert server.count("include /data/nginx/custom/npm-security/npm-server-guard.conf;") == 1
    assert "if ($npm_security_blocked_ip" not in server
    assert "if ($npm_security_blocked_country" not in server
    for name in ["burst=70", "limit_req_status 429", "error_page 403",
                 "proxy_intercept_errors on", "proxy_buffering off",
                 "location /error_pages/", "wp-login", "xmlrpc", "return 444;"]:
        assert name in server
    assert "log_format detailed_visitor escape=json" in http
    assert '"npm_security_policy_mode":"$npm_security_policy_mode"' in http
    assert '"npm_security_would_deny":"$npm_security_would_deny"' in http
    assert '"allowed":"$npm_security_effective_allowed"' in http
    assert server.count("proxy_set_header Host ") == 1


def test_migration_has_read_only_plan_and_rejects_unconfirmed_apply():
    plan = subprocess.run([sys.executable, str(MIGRATE)],
                          capture_output=True, text=True, timeout=10)
    assert plan.returncode == 0, plan.stderr
    assert "PLAN UNIQUEMENT" in plan.stdout
    assert "http-security.conf" in plan.stdout
    assert "server-security.conf" in plan.stdout
    refused = subprocess.run([sys.executable, str(MIGRATE), "--apply"],
                             capture_output=True, text=True, timeout=10)
    assert refused.returncode != 0
    assert "MIGRER_NPM_SEC" in refused.stderr
    apply = (ROOT / "scripts/npm-sec-apply.sh").read_text()
    assert "check_hook" in apply
    assert '"$TARGET/http-security.conf"' in apply
    assert '"$TARGET/server-security.conf"' in apply


def nginx_config(tmp, mode, port):
    http = HTTP.read_text()
    server = SERVER.read_text()
    http = re.sub(r"(?ms)^geoip2\s+\S+\.mmdb\s*\{.*?^\}",
                  "# GeoIP2 replaced in test only", http)
    assert "geoip2 /var/lib/geoip" not in http

    geo = """set_real_ip_from 127.0.0.1;
real_ip_header X-Lab-IP;
map $http_x_lab_country $geoip2_data_country_code {
    default XX; FR FR; CN CN;
}
"""
    for var, default in [
        ("country_name", "Unknown"), ("city_name", "Lab"),
        ("region_name", "Lab"), ("postal_code", "00000"),
        ("latitude", "0"), ("longitude", "0"),
        ("asn", "0"), ("isp", "Lab"),
    ]:
        geo += "map $http_x_lab_country $geoip2_data_" + var + f" {{ default {default}; }}\n"

    blocklist = tmp / "npm-blocklist.conf"
    guard = tmp / "npm-server-guard.conf"
    blocklist.write_text(render_nginx_blocklist(
        [{"type":"ip", "value":"198.51.100.44", "host":""}],
        policy_modes={"":mode},
    ))
    guard.write_text(render_nginx_server_guard())
    http = http.replace(
        "/data/nginx/custom/npm-security/npm-blocklist.conf", str(blocklist))
    server = server.replace(
        "/data/nginx/custom/npm-security/npm-server-guard.conf", str(guard))

    errors = tmp / "errors"
    errors.mkdir()
    for status in [400,401,403,404,405,407,408,409,410,411,412,
                   413,416,418,429,500,502,503,504,505]:
        (errors / f"{status}.html").write_text("test error")
    server = server.replace("/data/nginx/error_pages/ghost/", f"{errors}/")
    detailed = tmp / "detailed.jsonl"
    custom = tmp / "access-custom.log"
    for original, new in [
        ("/data/logs/access-geo-detailed.log", str(detailed)),
        ("/data/logs/access-custom.log", str(custom)),
    ]:
        http = http.replace(original, new)
        server = server.replace(original, new)

    http_path = tmp / "managed-http.conf"
    server_path = tmp / "managed-server.conf"
    http_path.write_text(http)
    server_path.write_text(server)
    conf = tmp / "nginx.conf"
    conf.write_text(f"""worker_processes 1;
error_log {tmp / "nginx-error.log"} notice;
pid {tmp / "nginx.pid"};
events {{ worker_connections 64; }}
http {{
{geo}
include {http_path};
server {{
    listen 127.0.0.1:{port};
    server_name cloud.kaliorbis.fr;
    include {server_path};
    location / {{ return 204; }}
}}
}}
""")
    return conf, detailed


@pytest.fixture(params=["block", "observe"])
def nginx_managed(tmp_path, request):
    nginx = shutil.which("nginx")
    if not nginx:
        pytest.skip("Nginx is not available on the test runner")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    conf, detailed = nginx_config(tmp_path, request.param, port)
    test = subprocess.run([nginx, "-t", "-p", str(tmp_path), "-c", str(conf)],
                          capture_output=True, text=True, timeout=15)
    assert test.returncode == 0, test.stderr
    with (tmp_path / "nginx-worker.log").open("wb") as output:
        worker = subprocess.Popen(
            [nginx, "-p", str(tmp_path), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                if worker.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            assert worker.poll() is None, (tmp_path / "nginx-worker.log").read_text()
            yield port, request.param, detailed
        finally:
            if worker.poll() is None:
                worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)


def request(port, ip, country="FR", agent="LabBrowser"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", "/", headers={
            "Host":"cloud.kaliorbis.fr", "X-Lab-IP":ip,
            "X-Lab-Country":country, "User-Agent":agent,
        })
        try:
            response = conn.getresponse()
            response.read()
            return response.status
        except http.client.RemoteDisconnected:
            return 444
    finally:
        conn.close()


def latest(log):
    for _ in range(30):
        if log.exists() and log.stat().st_size:
            break
        time.sleep(.05)
    items = [json.loads(line) for line in log.read_text().splitlines() if line]
    assert items
    return items[-1]


def test_country_ua_and_dynamic_policy_have_correct_live_behavior(nginx_managed):
    port, mode, logfile = nginx_managed
    assert request(port,"203.0.113.20") == 204
    assert latest(logfile)["allowed"] == "yes"

    assert request(port,"198.51.100.44") == (403 if mode == "block" else 204)
    entry = latest(logfile)
    assert entry["npm_security_policy_mode"] == mode
    assert entry["npm_security_would_deny"] == "1"
    assert entry["npm_security_deny"] == ("1" if mode == "block" else "0")
    assert entry["allowed"] == ("no" if mode == "block" else "yes")

    assert request(port,"203.0.113.20",country="CN") == 444
    assert latest(logfile)["allowed"] == "no"
    assert request(port,"203.0.113.20",agent="sqlmap/1.0") == 444
    assert latest(logfile)["blocked_agent"] == "1"
    assert request(port,"192.168.1.22",country="CN") == 204


def test_json_preserves_existing_columns_and_adds_observation(nginx_managed):
    port, _, logfile = nginx_managed
    assert request(port,"203.0.113.23") == 204
    item = latest(logfile)
    for key in [
        "timestamp", "remote_addr", "method", "uri", "host", "status",
        "request_time", "http_user_agent", "country_code", "country_name",
        "asn", "isp", "allowed", "blocked_agent",
        "npm_security_policy_mode", "npm_security_would_deny",
    ]:
        assert key in item
    assert item["status"] == 204
