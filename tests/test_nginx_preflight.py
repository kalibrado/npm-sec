"""Read-only NPM / GeoIP2 preflight checks without Docker or network."""
import json
import subprocess
import sys
from pathlib import Path

from services.nginx_preflight import analyze_nginx_dump


BASE_CONFIG = """
# configuration file /etc/nginx/nginx.conf:
http {
    include /data/nginx/custom/npm-security/npm-blocklist.conf;
    include /data/nginx/custom/npm-security/npm-server-guard.conf;
    map $host $npm_security_policy_mode { default block; }
    map "$npm_security_trusted_ip:$npm_security_any_block" $npm_security_would_deny {
        default 0; "0:1" 1;
    }
    map "$npm_security_policy_mode:$npm_security_would_deny" $npm_security_deny {
        default 0; "block:1" 1;
    }
    log_format npm_json escape=json
      '{"timestamp":"$time_iso8601",'
      '"remote_addr":"$remote_addr",'
      '"host":"$host",'
      '"status":"$status",'
      '"npm_security_policy_mode":"$npm_security_policy_mode",'
      '"npm_security_would_deny":"$npm_security_would_deny"}';
    access_log /data/logs/access-geo-detailed.log npm_json;
}
"""


def states(report):
    return {check["id"]: check["status"] for check in report["checks"]}


def test_ready_for_observation_without_country_blocks():
    report = analyze_nginx_dump(BASE_CONFIG)
    assert report["required_checks_pass"] is True
    assert report["ready_for_log_integration"] is True
    assert report["ready_for_country_policy"] is True
    assert report["country_rules_detected"] is False
    assert states(report)["geoip2_country_variable"] == "warning"
    assert states(report)["instrumented_access_log"] == "pass"
    assert states(report)["real_client_ip_review"] == "warning"
    assert "nginx_configuration_dump_only" == report["source"]


def test_declared_but_inactive_log_format_is_not_ready():
    text = BASE_CONFIG.replace(
        "access_log /data/logs/access-geo-detailed.log npm_json;",
        "access_log /data/logs/access-geo-detailed.log combined;",
    )
    report = analyze_nginx_dump(text)
    assert report["ready_for_log_integration"] is False
    assert report["required_checks_pass"] is False
    assert states(report)["instrumented_access_log"] == "fail"


def test_partial_json_log_instrumentation_is_rejected():
    text = BASE_CONFIG.replace(
        ''"npm_security_would_deny":"$npm_security_would_deny"'}',
        ''"request_time":"$request_time"'}',
    )
    result = analyze_nginx_dump(text)
    assert states(result)["instrumented_access_log"] == "fail"
    assert result["required_checks_pass"] is False


def test_missing_proxy_includes_fails_without_claiming_safety():
    text = BASE_CONFIG.replace(
        "include /data/nginx/custom/npm-security/npm-server-guard.conf;",
        "# missing guard configuration",
    )
    result = analyze_nginx_dump(text)
    assert states(result)["server_guard_include"] == "fail"
    assert result["required_checks_pass"] is False


def test_geoip2_country_policy_requires_country_variable_and_mmdb():
    country_map = """
    map $geoip2_data_country_code $npm_security_blocked_country {
        default 0;
        CN 1;
    }
    """
    missing_geo = analyze_nginx_dump(BASE_CONFIG + country_map)
    assert missing_geo["country_rules_detected"] is True
    assert missing_geo["required_checks_pass"] is False
    assert states(missing_geo)["geoip2_country_variable"] == "fail"

    geoip = """
    geoip2 /data/geoip2/GeoLite2-Country.mmdb {
        $geoip2_data_country_code country iso_code;
    }
    """
    without_db = analyze_nginx_dump(BASE_CONFIG + country_map + geoip, geoip_db_readable=False)
    assert without_db["required_checks_pass"] is False
    assert states(without_db)["geoip2_country_variable"] == "pass"
    assert states(without_db)["geoip2_database"] == "fail"

    with_db = analyze_nginx_dump(BASE_CONFIG + country_map + geoip, geoip_db_readable=True)
    assert with_db["ready_for_country_policy"] is True
    assert with_db["required_checks_pass"] is True


def test_http_real_ip_is_never_assumed_safe_just_from_config():
    real_ip = (
        "real_ip_header X-Forwarded-For;\n"
        "set_real_ip_from 0.0.0.0/0;\n"
    )
    result = analyze_nginx_dump(BASE_CONFIG + real_ip)
    assert states(result)["real_client_ip_review"] == "warning"
    assert "vérifier" in next(
        check["description"].lower()
        for check in result["checks"] if check["id"] == "real_client_ip_review"
    )


def test_cli_offline_json_and_missing_required_check(tmp_path):
    config_file = tmp_path / "nginx-dump.txt"
    config_file.write_text(BASE_CONFIG, encoding="utf-8")
    path = Path("scripts/npm-sec-preflight.py")
    ok = subprocess.run(
        [sys.executable, str(path), "--config-dump", str(config_file), "--json"],
        capture_output=True, text=True, timeout=10,
    )
    assert ok.returncode == 0, ok.stderr
    data = json.loads(ok.stdout)
    assert data["inspection_mode"] == "offline"
    assert data["required_checks_pass"] is True

    config_file.write_text(
        BASE_CONFIG.replace("escape=json", "escape=none"), encoding="utf-8"
    )
    not_ready = subprocess.run(
        [sys.executable, str(path), "--config-dump", str(config_file), "--json"],
        capture_output=True, text=True, timeout=10,
    )
    assert not_ready.returncode == 1
    assert json.loads(not_ready.stdout)["required_checks_pass"] is False


def test_cli_offline_country_database_check(tmp_path):
    country = """
    map $geoip2_data_country_code $npm_security_blocked_country {
        default 0; RU 1;
    }
    geoip2 /data/geoip2/GeoLite2-Country.mmdb {
        $geoip2_data_country_code country iso_code;
    }
    """
    conf = tmp_path / "dump.txt"
    conf.write_text(BASE_CONFIG + country)
    db = tmp_path / "GeoLite2-Country.mmdb"
    db.write_bytes(b"dummy")
    run = subprocess.run(
        [sys.executable, "scripts/npm-sec-preflight.py",
         "--config-dump", str(conf), "--geoip-db-file", str(db), "--json"],
        capture_output=True, text=True, timeout=10,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["ready_for_country_policy"] is True
