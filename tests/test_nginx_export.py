"""Regression tests for generated IP/country policy and deployment evidence."""
import hashlib
import json

import pytest

from services import export, deployment


def test_ip_cidr_policy_enforces_and_trust_overrides():
    conf = export.render_nginx_blocklist(
        [
            {"type": "ip", "value": "203.0.113.4"},
            {"type": "cidr", "value": "198.51.100.0/24"},
        ],
        [{"type": "ip", "value": "203.0.113.17"}],
    )
    assert "geo $npm_security_blocked_ip" in conf
    assert "203.0.113.4 1;" in conf
    assert "198.51.100.0/24 1;" in conf
    assert "geo $npm_security_trusted_ip" in conf
    assert "203.0.113.17 1;" in conf
    assert 'map "$npm_security_trusted_ip:$npm_security_any_block" $npm_security_deny' in conf
    assert '    "0:1" 1;' in conf
    assert "    ~1 1;" in conf
    assert "map $host $npm_security_blocked_country" in conf
    assert "map $geoip2_data_country_code" not in conf
    assert "if ($npm_security_deny) { return 403; }" in export.render_nginx_server_guard()


def test_geoblock_uses_geoip2_only_when_needed():
    conf = export.render_nginx_blocklist(
        [{"type": "country", "value": "CN"}, {"type": "country", "value": "RU"}]
    )
    assert "map $geoip2_data_country_code" in conf
    assert "CN 1;" in conf
    assert "RU 1;" in conf


def test_invalid_ip_or_country_does_not_produce_nginx_directives():
    with pytest.raises(ValueError):
        export.render_nginx_blocklist([{"type": "ip", "value": "1.2.3.4; return 200;"}])
    with pytest.raises(ValueError):
        export.render_nginx_blocklist([{"type": "country", "value": "FR;"}])


def test_policy_is_pending_until_matching_apply_hash(monkeypatch, tmp_path):
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path)
    monkeypatch.setattr(deployment, "EXPORT_DIR", tmp_path)
    export.write_blocklist_exports([{"type": "ip", "value": "203.0.113.2"}], [])
    pending = deployment.get_policy_deployment_status()
    assert pending["state"] == "pending"
    digest = pending["generated_hash"]
    (tmp_path / "deployment-status.json").write_text(
        json.dumps(
            {
                "status": "applied",
                "applied_hash": digest,
                "applied_at": "2026-11-03T00:00:00+00:00",
                "container": "npm",
            }
        )
    )
    assert deployment.get_policy_deployment_status()["state"] == "applied"
    export.write_blocklist_exports([{"type": "ip", "value": "203.0.113.3"}], [])
    assert deployment.get_policy_deployment_status()["state"] == "pending"
