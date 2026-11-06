"""Nginx JSON log formats may use native variable names."""
import json

from services.log_parser import parse_line


def test_nginx_native_request_method_and_host_are_supported():
    event = parse_line(json.dumps({
        "remote_addr": "192.0.2.40",
        "time_iso8601": "2026-11-06T03:00:00+01:00",
        "request_method": "POST",
        "http_host": "CLOUD.KALIORBIS.FR.",
        "request_uri": "/login",
        "status": "401",
    }))
    assert event is not None
    assert event["method"] == "POST"
    assert event["host"] == "cloud.kaliorbis.fr"
    assert event["uri"] == "/login"
    assert event["status"] == 401


def test_explicit_fields_take_precedence_over_native_fallbacks():
    event = parse_line(json.dumps({
        "method": "GET", "request_method": "POST",
        "host": "example.org", "http_host": "other.example",
        "status": 200,
    }))
    assert event is not None
    assert event["method"] == "GET"
    assert event["host"] == "example.org"


def test_missing_fields_keep_safe_defaults():
    event = parse_line(json.dumps({"status": 200}))
    assert event is not None
    assert event["method"] == "-"
    assert event["host"] == "-"
