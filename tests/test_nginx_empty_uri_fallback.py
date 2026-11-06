"""The stored request path and threat classifier must use the same fallback."""
import json

from services.log_parser import parse_line


def test_empty_custom_uri_uses_native_request_uri():
    event = parse_line(json.dumps({
        "uri": "",
        "request_uri": "/.env",
        "remote_addr": "203.0.113.10",
        "status": 404,
        "http_user_agent": "Mozilla/5.0",
    }))
    assert event is not None
    assert event["uri"] == "/.env"
    assert event["threat"] == "secret_discovery"


def test_custom_uri_takes_precedence_over_native():
    event = parse_line(json.dumps({
        "uri": "/health",
        "request_uri": "/.env",
        "status": 200,
        "http_user_agent": "Mozilla/5.0",
    }))
    assert event is not None
    assert event["uri"] == "/health"
    assert event["threat"] == "normal"
