"""Native Nginx request_uri must be used consistently for threat classification."""
import json

from services.log_parser import parse_line


def test_native_request_uri_classifies_sensitive_path():
    event = parse_line(json.dumps({
        "remote_addr": "203.0.113.10",
        "request_uri": "/.env",
        "request_method": "GET",
        "status": 404,
        "http_user_agent": "Mozilla/5.0",
    }))
    assert event is not None
    assert event["uri"] == "/.env"
    assert event["threat"] == "secret_discovery"


def test_explicit_uri_controls_classification():
    event = parse_line(json.dumps({
        "uri": "/health",
        "request_uri": "/.env",
        "http_user_agent": "Mozilla/5.0",
        "status": 200,
    }))
    assert event is not None
    assert event["uri"] == "/health"
    assert event["threat"] == "normal"
