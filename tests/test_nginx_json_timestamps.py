"""Nginx JSON access logs may use time_iso8601 instead of timestamp."""
import json

from services.log_parser import parse_line


def test_nginx_iso8601_timestamp_is_preserved():
    event = parse_line(json.dumps({
        "time_iso8601": "2026-11-06T02:20:30+01:00",
        "remote_addr": "192.0.2.10",
        "uri": "/health",
        "status": 200,
    }))
    assert event is not None
    assert event["timestamp"] == "2026-11-06T02:20:30+01:00"


def test_explicit_timestamp_takes_precedence():
    event = parse_line(json.dumps({
        "timestamp": "2026-11-05T22:00:00+01:00",
        "time_iso8601": "2026-11-06T02:20:30+01:00",
        "status": 200,
    }))
    assert event["timestamp"] == "2026-11-05T22:00:00+01:00"


def test_empty_timestamp_uses_nginx_iso8601():
    event = parse_line(json.dumps({
        "timestamp": "",
        "time_iso8601": "2026-11-06T02:20:30+01:00",
        "status": 200,
    }))
    assert event["timestamp"] == "2026-11-06T02:20:30+01:00"
