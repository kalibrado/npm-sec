"""Real-SQL regression tests for behavioral threat correlation."""
from datetime import datetime, timezone

import pytest

import database
from services import log_parser


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "logs.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "test-temporary-credentials")
    database.init_db()


def event(ip="203.0.113.7", host="cloud.example.test", uri="/login", status=401, ua="Mozilla/5.0"):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "country_code": "XX",
        "country_name": "-",
        "city": "-",
        "host": host,
        "method": "POST",
        "referer": "",
        "user_agent": ua,
        "isp": "-",
        "asn": "",
        "uri": uri,
        "status": status,
        "blocked": 0,
        "ua": ua,
        "latitude": 0.0,
        "longitude": 0.0,
        "request_time": 0.01,
        "threat": "normal",
    }


def test_brute_force_after_repeated_failed_logins(db):
    last = None
    for _ in range(10):
        last = log_parser.insert_log(event())
    assert last["threat"] == "brute_force"
    assert "brute_force_login_failures" in last["threat_reasons"]
    assert last["threat_score"] >= 60


def test_brute_force_does_not_merge_different_hosts(db):
    for _ in range(6):
        a = log_parser.insert_log(event(host="one.example.test"))
        b = log_parser.insert_log(event(host="two.example.test"))
    assert "brute_force_login_failures" not in a["threat_reasons"]
    assert "brute_force_login_failures" not in b["threat_reasons"]


def test_successful_logins_are_not_brute_force(db):
    for _ in range(12):
        last = log_parser.insert_log(event(status=200))
    assert "brute_force_login_failures" not in last["threat_reasons"]


def test_path_enumeration_detected_after_many_denied_paths(db):
    last = None
    for i in range(12):
        last = log_parser.insert_log(event(uri=f"/missing-{i}", status=404))
    assert last["threat"] == "scanner"
    assert "http_path_enumeration" in last["threat_reasons"]


def test_repeated_same_missing_path_not_an_enumeration(db):
    for _ in range(16):
        last = log_parser.insert_log(event(uri="/missing", status=404))
    assert "http_path_enumeration" not in last["threat_reasons"]


def test_benign_bot_user_agent_does_not_trigger_automatic_ban(db):
    item = log_parser.insert_log(
        event(uri="/robots.txt", status=200, ua="Googlebot/2.1")
    )
    assert item["threat_score"] < 30
    assert "brute_force_login_failures" not in item["threat_reasons"]
