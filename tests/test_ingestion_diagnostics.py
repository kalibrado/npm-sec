"""Operational diagnostics for the real persistent file cursor and collector."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import ingestion, ingestion_diagnostics as monitor


@pytest.fixture
def environment(tmp_path, monkeypatch):
    path = tmp_path / "access-geo-detailed.log"
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "monitor.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "monitor-integration-admin-password")
    monkeypatch.setattr(ingestion, "LOG_FILE", path)
    monkeypatch.setattr(monitor, "LOG_FILE", path)
    database.init_db()
    return TestClient(app), path


def authenticate(client):
    r = client.post(
        "/auth/login",
        json={"username": "admin", "password": "monitor-integration-admin-password"},
    )
    assert r.status_code == 200, r.text


def event(ip="203.0.113.44", *, instrumented=False):
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": ip,
        "host": "cloud.kaliorbis.fr",
        "uri": "/login",
        "status": "200",
        "allowed": "yes",
        "http_user_agent": "test browser",
    }
    if instrumented:
        data.update({
            "npm_security_policy_mode": "observe",
            "npm_security_would_deny": "0",
        })
    return json.dumps(data) + "\n"


def test_diagnostic_is_admin_only_and_never_exposes_log_lines(environment):
    c, path = environment
    path.write_text(event(ip="203.0.113.180"))
    assert c.get("/health/ingestion").status_code == 401
    authenticate(c)
    response = c.get("/health/ingestion")
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["log_file"] == str(path.resolve())
    assert report["file"]["exists"] is True
    assert report["stored"]["total_logs"] == 0
    assert report["code"] == "collector_not_observed"
    assert "203.0.113.180" not in response.text
    assert '"/login"' not in response.text


def test_missing_log_mount_has_clear_diagnostic(environment):
    c, path = environment
    authenticate(c)
    report = c.get("/health/ingestion").json()
    assert report["status"] == "error"
    assert report["code"] == "file_missing"
    assert report["cursor"]["present"] is False
    assert "LOG_FILE" in report["advice"]
    assert ingestion.ingest_file_once() == 0
    report = c.get("/health/ingestion").json()
    assert report["runtime"]["missing_file_polls"] == 1
    assert report["runtime"]["polls"] == 1


def test_empty_mounted_log_is_not_misrepresented_as_a_block(environment):
    c, path = environment
    path.write_bytes(b"")
    assert ingestion.ingest_file_once() == 0
    authenticate(c)
    report = c.get("/health/ingestion").json()
    assert report["status"] == "warning"
    assert report["code"] == "empty_file"
    assert report["cursor"]["present"] is True
    assert report["cursor"]["offset_bytes"] == 0
    assert report["file"]["size_bytes"] == 0
    assert report["runtime"]["polls"] == 1
    assert report["runtime"]["seconds_since_poll"] is not None


def test_file_cursor_backlog_invalid_json_and_duplicates_are_visible(environment):
    c, path = environment
    path.write_text(event() + "INVALID-JSON\n" + "[]\n")
    assert ingestion.ingest_file_once() == 1
    authenticate(c)
    report = c.get("/health/ingestion").json()
    assert report["runtime"]["lines_read"] == 3
    assert report["runtime"]["lines_inserted"] == 1
    assert report["runtime"]["lines_invalid"] == 2
    assert report["runtime"]["last_batch_invalid"] == 2
    assert report["status"] == "warning"
    assert report["code"] == "invalid_log_lines"
    assert report["cursor"]["backlog_bytes"] == 0
    assert report["stored"]["total_logs"] == 1

    # Restore the cursor; replayed records are deduplicated using source offsets.
    with database.get_db() as conn:
        conn.execute("UPDATE ingestion_state SET byte_offset=0")
        conn.commit()
    assert ingestion.ingest_file_once() == 0
    report = c.get("/health/ingestion").json()
    assert report["runtime"]["lines_duplicate"] == 1
    assert report["stored"]["total_logs"] == 1

    # Incomplete JSON lines are not consumed until newline arrives.
    with path.open("ab") as out:
        out.write(event("203.0.113.45").rstrip("\n").encode())
    assert ingestion.ingest_file_once() == 0
    report = c.get("/health/ingestion").json()
    assert report["code"] == "backlog"
    assert report["cursor"]["backlog_bytes"] > 0
    with path.open("ab") as out:
        out.write(b"\n")
    assert ingestion.ingest_file_once() == 1
    assert c.get("/health/ingestion").json()["cursor"]["backlog_bytes"] == 0


def test_rotation_and_observe_instrumentation_are_reported(environment):
    c, path = environment
    path.write_text(event())
    assert ingestion.ingest_file_once() == 1
    path.rename(path.with_suffix(".old"))
    path.write_text(event("203.0.113.48", instrumented=True))
    authenticate(c)
    report = c.get("/health/ingestion").json()
    assert report["code"] == "rotation_pending"
    assert report["cursor"]["rotation_pending"] is True
    assert report["cursor"]["backlog_bytes"] is None
    assert ingestion.ingest_file_once() == 1
    report = c.get("/health/ingestion").json()
    assert report["code"] == "up_to_date"
    assert report["cursor"]["generation"] == 0
    assert report["stored"]["total_logs"] == 2
    assert report["stored"]["recent_sample_size"] == 2
    assert report["stored"]["instrumented_sample"] == 1


def test_collector_errors_and_stall_are_detectable_without_leaking_exception(environment):
    c, path = environment
    path.write_text(event())
    monitor.record_failure(path, PermissionError("secret-token in filename"))
    authenticate(c)
    response = c.get("/health/ingestion")
    assert response.status_code == 200
    assert response.json()["code"] == "collector_error"
    assert response.json()["runtime"]["last_error_type"] == "PermissionError"
    assert "secret-token" not in response.text

    assert ingestion.ingest_file_once() == 1
    assert c.get("/health/ingestion").json()["code"] == "up_to_date"
    with monitor._lock:
        monitor._runtime["last_poll_monotonic"] = time.monotonic() - 61
    report = c.get("/health/ingestion").json()
    assert report["code"] == "collector_stalled"
    assert report["status"] == "error"


def test_diagnostic_is_read_only_and_preserves_database(environment):
    c, path = environment
    path.write_text(event())
    assert ingestion.ingest_file_once() == 1
    with database.get_db() as conn:
        before = tuple(conn.execute(
            "SELECT physical_id, generation, byte_offset FROM ingestion_state"
        ).fetchone())
    authenticate(c)
    for _ in range(3):
        report = c.get("/health/ingestion")
        assert report.status_code == 200
    with database.get_db() as conn:
        after = tuple(conn.execute(
            "SELECT physical_id, generation, byte_offset FROM ingestion_state"
        ).fetchone())
        assert conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0] == 1
    assert after == before


def test_health_view_is_wired_to_diagnostics():
    html = Path("templates/dashboard.html").read_text(encoding="utf-8")
    js = Path("static/dashboard.js").read_text(encoding="utf-8")
    css = Path("static/dashboard.css").read_text(encoding="utf-8")
    assert 'id="ingestion-health-status"' in html
    assert 'id="ingestion-health-metrics"' in html
    assert 'id="ingestion-health-refresh"' in html
    assert "/health/ingestion" in js
    assert "loadIngestionDiagnostics()" in js
    assert "runtime.lines_invalid" in js
    assert 'data-health-card="ingestion"' in css
