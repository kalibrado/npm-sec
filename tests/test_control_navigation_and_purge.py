"""Regression tests for UX navigation and authenticated destructive log cleanup."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services import ingestion


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "purge.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "test-purge-admin-password")
    monkeypatch.setattr(ingestion, "LOG_FILE", tmp_path / "original-access.log")
    database.init_db()
    return TestClient(app)


def authenticate(client):
    r = client.post(
        "/auth/login",
        json={"username": "admin", "password": "test-purge-admin-password"},
    )
    assert r.status_code == 200, r.text


def purge(client, *, phrase="PURGER", header="PURGER"):
    return client.post(
        "/db/purge-logs",
        json={"confirmation": phrase},
        headers={"X-Purge-Confirmation": header},
    )


def seed():
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO blocklist(type, value, host, reason)
               VALUES ('ip','203.0.113.8','','keep')"""
        )
        conn.execute(
            """INSERT INTO trusted_entries(type,value,reason)
               VALUES ('ip','192.0.2.2','keep')"""
        )
        conn.execute(
            "INSERT INTO policy_modes(host,mode) VALUES ('cloud.kaliorbis.fr','observe')"
        )
        conn.execute(
            """INSERT INTO ban_events(target,type,action,reason)
               VALUES ('203.0.113.8','ip','BLOCK','keep audit')"""
        )
        conn.execute(
            """INSERT INTO ingestion_state(path,physical_id,generation,byte_offset)
               VALUES ('/logs/access.log','device:inode',0,560)"""
        )
        conn.execute(
            """INSERT INTO access_logs
               (timestamp, ip, host, status, blocked, source_id, source_offset,
                policy_mode, would_deny)
               VALUES (datetime('now'),'203.0.113.1','cloud.kaliorbis.fr',200,0,
                       'device:inode:0',0,'observe',1)"""
        )
        log_id = conn.execute(
            """INSERT INTO access_logs(timestamp,ip,host,status,blocked)
               VALUES (datetime('now'),'203.0.113.2','jellyfin.kaliorbis.fr',403,1)"""
        ).lastrowid
        threat_id = conn.execute(
            """INSERT INTO threat_events(access_log_id,ip,threat_type,score)
               VALUES (?,'203.0.113.2','scanner',77)""", (log_id,)
        ).lastrowid
        conn.execute(
            "INSERT INTO threat_tags(threat_event_id,tag) VALUES (?,'scanner')",
            (threat_id,),
        )
        incident_id = conn.execute(
            """INSERT INTO observation_incidents(host,ip,hits)
               VALUES ('cloud.kaliorbis.fr','203.0.113.1',4)"""
        ).lastrowid
        conn.execute(
            """INSERT INTO observation_alerts(incident_id,recent_hits)
               VALUES (?,4)""", (incident_id,)
        )
        conn.commit()


def count(table):
    with database.get_db() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_purge_requires_admin_and_two_independent_confirmations(client):
    seed()
    assert purge(client).status_code == 401
    authenticate(client)
    for phrase, header in [
        ("", "PURGER"),
        ("PURGER", ""),
        ("purger", "PURGER"),
        ("PURGER", "maybe"),
    ]:
        response = purge(client, phrase=phrase, header=header)
        assert response.status_code == 422, response.text
    assert count("access_logs") == 2
    assert count("blocklist") == 1


def test_purge_removes_derived_logs_but_not_policies_or_cursor(client, tmp_path):
    seed()
    original_log = tmp_path / "original-access.log"
    original_log.write_text("nginx source logfile must be preserved\n", encoding="utf-8")
    authenticate(client)
    result = purge(client)
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["status"] == "ok"
    assert payload["deleted"] == {
        "threat_tags": 1,
        "threat_events": 1,
        "observation_alerts": 1,
        "observation_incidents": 1,
        "access_logs": 2,
    }
    assert original_log.read_text() == "nginx source logfile must be preserved\n"

    for table in (
        "access_logs", "threat_events", "threat_tags",
        "observation_incidents", "observation_alerts",
    ):
        assert count(table) == 0

    for table in (
        "blocklist", "trusted_entries", "policy_modes", "ban_events",
        "ingestion_state", "users", "sessions",
    ):
        assert count(table) == 1, table
    with database.get_db() as conn:
        state = conn.execute(
            "SELECT physical_id, generation, byte_offset FROM ingestion_state"
        ).fetchone()
        assert tuple(state) == ("device:inode", 0, 560)

    # Purge is idempotent and must not break future event ingestion.
    again = purge(client)
    assert again.status_code == 200
    assert all(value == 0 for value in again.json()["deleted"].values())
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO access_logs(timestamp,ip,host,status)
               VALUES (datetime('now'),'203.0.113.45','cloud.kaliorbis.fr',200)"""
        )
        conn.commit()
    assert count("access_logs") == 1


def test_dedicated_control_page_is_separate_from_lists_and_scrollable():
    page = Path("templates/dashboard.html").read_text(encoding="utf-8")
    css = Path("static/dashboard.css").read_text(encoding="utf-8")
    js = Path("static/dashboard.js").read_text(encoding="utf-8")
    assert page.count('data-view="control"') >= 2
    assert 'id="panel-control"' in page
    assert 'id="security-console-scroll"' in page
    assert 'id="security-control-refresh"' in page
    assert page.index('id="panel-control"') < page.index('id="security-control-overview"')
    assert page.index('id="security-policy-preview"') < page.index('id="panel-lists"')
    assert page.index('id="panel-lists"') < page.index('id="lists-blocked-body"')
    assert 'body[data-view="control"] #panel-control' in css
    assert 'body[data-view="control"] .layout > :not(#panel-control)' in css
    assert 'overflow-y: auto !important;' in css
    assert "if (v==='control') loadSecurityControl();" in js
    assert "if (v==='lists') loadSecurityLists();" in js


def test_blank_forms_have_inline_errors_and_action_buttons_have_status():
    page = Path("templates/dashboard.html").read_text(encoding="utf-8")
    js = Path("static/dashboard.js").read_text(encoding="utf-8")
    for identifier in [
        "bl-form-feedback", "trusted-form-feedback", "lists-block-feedback",
        "lists-trusted-feedback", "bl-export-status", "security-preview-result",
        "log-purge-feedback", "logs-purge-dialog-status",
    ]:
        assert f'id="{identifier}"' in page
    assert 'id="security-preview-form" novalidate' in page
    for part in [
        "requiredInput('bl-input'",
        "requiredInput('trusted-input'",
        "requiredInput('lists-block-input'",
        "requiredInput('lists-trusted-input'",
        "container.dataset.decision = 'error'",
        "formFeedback('bl-form-feedback'",
        "withBusyButton('bl-apply-export'",
    ]:
        assert part in js
    assert "'X-Purge-Confirmation': 'PURGER'" in js
    assert "dialog.showModal()" in js
    assert "input.value !== 'PURGER'" in js
    assert "logs-purge-submit" in page
    assert "/db/purge-logs" in js
