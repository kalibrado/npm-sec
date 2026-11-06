"""End-to-end ingestion tests using a real temporary SQLite database."""
import asyncio
import json
from datetime import datetime, timezone

import pytest

import database
from services import ingestion, log_parser


def line(ip="203.0.113.4", uri="/", status=200):
    return json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remote_addr": ip,
            "host": "cloud.example.test",
            "uri": uri,
            "status": status,
            "allowed": "yes",
            "http_user_agent": "Mozilla/5.0",
        }
    ) + "\n"


@pytest.fixture
def sample(tmp_path, monkeypatch):
    log_file = tmp_path / "access.log"
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "logs.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "test-password-for-temporary-db")
    monkeypatch.setattr(ingestion, "LOG_FILE", log_file)
    database.init_db()
    return log_file


def row_count():
    with database.get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]


def test_ingest_without_sse_and_resume_after_append(sample):
    sample.write_text(line() + line("203.0.113.5"))
    assert ingestion.ingest_file_once() == 2
    assert ingestion.ingest_file_once() == 0
    assert row_count() == 2

    with sample.open("a") as stream:
        stream.write(line("203.0.113.6"))
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 3


def test_cursor_replay_does_not_duplicate_events(sample):
    sample.write_text(line() + line("203.0.113.5"))
    assert ingestion.ingest_file_once() == 2
    with database.get_db() as conn:
        conn.execute("UPDATE ingestion_state SET byte_offset=0")
        conn.commit()
    assert ingestion.ingest_file_once() == 0
    assert row_count() == 2


def test_log_rotation_opens_new_file_from_start(sample):
    sample.write_text(line())
    assert ingestion.ingest_file_once() == 1
    sample.rename(sample.with_suffix(".old"))
    sample.write_text(line("203.0.113.22"))
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 2


def test_copytruncate_starts_new_generation(sample):
    sample.write_text(line() + line("203.0.113.5"))
    assert ingestion.ingest_file_once() == 2
    sample.write_text(line("203.0.113.8"))
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 3


def test_sse_reads_already_ingested_rows(sample):
    sample.write_text(line("203.0.113.44", "/.env", 403))
    assert ingestion.ingest_file_once() == 1

    async def consume_first():
        stream = log_parser.sse_generator(since_id=0)
        try:
            return await anext(stream)
        finally:
            await stream.aclose()

    message = asyncio.run(consume_first())
    assert "id: 1" in message
    assert "data: " in message
    assert "203.0.113.44" in message


def test_existing_database_without_cursor_replays_missing_rows(sample):
    existing = json.loads(line("203.0.113.1"))
    sample.write_text(json.dumps(existing) + "\n" + line("203.0.113.9"))
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO access_logs (timestamp, ip, uri, status)
               VALUES (?, ?, ?, ?)""",
            [existing["timestamp"], existing["remote_addr"], existing["uri"], existing["status"]],
        )
        conn.commit()
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 2
    assert ingestion.ingest_file_once() == 0
    with database.get_db() as conn:
        rows = conn.execute("SELECT source_id, source_offset FROM access_logs ORDER BY id").fetchall()
        assert all(row["source_id"] is not None for row in rows)


def test_cursorless_legacy_same_signature_reconciles_one_row_each(sample):
    existing = json.loads(line("203.0.113.1"))
    raw = json.dumps(existing) + "\n"
    sample.write_text(raw * 2 + line("203.0.113.10"))
    with database.get_db() as conn:
        for _ in range(2):
            conn.execute(
                "INSERT INTO access_logs (timestamp, ip, uri, status) VALUES (?, ?, ?, ?)",
                [existing["timestamp"], existing["remote_addr"], existing["uri"], existing["status"]],
            )
        conn.commit()
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 3
    assert ingestion.ingest_file_once() == 0


def test_sse_frame_uses_real_newlines(sample):
    sample.write_text(line("203.0.113.45", "/login", 401))
    assert ingestion.ingest_file_once() == 1

    async def first_frame():
        stream = log_parser.sse_generator(since_id=0)
        try:
            return await anext(stream)
        finally:
            await stream.aclose()

    frame = asyncio.run(first_frame())
    assert frame.startswith("id: 1\ndata: ")
    assert frame.endswith("\n\n")
    assert r"\n" not in frame
    event = json.loads(frame.split("\ndata: ", 1)[1].strip())
    assert event["ip"] == "203.0.113.45"


def test_legacy_replay_does_not_claim_another_hosts_event(sample):
    existing = json.loads(line("203.0.113.1", "/login", 401))
    other = dict(existing, host="other.example.test")
    sample.write_text(json.dumps(other) + "\n")
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO access_logs (timestamp, ip, uri, status, host)
               VALUES (?, ?, ?, ?, ?)""",
            [existing["timestamp"], existing["remote_addr"], existing["uri"],
             existing["status"], existing["host"]],
        )
        conn.commit()
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 2
    with database.get_db() as conn:
        rows = conn.execute("SELECT host, source_id FROM access_logs ORDER BY id").fetchall()
        assert rows[0]["host"] == "cloud.example.test"
        assert rows[0]["source_id"] is None
        assert rows[1]["host"] == "other.example.test"
        assert rows[1]["source_id"] is not None


def test_legacy_replay_keeps_distinct_http_methods(sample):
    existing = json.loads(line("203.0.113.1", "/login", 401))
    existing["method"] = "POST"
    incoming = dict(existing, method="GET")
    sample.write_text(json.dumps(incoming) + "\n")
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO access_logs (timestamp, ip, uri, status, host, method)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [existing["timestamp"], existing["remote_addr"], existing["uri"],
             existing["status"], existing["host"], existing["method"]],
        )
        conn.commit()
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 2
    with database.get_db() as conn:
        rows = conn.execute(
            "SELECT method, source_id FROM access_logs ORDER BY id"
        ).fetchall()
        assert rows[0]["method"] == "POST"
        assert rows[0]["source_id"] is None
        assert rows[1]["method"] == "GET"
        assert rows[1]["source_id"] is not None
