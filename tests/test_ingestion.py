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


def test_existing_database_without_cursor_starts_at_eof(sample):
    sample.write_text(line("203.0.113.1"))
    # Legacy installation: historical logs without a persisted file cursor.
    with database.get_db() as conn:
        conn.execute(
            """INSERT INTO access_logs (timestamp, ip, uri)
               VALUES (?, ?, ?)""",
            [datetime.now(timezone.utc).isoformat(), "203.0.113.1", "/"],
        )
        conn.commit()
    assert ingestion.ingest_file_once() == 0
    assert row_count() == 1
    with sample.open("a") as stream:
        stream.write(line("203.0.113.9"))
    assert ingestion.ingest_file_once() == 1
    assert row_count() == 2


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
    assert frame.startswith("id: 1\\ndata: ")
    assert frame.endswith("\\n\\n")
    assert "\\\\n" not in frame
    event = json.loads(frame.split("\\ndata: ", 1)[1].strip())
    assert event["ip"] == "203.0.113.45"
