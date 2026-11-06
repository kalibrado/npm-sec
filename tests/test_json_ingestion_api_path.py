"""Exercise JSON log ingestion through the same API paths used by the dashboard."""
import asyncio
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

import database
from auth_deps import get_current_user
from routers import logs
from services import ingestion, log_parser


def test_json_ingestion_reaches_history_stats_and_sse(tmp_path, monkeypatch):
    log_file = tmp_path / "access.jsonl"
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "nsd.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "test-password-for-temporary-db")
    monkeypatch.setattr(ingestion, "LOG_FILE", log_file)
    monkeypatch.setattr(ingestion, "check_alerts", lambda: None)
    database.init_db()
    logs.stats_cache.update({"data": None, "ts": 0})

    events = [
        {
            "time_iso8601": "2026-11-06T12:00:00+01:00",
            "remote_addr": "203.0.113.41",
            "http_host": "cloud.example.test",
            "request_method": "GET",
            "request_uri": "/latest",
            "status": 200,
            "allowed": "yes",
            "http_user_agent": "IntegrationTest/1.0",
        },
        {
            "time_iso8601": "2026-11-06T12:00:01+01:00",
            "remote_addr": "203.0.113.42",
            "http_host": "cloud.example.test",
            "request_method": "POST",
            "request_uri": "/login",
            "status": 403,
            "allowed": "no",
            "http_user_agent": "IntegrationTest/1.0",
        },
    ]
    log_file.write_text("".join(json.dumps(event) + "\n" for event in events))
    assert ingestion.ingest_file_once() == 2

    app = FastAPI()
    app.include_router(logs.router)
    client = TestClient(app)
    assert client.get("/history").status_code == 401
    app.dependency_overrides[get_current_user] = lambda: {"username": "reader", "role": "viewer"}

    response = client.get("/history?limit=10")
    assert response.status_code == 200
    history = response.json()
    assert history["total"] == 2
    by_uri = {row["uri"]: row for row in history["logs"]}
    assert by_uri["/latest"]["method"] == "GET"
    assert by_uri["/latest"]["host"] == "cloud.example.test"
    assert by_uri["/login"]["method"] == "POST"
    assert by_uri["/login"]["blocked"] == 1

    stats = client.get("/stats")
    assert stats.status_code == 200
    assert stats.json()["total"] == 2
    assert stats.json()["blocked"] == 1

    async def first_sse_frame():
        stream = log_parser.sse_generator(since_id=0)
        try:
            return await anext(stream)
        finally:
            await stream.aclose()

    frame = asyncio.run(first_sse_frame())
    assert frame.startswith("id: 1\ndata: ")
    payload = json.loads(frame.split("\ndata: ", 1)[1].strip())
    assert payload["uri"] == "/latest"

    # Restarting the poller must not double-count events exposed by the API.
    assert ingestion.ingest_file_once() == 0
    assert client.get("/history").json()["total"] == 2
