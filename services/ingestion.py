"""Single-writer log ingestion, independent of browsers and the SSE endpoint.

A persistent file cursor prevents re-reading events after service restarts.
The source position is also recorded with each log row to make crash recovery
idempotent even if the process stopped after writing an event but before moving
the cursor. This collector is designed for one Uvicorn worker per database.
"""
import asyncio
import os
from pathlib import Path

from config import LOG_FILE
from database import get_db
from services.log_parser import check_alerts, insert_log, parse_line
from services.ingestion_diagnostics import record_cycle, record_failure


def _current_identity(fd) -> tuple[str, int]:
    stat = os.fstat(fd.fileno())
    return f"{stat.st_dev}:{stat.st_ino}", stat.st_size


def ingest_file_once(log_file: Path | None = None, batch_size: int = 500) -> int:
    """Ingest up to batch_size complete lines; return newly inserted rows.

    Invalid JSON lines are skipped. A partial final line is retried during the
    following poll. Changes of inode or file truncation trigger a new source
    generation. On an initial upgrade with an existing database, start at EOF
    rather than double-counting legacy rows that have no source cursor.
    """
    log_file = Path(log_file or LOG_FILE)
    try:
        handle = open(log_file, "rb")
    except FileNotFoundError:
        record_cycle(log_file, missing=True)
        return 0

    with handle:
        physical_id, file_size = _current_identity(handle)
        path = str(log_file.resolve())
        with get_db() as conn:
            state = conn.execute(
                "SELECT physical_id, generation, byte_offset FROM ingestion_state WHERE path=?",
                [path],
            ).fetchone()
            if state is None:
                legacy_count = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
                offset = file_size if legacy_count else 0
                generation = 0
                # Persist bootstrap immediately. A crash before the first batch
                # must never cause the next startup to skip the remainder.
                conn.execute(
                    """INSERT INTO ingestion_state
                       (path, physical_id, generation, byte_offset)
                       VALUES (?, ?, 0, ?)""",
                    [path, physical_id, offset],
                )
                conn.commit()
            elif state["physical_id"] != physical_id:
                offset, generation = 0, 0
            elif file_size < state["byte_offset"]:
                offset, generation = 0, state["generation"] + 1
            else:
                offset = state["byte_offset"]
                generation = state["generation"]

        source_id = f"{physical_id}:{generation}"
        handle.seek(offset)
        processed = 0
        inserted = 0
        invalid = 0
        duplicates = 0
        # Checkpoint after each batch. Unique source_id + source_offset
        # deduplicates replays following a crash before checkpoint.
        while processed < max(1, batch_size):
            position = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                handle.seek(position)
                break
            offset = handle.tell()
            processed += 1
            event = parse_line(raw.decode("utf-8", errors="replace"))
            if event is None:
                invalid += 1
                continue
            event["source_id"] = source_id
            event["source_offset"] = position
            result = insert_log(event)
            if result.get("duplicate"):
                duplicates += 1
            else:
                inserted += 1

        with get_db() as conn:
            conn.execute(
                """INSERT INTO ingestion_state (path, physical_id, generation, byte_offset, updated_at)
                   VALUES (?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(path) DO UPDATE SET
                     physical_id=excluded.physical_id,
                     generation=excluded.generation,
                     byte_offset=excluded.byte_offset,
                     updated_at=excluded.updated_at""",
                [path, physical_id, generation, offset],
            )
            conn.commit()

        record_cycle(
            log_file, read=processed, inserted=inserted,
            invalid=invalid, duplicate=duplicates,
        )
        if inserted:
            check_alerts()
        return inserted


async def ingest_forever(poll_interval: float = 0.3):
    """Poll files on the server even if no web browser is connected."""
    while True:
        try:
            count = ingest_file_once()
            if count:
                # Give incoming HTTP handlers some time between large batches.
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Keep the process alive during log rotation / missing mounts.
            record_failure(LOG_FILE, exc)
            print(f"[ingestion] error: {type(exc).__name__}")
        await asyncio.sleep(poll_interval)
