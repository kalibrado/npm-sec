"""Immutable draft revisions for typed Nginx settings; no NPM side effects."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from services.nginx_settings_schema import validate_settings


class RevisionConflict(ValueError):
    """A concurrent writer already created a newer revision."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def initialize_settings_revisions(conn: sqlite3.Connection) -> None:
    """Create an isolated table without modifying existing security rules."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nginx_settings_revisions (
            revision INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            author TEXT NOT NULL,
            reason TEXT NOT NULL,
            source_sha256 TEXT,
            settings_json TEXT NOT NULL,
            settings_sha256 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT')
        )
    """)
    conn.commit()


def latest_settings_revision(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("""
        SELECT revision, created_at, author, reason, source_sha256,
               settings_json, settings_sha256, status
        FROM nginx_settings_revisions ORDER BY revision DESC LIMIT 1
    """).fetchone()
    if row is None:
        return None
    # Fail closed if the newest draft was altered, even when its hash was
    # recomputed: callers must never receive unvalidated persisted settings.
    from services.nginx_settings_diff import RevisionIntegrityError, _read_revision

    settings = _read_revision(conn, row[0])
    if row[7] != "DRAFT":
        raise RevisionIntegrityError(f"revision {row[0]} has an invalid status")
    return {
        "revision": row[0], "created_at": row[1], "author": row[2],
        "reason": row[3], "source_sha256": row[4],
        "settings": settings, "settings_sha256": row[6],
        "status": row[7],
    }


def create_settings_revision(
    conn: sqlite3.Connection, settings: Any, *, expected_revision: int,
    author: str, reason: str, source_sha256: str | None = None,
) -> dict[str, Any]:
    """Persist a validated draft with optimistic concurrency.

    No Nginx files are generated, and no configuration is applied.
    The caller must authorize the actor before invoking this storage layer.
    """
    normalized = validate_settings(settings)
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("expected_revision must be a nonnegative integer")
    if not isinstance(author, str) or not author.strip() or len(author) > 128:
        raise ValueError("author required (max 128 characters)")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
        raise ValueError("reason required (max 1024 characters)")
    if source_sha256 is not None and (
        not isinstance(source_sha256, str) or len(source_sha256) != 64
        or any(c not in "0123456789abcdef" for c in source_sha256)
    ):
        raise ValueError("source_sha256 must be lowercase SHA-256")
    payload = _canonical(normalized)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    # BEGIN IMMEDIATE serializes competing writers across SQLite connections.
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = conn.execute(
            "SELECT COALESCE(MAX(revision), 0) FROM nginx_settings_revisions"
        ).fetchone()[0]
        if current != expected_revision:
            raise RevisionConflict(f"expected revision {expected_revision}, current {current}")
        # Never bury a corrupted latest draft under a fresh valid revision.
        # Keep the integrity check inside the writer transaction.
        if current:
            latest_settings_revision(conn)
        cursor = conn.execute("""
            INSERT INTO nginx_settings_revisions
            (created_at, author, reason, source_sha256, settings_json, settings_sha256)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(), author.strip(), reason.strip(),
            source_sha256, payload, digest,
        ))
        revision = cursor.lastrowid
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    result = latest_settings_revision(conn)
    assert result is not None and result["revision"] == revision
    return result


def restore_settings_revision(
    conn: sqlite3.Connection, *, target_revision: int, expected_revision: int,
    author: str, reason: str,
) -> dict[str, Any]:
    """Copy a verified historical draft into a new immutable DRAFT revision.

    This is a draft restoration, not an Nginx deployment or applied rollback.
    The caller must enforce admin authorization before invoking this function.
    """
    if type(target_revision) is not int or target_revision < 1:
        raise ValueError("target_revision must be a positive integer")
    from services.nginx_settings_diff import _read_revision

    # Validate the source before delegating the concurrency-controlled write.
    # A concurrent SQLite writer cannot alter historical immutable revisions.
    settings = _read_revision(conn, target_revision)
    return create_settings_revision(
        conn, settings, expected_revision=expected_revision,
        author=author, reason=reason,
    )
