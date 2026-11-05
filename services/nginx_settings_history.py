"""Read-only, integrity-checked revision history for future admin API.

This module does not authorize callers or interact with Nginx. Authorization
must be enforced at the HTTP boundary before using this storage API.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from services.nginx_settings_diff import _read_revision


def list_settings_revisions(
    conn: sqlite3.Connection, *, limit: int = 50, before_revision: int | None = None,
) -> list[dict[str, Any]]:
    """List verified draft metadata newest first, without exposing settings payloads.

    A corrupt revision fails the entire read rather than appearing trustworthy.
    Cursor pagination uses strict revision ordering to avoid offset drift.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer between 1 and 100")
    if before_revision is not None and (
        type(before_revision) is not int or before_revision < 1
    ):
        raise ValueError("before_revision must be a positive integer")
    rows = conn.execute(
        """SELECT revision, created_at, author, reason, source_sha256,
                  settings_sha256, status
           FROM nginx_settings_revisions
           WHERE (? IS NULL OR revision < ?)
           ORDER BY revision DESC LIMIT ?""",
        (before_revision, before_revision, limit),
    ).fetchall()
    result = []
    for revision, created_at, author, reason, source_sha256, digest, status in rows:
        _read_revision(conn, revision)
        if status != "DRAFT":
            raise ValueError(f"revision {revision}: unexpected status")
        result.append({
            "revision": revision,
            "created_at": created_at,
            "author": author,
            "reason": reason,
            "source_sha256": source_sha256,
            "settings_sha256": digest,
            "status": status,
        })
    return result
