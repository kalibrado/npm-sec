"""Read-only, integrity-checked comparison of stored Nginx settings drafts.

No Nginx rendering, Docker access or deployment side effects.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from services.nginx_settings_schema import validate_settings


class RevisionNotFound(LookupError):
    """The requested settings revision does not exist."""


class RevisionIntegrityError(ValueError):
    """A persisted revision no longer matches its stored SHA-256."""


def _read_revision(conn: sqlite3.Connection, revision: int) -> dict[str, Any]:
    if type(revision) is not int or revision < 1:
        raise ValueError("revision must be a positive integer")
    row = conn.execute(
        "SELECT settings_json, settings_sha256 FROM nginx_settings_revisions WHERE revision = ?",
        (revision,),
    ).fetchone()
    if row is None:
        raise RevisionNotFound(f"revision {revision} not found")
    raw, expected_hash = row
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected_hash:
        raise RevisionIntegrityError(f"revision {revision} failed SHA-256 verification")
    try:
        parsed = json.loads(raw)
        normalized = validate_settings(parsed)
    except (ValueError, TypeError) as exc:
        raise RevisionIntegrityError(f"revision {revision} contains invalid settings") from exc
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != raw:
        raise RevisionIntegrityError(f"revision {revision} is not canonical")
    return normalized


def compare_settings_revisions(
    conn: sqlite3.Connection, before_revision: int, after_revision: int,
) -> dict[str, Any]:
    """Return a deterministic field-level diff, without mutating stored drafts."""
    before = _read_revision(conn, before_revision)
    after = _read_revision(conn, after_revision)
    changes = {
        key: {"before": before[key], "after": after[key]}
        for key in sorted(before)
        if before[key] != after[key]
    }
    return {
        "before_revision": before_revision,
        "after_revision": after_revision,
        "changes": changes,
    }
