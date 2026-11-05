"""Regression tests for read-only settings revision history."""
import sqlite3

import pytest

from services.nginx_settings_diff import RevisionIntegrityError
from services.nginx_settings_history import list_settings_revisions
from services.nginx_settings_revisions import (
    create_settings_revision,
    initialize_settings_revisions,
)

SETTINGS = {
    "auto_ban_enabled": False,
    "country_block_enabled": False,
    "blocked_countries": [],
    "trusted_proxy_cidrs": [],
    "rate_limit_rps": 10,
    "rate_limit_burst": 20,
}


@pytest.fixture
def conn():
    db = sqlite3.connect(":memory:")
    initialize_settings_revisions(db)
    yield db
    db.close()


def seed(conn, count=3):
    for revision in range(count):
        create_settings_revision(
            conn, {**SETTINGS, "rate_limit_rps": revision + 1},
            expected_revision=revision, author="admin", reason=f"change {revision}",
        )


def test_history_is_newest_first_and_excludes_payload(conn):
    seed(conn)
    rows = list_settings_revisions(conn)
    assert [row["revision"] for row in rows] == [3, 2, 1]
    assert all("settings" not in row and row["status"] == "DRAFT" for row in rows)
    assert rows[0]["reason"] == "change 2"


def test_cursor_pagination(conn):
    seed(conn)
    assert [r["revision"] for r in list_settings_revisions(conn, limit=1)] == [3]
    assert [r["revision"] for r in list_settings_revisions(conn, before_revision=3)] == [2, 1]
    assert list_settings_revisions(conn, before_revision=1) == []


@pytest.mark.parametrize("kwargs", [
    {"limit": 0}, {"limit": 101}, {"limit": True},
    {"before_revision": 0}, {"before_revision": False},
])
def test_invalid_pagination_rejected(conn, kwargs):
    with pytest.raises(ValueError):
        list_settings_revisions(conn, **kwargs)


def test_corrupt_revision_rejected(conn):
    seed(conn)
    conn.execute(
        "UPDATE nginx_settings_revisions SET settings_json = ? WHERE revision = 2",
        ('{"auto_ban_enabled":true}',),
    )
    conn.commit()
    with pytest.raises(RevisionIntegrityError):
        list_settings_revisions(conn)


def test_history_does_not_modify_database(conn):
    seed(conn)
    before = conn.total_changes
    list_settings_revisions(conn)
    assert conn.total_changes == before
