"""Integrity regression tests for latest settings revision reads."""
import hashlib
import json
import sqlite3

import pytest

from services.nginx_settings_diff import RevisionIntegrityError
from services.nginx_settings_revisions import (
    create_settings_revision,
    initialize_settings_revisions,
    latest_settings_revision,
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
    connection = sqlite3.connect(":memory:")
    initialize_settings_revisions(connection)
    yield connection
    connection.close()


def seed(conn):
    return create_settings_revision(
        conn, SETTINGS, expected_revision=0, author="admin", reason="baseline"
    )


def test_empty_latest_is_none(conn):
    assert latest_settings_revision(conn) is None


def test_valid_latest_returns_verified_settings(conn):
    saved = seed(conn)
    assert latest_settings_revision(conn) == saved


def test_modified_payload_is_rejected(conn):
    seed(conn)
    conn.execute(
        "UPDATE nginx_settings_revisions SET settings_json = ? WHERE revision = 1",
        ('{"auto_ban_enabled":true}',),
    )
    with pytest.raises(RevisionIntegrityError):
        latest_settings_revision(conn)


def test_invalid_schema_even_with_recomputed_hash_is_rejected(conn):
    seed(conn)
    raw = json.dumps({"auto_ban_enabled": True}, sort_keys=True, separators=(",", ":"))
    conn.execute(
        "UPDATE nginx_settings_revisions SET settings_json = ?, settings_sha256 = ? WHERE revision = 1",
        (raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()),
    )
    with pytest.raises(RevisionIntegrityError):
        latest_settings_revision(conn)


def test_noncanonical_payload_even_with_valid_hash_is_rejected(conn):
    seed(conn)
    raw = json.dumps(SETTINGS, indent=2)
    conn.execute(
        "UPDATE nginx_settings_revisions SET settings_json = ?, settings_sha256 = ? WHERE revision = 1",
        (raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()),
    )
    with pytest.raises(RevisionIntegrityError):
        latest_settings_revision(conn)


def test_unexpected_status_rejected(conn):
    seed(conn)
    conn.execute("PRAGMA ignore_check_constraints = ON")
    conn.execute("UPDATE nginx_settings_revisions SET status = 'APPLIED' WHERE revision = 1")
    with pytest.raises(RevisionIntegrityError):
        latest_settings_revision(conn)


def test_read_has_no_mutation(conn):
    seed(conn)
    before = conn.total_changes
    latest_settings_revision(conn)
    assert conn.total_changes == before
