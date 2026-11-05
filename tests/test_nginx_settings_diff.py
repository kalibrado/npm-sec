import sqlite3

import pytest

from services.nginx_settings_revisions import create_settings_revision, initialize_settings_revisions
from services.nginx_settings_diff import (
    RevisionIntegrityError,
    RevisionNotFound,
    compare_settings_revisions,
)


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    initialize_settings_revisions(conn)
    yield conn
    conn.close()


def sample():
    return {
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": ["FR"],
        "trusted_proxy_cidrs": ["192.168.1.0/24"],
        "rate_limit_rps": 10,
        "rate_limit_burst": 20,
    }


def seed(db):
    original = sample()
    create_settings_revision(db, original, expected_revision=0, author="admin", reason="initial")
    changed = sample()
    changed["rate_limit_rps"] = 25
    changed["blocked_countries"] = ["DE"]
    create_settings_revision(db, changed, expected_revision=1, author="admin", reason="update")


def test_diff_is_deterministic_and_read_only(db):
    seed(db)
    result = compare_settings_revisions(db, 1, 2)
    assert result == {
        "before_revision": 1,
        "after_revision": 2,
        "changes": {
            "blocked_countries": {"before": ["FR"], "after": ["DE"]},
            "rate_limit_rps": {"before": 10, "after": 25},
        },
    }
    assert compare_settings_revisions(db, 2, 1)["changes"]["rate_limit_rps"] == {
        "before": 25, "after": 10,
    }
    assert compare_settings_revisions(db, 1, 1)["changes"] == {}
    assert db.execute("SELECT COUNT(*) FROM nginx_settings_revisions").fetchone()[0] == 2


@pytest.mark.parametrize("revision", [0, -1, True, "1"])
def test_reject_invalid_revision(db, revision):
    with pytest.raises(ValueError):
        compare_settings_revisions(db, revision, 1)


def test_missing_revision(db):
    with pytest.raises(RevisionNotFound):
        compare_settings_revisions(db, 1, 2)


def test_detect_modified_stored_payload(db):
    seed(db)
    db.execute("UPDATE nginx_settings_revisions SET settings_json = ? WHERE revision = 1", ('{}',))
    db.commit()
    with pytest.raises(RevisionIntegrityError):
        compare_settings_revisions(db, 1, 2)


def test_detect_invalid_payload_even_with_recomputed_hash(db):
    import hashlib
    seed(db)
    payload = '{"raw_nginx":"include /etc/passwd;"}'
    db.execute(
        "UPDATE nginx_settings_revisions SET settings_json=?, settings_sha256=? WHERE revision=1",
        (payload, hashlib.sha256(payload.encode()).hexdigest()),
    )
    db.commit()
    with pytest.raises(RevisionIntegrityError):
        compare_settings_revisions(db, 1, 2)
