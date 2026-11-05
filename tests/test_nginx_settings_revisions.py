import sqlite3

import pytest

from services.nginx_settings_revisions import (
    RevisionConflict,
    create_settings_revision,
    initialize_settings_revisions,
    latest_settings_revision,
)


@pytest.fixture
def settings():
    return {
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": ["FR"],
        "trusted_proxy_cidrs": ["192.168.1.0/24"],
        "rate_limit_rps": 10,
        "rate_limit_burst": 20,
    }


@pytest.fixture
def db():
    connection = sqlite3.connect(":memory:")
    initialize_settings_revisions(connection)
    yield connection
    connection.close()


def test_immutable_drafts_and_hash(db, settings):
    assert latest_settings_revision(db) is None
    first = create_settings_revision(
        db, settings, expected_revision=0, author="admin", reason="initial",
        source_sha256="a" * 64,
    )
    assert first["revision"] == 1
    assert first["status"] == "DRAFT"
    assert len(first["settings_sha256"]) == 64
    settings["rate_limit_rps"] = 20
    second = create_settings_revision(
        db, settings, expected_revision=1, author="admin", reason="change rate",
    )
    assert second["revision"] == 2
    assert second["settings_sha256"] != first["settings_sha256"]
    assert db.execute(
        "SELECT COUNT(*) FROM nginx_settings_revisions"
    ).fetchone()[0] == 2
    assert db.execute(
        "SELECT settings_json FROM nginx_settings_revisions WHERE revision=1"
    ).fetchone()[0].find('"rate_limit_rps":10') != -1


def test_stale_writer_cannot_overwrite(db, settings):
    create_settings_revision(db, settings, expected_revision=0, author="admin", reason="initial")
    with pytest.raises(RevisionConflict):
        create_settings_revision(db, settings, expected_revision=0, author="admin", reason="stale")
    assert latest_settings_revision(db)["revision"] == 1


@pytest.mark.parametrize("change", [
    {"auto_ban_enabled": "false"},
    {"raw_nginx": "include /etc/passwd;"},
])
def test_invalid_settings_never_persist(db, settings, change):
    settings.update(change)
    with pytest.raises(ValueError):
        create_settings_revision(db, settings, expected_revision=0, author="admin", reason="bad")
    assert latest_settings_revision(db) is None


def test_author_reason_and_source_validation(db, settings):
    for kwargs in [
        {"author": "", "reason": "x"},
        {"author": "admin", "reason": ""},
        {"author": "admin", "reason": "x", "source_sha256": "not-a-hash"},
    ]:
        with pytest.raises(ValueError):
            create_settings_revision(db, settings, expected_revision=0, **kwargs)
    assert latest_settings_revision(db) is None


def test_existing_tables_preserved(db, settings):
    db.execute("CREATE TABLE existing_rules (id INTEGER PRIMARY KEY)")
    db.execute("INSERT INTO existing_rules VALUES (7)")
    db.commit()
    initialize_settings_revisions(db)
    create_settings_revision(db, settings, expected_revision=0, author="admin", reason="draft")
    assert db.execute("SELECT id FROM existing_rules").fetchone()[0] == 7
