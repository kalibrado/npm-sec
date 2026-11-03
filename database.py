import contextlib
import sqlite3

from  config import DB_FILE, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, ADMIN_TOKEN
from  security import pbkdf2_password

STATS_CACHE_TTL = 10.0
_stats_cache: dict = {"data": None, "ts": 0.0}


def invalidate_stats_cache():
    _stats_cache["ts"] = 0.0


def get_stats_cache():
    return _stats_cache


@contextlib.contextmanager
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_logs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                ip            TEXT,
                country_code  TEXT,
                country_name  TEXT,
                city          TEXT,
                isp           TEXT,
                method        TEXT,
                referer       TEXT,
                host          TEXT,
                user_agent    TEXT,
                asn           TEXT,
                uri           TEXT,
                status        INTEGER,
                blocked       INTEGER DEFAULT 0,
                ua            TEXT,
                ua_type       TEXT,
                latitude      REAL DEFAULT 0,
                longitude     REAL DEFAULT 0,
                threat        TEXT,
                request_time  REAL DEFAULT 0
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocklist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                type       TEXT NOT NULL,
                value      TEXT NOT NULL,
                reason     TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT,
                host       TEXT NOT NULL DEFAULT '',
                UNIQUE(type, value, host)
            )
        """
        )
        # Older databases had a global-only uniqueness constraint.
        # SQLite cannot change a UNIQUE constraint in place, so recreate
        # only this small table while preserving IDs, audit history and expiry.
        # The entire migration is committed atomically with init_db().
        block_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(blocklist)")
        }
        if "host" not in block_columns:
            conn.execute(
                """CREATE TABLE blocklist_host_scoped (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    reason TEXT DEFAULT '',
                    created_at TEXT DEFAULT (datetime('now')),
                    expires_at TEXT,
                    host TEXT NOT NULL DEFAULT '',
                    UNIQUE(type, value, host)
                )"""
            )
            expiry_expr = "expires_at" if "expires_at" in block_columns else "NULL"
            conn.execute(
                f"""INSERT INTO blocklist_host_scoped
                    (id, type, value, reason, created_at, expires_at, host)
                    SELECT id, type, value, reason, created_at, {expiry_expr}, ''
                    FROM blocklist"""
            )
            conn.execute("DROP TABLE blocklist")
            conn.execute("ALTER TABLE blocklist_host_scoped RENAME TO blocklist")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocklist_host ON blocklist(host)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS policy_modes (
                host TEXT PRIMARY KEY,
                mode TEXT NOT NULL CHECK(mode IN ('block','observe')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"""
        )
        # Existing installations receive a nullable expiration column.
        block_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(blocklist)")
        }
        if "expires_at" not in block_columns:
            conn.execute("ALTER TABLE blocklist ADD COLUMN expires_at TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                access_log_id INTEGER,
                ip            TEXT,
                threat_type   TEXT NOT NULL,
                score         INTEGER NOT NULL,
                reasons       TEXT DEFAULT '[]',
                created_at    TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(access_log_id) REFERENCES access_logs(id)
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ban_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target     TEXT NOT NULL,
                type       TEXT NOT NULL,
                action     TEXT NOT NULL,
                reason     TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trusted_entries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                type       TEXT NOT NULL,
                value      TEXT NOT NULL,
                reason     TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                UNIQUE(type, value)
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS whois_cache (
                ip         TEXT PRIMARY KEY,
                payload    TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_tags (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_event_id INTEGER,
                tag             TEXT NOT NULL,
                created_at      TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(threat_event_id) REFERENCES threat_events(id)
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'viewer',
                enabled       INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT DEFAULT (datetime('now')),
                last_login    TEXT
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at  TEXT DEFAULT (datetime('now')),
                expires_at  TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """
        )
        # Upgrade older databases in place, without losing historical traffic.
        access_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(access_logs)")
        }
        if "source_id" not in access_columns:
            conn.execute("ALTER TABLE access_logs ADD COLUMN source_id TEXT")
        if "source_offset" not in access_columns:
            conn.execute("ALTER TABLE access_logs ADD COLUMN source_offset INTEGER")
        # NPM Security log fields are optional: older JSON log formats keep
        # ingesting, but cannot produce verified observation telemetry.
        if "policy_mode" not in access_columns:
            conn.execute("ALTER TABLE access_logs ADD COLUMN policy_mode TEXT")
        if "would_deny" not in access_columns:
            conn.execute("ALTER TABLE access_logs ADD COLUMN would_deny INTEGER")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS observation_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                ip TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN ('open','acknowledged','resolved')),
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now')),
                hits INTEGER NOT NULL DEFAULT 1,
                last_uri TEXT NOT NULL DEFAULT '',
                last_country TEXT NOT NULL DEFAULT '',
                last_alert_at TEXT,
                UNIQUE(host, ip)
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS observation_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                recent_hits INTEGER NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES observation_incidents(id)
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS ingestion_state (
                path TEXT PRIMARY KEY,
                physical_id TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                byte_offset INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"""
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_access_source_offset "
            "ON access_logs(source_id, source_offset)"
        )
        for idx in [
            "CREATE INDEX IF NOT EXISTS idx_timestamp  ON access_logs(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_id         ON access_logs(id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_blocked    ON access_logs(blocked)",
            "CREATE INDEX IF NOT EXISTS idx_host       ON access_logs(host)",
            "CREATE INDEX IF NOT EXISTS idx_status     ON access_logs(status)",
            "CREATE INDEX IF NOT EXISTS idx_country    ON access_logs(country_code)",
            "CREATE INDEX IF NOT EXISTS idx_ip         ON access_logs(ip)",
            "CREATE INDEX IF NOT EXISTS idx_uri        ON access_logs(uri)",
            "CREATE INDEX IF NOT EXISTS idx_threat_ip  ON threat_events(ip)",
            "CREATE INDEX IF NOT EXISTS idx_threat_ts  ON threat_events(created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_threat_score ON threat_events(score DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ban_events_target ON ban_events(target)",
            "CREATE INDEX IF NOT EXISTS idx_ban_events_ts ON ban_events(created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_trusted_type_value ON trusted_entries(type, value)",
            "CREATE INDEX IF NOT EXISTS idx_whois_cache_updated ON whois_cache(updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_access_logs_asn ON access_logs(asn)",
            "CREATE INDEX IF NOT EXISTS idx_access_logs_isp ON access_logs(isp)",
            "CREATE INDEX IF NOT EXISTS idx_threat_tags_tag ON threat_tags(tag)",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(token_hash)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_observation_events ON access_logs(host, ip, timestamp) WHERE policy_mode='observe' AND would_deny=1",
            "CREATE INDEX IF NOT EXISTS idx_observation_incidents_seen ON observation_incidents(last_seen DESC)",
            "CREATE INDEX IF NOT EXISTS idx_observation_incidents_status ON observation_incidents(status)",
            "CREATE INDEX IF NOT EXISTS idx_observation_alerts_created ON observation_alerts(created_at DESC)",
        ]:
            conn.execute(idx)
        admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if admin_count == 0:
            if DEFAULT_ADMIN_PASSWORD:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                    [DEFAULT_ADMIN_USERNAME, pbkdf2_password(DEFAULT_ADMIN_PASSWORD)],
                )
                print(f"✅ Admin user created: {DEFAULT_ADMIN_USERNAME}")
            else:
                raise RuntimeError(
                    "DEFAULT_ADMIN_PASSWORD is required to initialize the first admin user. "
                    "Set a strong password before starting the dashboard."
                )
        conn.commit()
    print(f"✅ DB initialisée : {DB_FILE}")
