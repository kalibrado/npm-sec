"""Persistent, rate-limited alerts for verified Nginx observation events.

Only explicit, server-originated policy_mode=observe + would_deny=1
produces incidents. No policy evaluation is inferred from HTTP status,
user-agent or the current *saved* dashboard mode: the deployed Nginx
log values are the source of truth.
"""
import ipaddress
import sqlite3

from config import (
    OBSERVE_ALERT_ENABLED,
    OBSERVE_ALERT_THRESHOLD,
    OBSERVE_ALERT_WINDOW_MINUTES,
    OBSERVE_ALERT_COOLDOWN_MINUTES,
)


def record_observation(conn: sqlite3.Connection, event: dict) -> dict | None:
    """Update an incident after a newly inserted access_log row.

    This function runs in the same SQLite transaction as the access log,
    so replaying a file cursor cannot duplicate incident hits or alerts.
    Returns a new persisted alert (or None) for optional delivery *after*
    commit. A dashboard alert is available even without Discord.
    """
    if event.get("policy_mode") != "observe" or event.get("would_deny") != 1:
        return None

    host = str(event.get("host") or "").strip().lower()[:253]
    raw_ip = event.get("ip") or ""
    try:
        ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return None
    if not host:
        return None

    uri = str(event.get("uri") or "")[:500]
    country = str(event.get("country_code") or "")[:2]
    conn.execute(
        """INSERT INTO observation_incidents
           (host, ip, hits, last_uri, last_country)
           VALUES (?, ?, 1, ?, ?)
           ON CONFLICT(host, ip) DO UPDATE SET
               hits=observation_incidents.hits + 1,
               last_seen=datetime('now'),
               last_uri=excluded.last_uri,
               last_country=excluded.last_country,
               status=CASE WHEN observation_incidents.status='resolved'
                   THEN 'open' ELSE observation_incidents.status END""",
        (host, ip, uri, country),
    )
    incident = conn.execute(
        "SELECT id FROM observation_incidents WHERE host=? AND ip=?",
        (host, ip),
    ).fetchone()
    incident_id = incident["id"]
    if not OBSERVE_ALERT_ENABLED:
        return None

    recent = conn.execute(
        """SELECT COUNT(*) FROM access_logs
           WHERE host=? AND ip=?
             AND policy_mode='observe' AND would_deny=1
             AND datetime(timestamp)>=datetime('now', ?)
             AND datetime(timestamp)<=datetime('now', '+1 minute')""",
        (host, ip, f"-{OBSERVE_ALERT_WINDOW_MINUTES} minutes"),
    ).fetchone()[0]
    if recent < OBSERVE_ALERT_THRESHOLD:
        return None

    updated = conn.execute(
        """UPDATE observation_incidents SET last_alert_at=datetime('now')
           WHERE id=? AND (last_alert_at IS NULL OR
               last_alert_at<=datetime('now', ?))""",
        (incident_id, f"-{OBSERVE_ALERT_COOLDOWN_MINUTES} minutes"),
    )
    if updated.rowcount != 1:
        return None

    alert = conn.execute(
        """INSERT INTO observation_alerts (incident_id, recent_hits)
           VALUES (?, ?)""",
        (incident_id, recent),
    )
    return {
        "id": alert.lastrowid,
        "incident_id": incident_id,
        "host": host,
        "ip": ip,
        "recent_hits": recent,
    }
